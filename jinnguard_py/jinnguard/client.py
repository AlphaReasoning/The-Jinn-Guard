import os
import socket
import json
import hmac
import hashlib
import struct
import time

DEFAULT_SOCKET_TIMEOUT_SECS = 5.0
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


def default_socket_path():
    """Return the runtime socket path, honoring both historical env names."""
    return (
        os.environ.get("JINN_GUARD_SOCKET")
        or os.environ.get("JINNGUARD_SOCKET")
        or "/tmp/jinnguard.sock"
    )


def load_guard_secret():
    """Load the HMAC admission secret from env or a mounted secret file."""
    secret = os.environ.get("JINN_GUARD_SECRET")
    if secret:
        return secret.encode("utf-8")

    secret_file = os.environ.get("JINN_GUARD_SECRET_FILE") or os.environ.get("JINNGUARD_SECRET_FILE")
    if secret_file:
        with open(secret_file, "rb") as handle:
            return handle.read().strip()

    raise KeyError(
        "CRITICAL_SECURITY_HALT: set JINN_GUARD_SECRET or "
        "JINN_GUARD_SECRET_FILE before creating a JinnGuardClient."
    )


def default_agent_id():
    """Return the caller's agent identity if one was provided by the runtime."""
    return (
        os.environ.get("JINN_AGENT_ID")
        or os.environ.get("JINNGUARD_AGENT_ID")
        or os.environ.get("JINN_GUARD_AGENT_ID")
    )


class JinnGuardClient:
    def __init__(self, socket_path=None, timeout=DEFAULT_SOCKET_TIMEOUT_SECS, max_response_bytes=MAX_RESPONSE_BYTES):
        self.socket_path = socket_path or default_socket_path()
        self.sock = None
        self._secret = load_guard_secret()
        self.timeout = float(timeout)
        self.max_response_bytes = int(max_response_bytes)
        self._sequence = int(time.time_ns() % 9_000_000_000_000_000_000)

    def _next_sequence(self):
        self._sequence += 1
        return self._sequence

    def _read_n(self, n):
        data = bytearray()
        while len(data) < n:
            packet = self.sock.recv(n - len(data))
            if not packet:
                break
            data.extend(packet)
        return bytes(data)

    def send_proposal(
        self,
        proposal,
        risk_score=None,
        sequence_counter=None,
        privilege=0.0,
        prompt=None,
        plan=None,
        source_code=None,
        requested_capabilities=None,
        execute=False,
    ):
        payload = self._build_payload(
            proposal,
            risk_score=risk_score,
            sequence_counter=sequence_counter,
            privilege=privilege,
            prompt=prompt,
            plan=plan,
            source_code=source_code,
            requested_capabilities=requested_capabilities,
            execute=execute,
        )
        payload_str = json.dumps(payload, separators=(",", ":"))
        signature = hmac.new(self._secret, payload_str.encode("utf-8"), hashlib.sha256).hexdigest()
        envelope = {
            "payload": payload_str,
            "signature": signature,
        }

        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect(self.socket_path)

            serialized = json.dumps(envelope, separators=(",", ":"))
            data = serialized.encode("utf-8")
            header = struct.pack(">IB", len(data), 1)
            self.sock.sendall(header + data)

            # Read response header
            resp_header = self._read_n(5)
            if len(resp_header) < 5:
                return "TRANSPORT_ERROR: Truncated response header"
            resp_len, resp_ver = struct.unpack(">IB", resp_header)
            if resp_ver != 1:
                return f"TRANSPORT_ERROR: Unsupported response frame version {resp_ver}"
            if resp_len > self.max_response_bytes:
                return (
                    "TRANSPORT_ERROR: Response frame too large "
                    f"({resp_len} > {self.max_response_bytes})"
                )
            resp_data = self._read_n(resp_len)
            if len(resp_data) < resp_len:
                return "TRANSPORT_ERROR: Truncated response body"
            return resp_data.decode("utf-8")
        except socket.timeout:
            return "TRANSPORT_ERROR: Socket timeout"
        except Exception as e:
            return f"TRANSPORT_ERROR: {str(e)}"
        finally:
            if self.sock:
                self.sock.close()

    def _build_payload(
        self,
        proposal,
        risk_score,
        sequence_counter,
        privilege,
        prompt,
        plan,
        source_code,
        requested_capabilities,
        execute,
    ):
        if isinstance(proposal, dict):
            payload = dict(proposal)
        else:
            seq = int(sequence_counter) if sequence_counter is not None else self._next_sequence()
            payload = {
                "intent_name": str(proposal),
                "session_privilege_bit": float(privilege),
                "action_risk_score": float(risk_score if risk_score is not None else 0.0),
                "sequence_counter": seq,
            }

        if prompt is not None:
            payload["prompt"] = prompt
        if plan is not None:
            payload["plan"] = plan
        if source_code is not None:
            payload["source_code"] = source_code
        if requested_capabilities is not None:
            payload["requested_capabilities"] = list(requested_capabilities)
        if execute:
            payload["execute"] = True

        if "sequence_counter" not in payload:
            payload["sequence_counter"] = (
                int(sequence_counter) if sequence_counter is not None else self._next_sequence()
            )
        payload.setdefault("session_privilege_bit", float(privilege))
        if risk_score is not None:
            payload.setdefault("action_risk_score", float(risk_score))
        return payload


class GuardVerdict:
    """Represents the daemon's enforcement decision for a proposal.

    Signals returned by the daemon:
      - ``SIGNAL: ALLOW``       — execution permitted, no restrictions.
      - ``SIGNAL: CONSTRAIN``   — execution permitted subject to ``constraints``.
      - ``SIGNAL: DENY_*``      — execution denied.

    For ``CONSTRAIN`` responses the daemon also returns a JSON object with the
    active constraint set and the execution result.  This class parses those
    fields so callers can apply rate limits, field redaction, etc.
    """

    def __init__(self, response: str):
        self.response = response
        self._constraints: dict = {}
        self._result: dict | None = None
        self._parse()

    def _parse(self):
        """Extract constraint JSON from CONSTRAIN responses.

        Wire format::

            SIGNAL: CONSTRAIN
            {"redact_output":false,"rate_limit_rps":5,...}
            {"exit_code":0,"stdout":"...","stderr":""}

        The daemon always ends each section with ``\n``.
        """
        lines = self.response.strip().splitlines()
        if len(lines) >= 2 and "CONSTRAIN" in lines[0]:
            # Line 1 -> constraint JSON
            try:
                self._constraints = json.loads(lines[1])
            except (json.JSONDecodeError, IndexError):
                self._constraints = {}
            # Line 2 -> execution result JSON (if present)
            if len(lines) >= 3:
                try:
                    self._result = json.loads(lines[2])
                except (json.JSONDecodeError, IndexError):
                    self._result = None
        elif len(lines) >= 2 and "ALLOW" in lines[0]:
            try:
                self._result = json.loads(lines[1])
            except (json.JSONDecodeError, IndexError):
                self._result = None

    def signal(self) -> str:
        """Return the first-line daemon signal, without trailing whitespace."""
        return self.response.splitlines()[0].strip() if self.response else ""

    def is_allowed(self) -> bool:
        """Return True if execution is permitted without substring false positives."""
        return (
            self.signal() == "SIGNAL: ALLOW"
            or self.signal().startswith("SIGNAL: ALLOW ")
            or self.is_constrained()
        )

    def is_constrained(self) -> bool:
        """Return True if execution is permitted but subject to constraints."""
        return self.signal() == "SIGNAL: CONSTRAIN" or self.signal().startswith("SIGNAL: CONSTRAIN ")

    def is_denied(self) -> bool:
        """Return True if execution was denied or transport failed."""
        signal = self.signal()
        return signal.startswith("SIGNAL: DENY") or signal.startswith("TRANSPORT_ERROR")

    def get_constraints(self) -> dict:
        """Return the active constraint set (empty dict if not constrained).

        Keys may include:
          - ``redact_output`` (bool)
          - ``rate_limit_rps`` (int | None)
          - ``output_byte_limit`` (int | None)
          - ``allowed_network_destinations`` (list[str])
        """
        return self._constraints

    def get_result(self) -> dict | None:
        """Return the execution result parsed from the daemon response, or None."""
        return self._result

    def rate_limit_rps(self) -> int | None:
        """Convenience: return the rate limit in requests-per-second, or None."""
        return self._constraints.get("rate_limit_rps")

    def output_byte_limit(self) -> int | None:
        """Convenience: return the output byte cap, or None."""
        return self._constraints.get("output_byte_limit")

    def __repr__(self) -> str:
        if self.is_constrained():
            return f"<GuardVerdict: CONSTRAIN constraints={self._constraints}>"
        elif self.is_allowed():
            return "<GuardVerdict: ALLOW>"
        else:
            return f"<GuardVerdict: DENY signal={self.signal()!r}>"


class Guard:
    def __init__(self, socket_path=None, agent_id=None):
        self.client = JinnGuardClient(socket_path=socket_path)
        self.agent_id = agent_id or default_agent_id()
        self._sequence = int(time.time_ns() % 9_000_000_000_000_000_000)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def audit(self, privilege, risk_score, intent_name="agent_action", agent_id=None):
        self._sequence += 1
        response = self.client.send_proposal(
            self._with_agent_id(intent_name, agent_id),
            risk_score=risk_score,
            sequence_counter=self._sequence,
            privilege=privilege,
        )
        return GuardVerdict(response)

    def execute_shell(self, command, risk_score=20.0, intent_name="execute_shell", agent_id=None):
        """Request broker-owned shell execution through the Jinn Guard daemon."""
        proposal = {
            "intent_name": intent_name,
            "action_risk_score": float(risk_score),
            "proposed_action": {"kind": "shell_command", "command": command},
        }
        return self._execute_proposal(self._with_agent_id(proposal, agent_id))

    def write_file(self, path, contents, risk_score=15.0, intent_name="write_file", agent_id=None):
        """Request broker-owned file write through the Jinn Guard daemon."""
        proposal = {
            "intent_name": intent_name,
            "action_risk_score": float(risk_score),
            "proposed_action": {"kind": "file_write", "path": path, "contents": contents},
        }
        return self._execute_proposal(self._with_agent_id(proposal, agent_id))

    def request(self, method, url, risk_score=20.0, intent_name="network_request", agent_id=None):
        """Request broker-owned network access through the Jinn Guard daemon."""
        proposal = {
            "intent_name": intent_name,
            "action_risk_score": float(risk_score),
            "proposed_action": {"kind": "network_request", "method": method, "url": url},
        }
        return self._execute_proposal(self._with_agent_id(proposal, agent_id))

    def _with_agent_id(self, proposal, agent_id=None):
        effective_agent_id = agent_id or self.agent_id
        if not effective_agent_id:
            return proposal
        if isinstance(proposal, dict):
            out = dict(proposal)
            out.setdefault("agent_id", effective_agent_id)
            return out
        return {
            "intent_name": str(proposal),
            "agent_id": effective_agent_id,
        }

    def _execute_proposal(self, proposal):
        self._sequence += 1
        proposal["sequence_counter"] = self._sequence
        proposal.setdefault(
            "context_vars",
            {
                "spending_ceiling_usd": 0.0,
                "privilege_escalation_depth": 0.0,
            },
        )
        response = self.client.send_proposal(proposal, execute=True)
        return GuardVerdict(response)
