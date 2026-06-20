#!/usr/bin/env python3
"""
_daemon.py — self-contained launcher for a private, sandboxed Jinn Guard daemon.

Used by the validation suite. Boots the REAL release binary with its own throwaway
socket, policy, secret, and audit log in a temp dir, binds metrics to loopback, and
cleans everything up on exit. It governs only its own private test agents and cannot
touch the host.

Standard-library only. The wire protocol here is byte-identical to the production
client and the in-tree tests (5-byte frame: u32 length + u8 version, then a JSON
envelope {"payload","signature"} with an HMAC-SHA256 over the payload).
"""
import hashlib
import hmac
import json
import os
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

DEFAULT_POLICY = """\
global_safety_ceiling: 90.0
deny_anonymous_agents: true
enforcement_scope:
  governed_path_prefixes: []
agent_nodes:
  - id: "claims_agent"
    privilege_tier: 2
    max_sequence_quota: 0
    allowed_intents:
      - "read_customer_record"
    invariants: []
  - id: "bounded_agent"
    privilege_tier: 1
    max_sequence_quota: 3
    allowed_intents:
      - "read_customer_record"
    invariants: []
"""


def find_binary():
    env = os.environ.get("JINNGUARD_BENCH_BINARY")
    if env and os.path.isfile(env) and os.access(env, os.X_OK):
        return env
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.abspath(os.path.join(here, "..", ".."))
    for rel in ("target/release/ts_cli", "target/debug/ts_cli"):
        cand = os.path.join(root, rel)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    sys.exit("ERROR: ts_cli binary not found. Build it: cargo build --release -p ts_cli")


class Daemon:
    """Context manager: `with Daemon() as d:` exposes d.sock, d.audit, d.metrics_port."""

    def __init__(self, policy=DEFAULT_POLICY):
        self._policy = policy
        self.secret = secrets.token_bytes(32)
        self.workdir = None
        self.proc = None
        self.sock = None
        self.audit = None
        self.metrics_port = 0
        self._seq = 700_000_000

    def __enter__(self):
        self.workdir = tempfile.mkdtemp(prefix="jinnguard_validate_")
        self.sock = os.path.join(self.workdir, "jg.sock")
        self.audit = os.path.join(self.workdir, "audit.log")
        secret_f = os.path.join(self.workdir, "secret")
        policy_f = os.path.join(self.workdir, "policy.yaml")
        lineage_f = os.path.join(self.workdir, "lineage.json")
        with open(secret_f, "wb") as f:
            f.write(self.secret)
        with open(policy_f, "w") as f:
            f.write(self._policy)

        # Pick a free loopback port for metrics.
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        self.metrics_port = s.getsockname()[1]
        s.close()

        env = dict(os.environ)
        env["JINNGUARD_METRICS_PORT"] = str(self.metrics_port)
        self.proc = subprocess.Popen(
            [find_binary(),
             "--socket-path", self.sock,
             "--lineage-file", lineage_f,
             "--audit-log", self.audit,
             "--policy-file", policy_f,
             "--secret-file", secret_f],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
        )
        deadline = time.time() + 8
        while time.time() < deadline:
            if os.path.exists(self.sock):
                try:
                    t = socket.socket(socket.AF_UNIX)
                    t.connect(self.sock)
                    t.close()
                    return self
                except OSError:
                    pass
            time.sleep(0.05)
        self.__exit__(None, None, None)
        sys.exit("ERROR: daemon did not come up in time.")

    def __exit__(self, *exc):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self.workdir and os.path.isdir(self.workdir):
            shutil.rmtree(self.workdir, ignore_errors=True)

    def _next_seq(self):
        self._seq += 1
        return self._seq

    def send(self, intent, agent_id, risk, *, forge_sig=False, version=1,
             reuse_seq=None, _attempts=6):
        """Send one proposal to the real daemon; return its first-line SIGNAL.
        Transport-level errors are retried (a connection race is not a verdict)."""
        seq = reuse_seq if reuse_seq is not None else self._next_seq()
        agent_field = ',"agent_id":"%s"' % agent_id if agent_id else ""
        payload = ('{"sequence_counter":%d,"intent_name":"%s",'
                   '"action_risk_score":%s%s}') % (seq, intent, risk, agent_field)
        sig = "0" * 64 if forge_sig else hmac.new(
            self.secret, payload.encode(), hashlib.sha256).hexdigest()
        env = json.dumps({"payload": payload, "signature": sig},
                         separators=(",", ":")).encode()
        pkt = struct.pack(">IB", len(env), version) + env

        last = "TRANSPORT_ERROR"
        for _ in range(_attempts):
            try:
                s = socket.socket(socket.AF_UNIX)
                s.settimeout(5)
                s.connect(self.sock)
                s.sendall(pkt)
                hdr = s.recv(5)
                if len(hdr) < 5:
                    s.close()
                    time.sleep(0.1)
                    continue
                ln = struct.unpack(">IB", hdr)[0]
                body = b""
                while len(body) < ln:
                    chunk = s.recv(ln - len(body))
                    if not chunk:
                        break
                    body += chunk
                s.close()
                return body.decode("utf-8", "replace").splitlines()[0].strip(), seq
            except OSError as e:
                last = "TRANSPORT_ERROR: %s" % e
                time.sleep(0.1)
        return last, seq

    def metrics(self):
        """Fetch the daemon's /metrics text (loopback)."""
        import urllib.request
        url = "http://127.0.0.1:%d/metrics" % self.metrics_port
        with urllib.request.urlopen(url, timeout=3) as r:
            return r.read().decode("utf-8", "replace")
