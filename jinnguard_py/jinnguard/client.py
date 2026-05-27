import socket
import json
import hmac
import hashlib
import os
import time

class GuardVerdict:
    def __init__(self, raw_signal: str):
        self.raw_signal = raw_signal.strip()

    def is_allowed(self) -> bool:
        return self.raw_signal == "SIGNAL: ALLOW"

    def is_denied(self) -> bool:
        return self.raw_signal.startswith("SIGNAL: DENY")

    # FIXED: Migrated definition directly to class level to ensure valid dunder method resolution
    def __repr__(self) -> str:
        status_string = "ALLOWED" if self.is_allowed() else "DENIED"
        return f"<GuardVerdict status='{status_string}' raw='{self.raw_signal}'>"

class Guard:
    def __init__(self, socket_path: str = "/tmp/jinnguard.sock"):
        self.socket_path = socket_path
        self.sock = None
        self.secret_key = os.environ["JINN_GUARD_SECRET"].encode('utf-8')

    def __enter__(self):
        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(self.socket_path)
            return self
        except Exception as e:
            raise ConnectionError(f"Failed connecting to Jinn Guard daemon link: {e}")

    def audit(self, privilege: float, risk_score: float) -> GuardVerdict:
        if not self.sock:
            raise RuntimeError("Active socket session context manager required.")

        # FIXED: Pulled out unvalidated text PID parameters to mirror daemon wire expectations
        payload = {
            "session_privilege_bit": float(privilege),
            "action_risk_score": float(risk_score),
            "sequence_counter": int(time.time() * 100)
        }
        payload_str = json.dumps(payload, separators=(',', ':'))
        signature = hmac.new(self.secret_key, payload_str.encode('utf-8'), hashlib.sha256).hexdigest()
        
        wire_envelope = {
            "payload": payload_str,
            "signature": signature
        }
        
        self.sock.sendall(json.dumps(wire_envelope).encode('utf-8'))
        response = self.sock.recv(1024).decode('utf-8')
        return GuardVerdict(response)

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.sock:
            self.sock.close()
