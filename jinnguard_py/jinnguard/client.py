import os
import socket
import json
import ssl

class JinnGuardClient:
    def __init__(self, socket_path="jinnguard.sock"):
        self.socket_path = socket_path
        self.sock = None
        
        # Pull cryptographic identity from secure environment variable configuration
        self.private_key_hex = os.environ.get("JINN_AGENT_PRIVATE_KEY")
        if not self.private_key_hex:
            raise KeyError("CRITICAL_SECURITY_HALT: JINN_AGENT_PRIVATE_KEY environment variable is unassigned.")

    def initialize_secure_transport(self, ca_path=None):
        # Establish explicit, production-grade transport security constraints
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        if ca_path:
            context.load_verify_locations(cafile=ca_path)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    def send_proposal(self, payload_dict):
        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(self.socket_path)
            
            serialized = json.dumps(payload_dict) + "\n"
            self.sock.sendall(serialized.encode())
            
            response = self.sock.recv(1024)
            return response.decode()
        except Exception as e:
            return f"TRANSPORT_ERROR: {str(e)}"
        finally:
            if self.sock:
                self.sock.close()
