import socket
import json
import hmac
import hashlib
import os
import time

class IntentToken:
    def __init__(self, origin_agent: str, intent_name: str, baseline_risk: float):
        self.history = [{
            "agent": origin_agent,
            "intent": intent_name,
            "risk_contribution": baseline_risk
        }]
        self.cumulative_risk = baseline_risk
        self.tx_sequence = int(time.time() * 100)

    def handoff(self, target_agent: str, sub_intent: str, additional_risk: float):
        self.history.append({
            "agent": target_agent,
            "intent": sub_intent,
            "risk_contribution": additional_risk
        })
        self.cumulative_risk += additional_risk
        self.tx_sequence += 1

    def serialize_payload(self, privilege_lane: float):
        # FIXED: Completely removed calling_process_id field from text transmission data wire loops
        return {
            "session_privilege_bit": float(privilege_lane),
            "action_risk_score": float(self.cumulative_risk),
            "sequence_counter": int(self.tx_sequence)
        }

def execute_fabric_pipeline(token: IntentToken, privilege_lane: float, forced_raw_payload=None):
    print(f"\n🔗 [FABRIC MESH] Routing Multi-Agent Token Chain...")
    secret_key = os.environ["JINN_GUARD_SECRET"].encode('utf-8')
    
    if forced_raw_payload:
        payload_str = forced_raw_payload
    else:
        payload = token.serialize_payload(privilege_lane)
        payload_str = json.dumps(payload, separators=(',', ':'))
    
    signature = hmac.new(secret_key, payload_str.encode('utf-8'), hashlib.sha256).hexdigest()
    
    wire_envelope = {
        "payload": payload_str,
        "signature": signature
    }

    import struct
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect('/tmp/jinnguard.sock')
        
        serialized = json.dumps(wire_envelope, separators=(",", ":"))
        data = serialized.encode("utf-8")
        header = struct.pack(">IB", len(data), 1)
        s.sendall(header + data)

        # Read response header
        resp_header = b''
        while len(resp_header) < 5:
            chunk = s.recv(5 - len(resp_header))
            if not chunk:
                break
            resp_header += chunk
        
        if len(resp_header) < 5:
            print("   ⚠️  Fabric linkage integration error: Truncated response header")
            return None
            
        resp_len, resp_ver = struct.unpack(">IB", resp_header)
        
        resp_data = b''
        while len(resp_data) < resp_len:
            chunk = s.recv(resp_len - len(resp_data))
            if not chunk:
                break
            resp_data += chunk
            
        response = resp_data.decode('utf-8').strip()
        s.close()
        
        if "ALLOW" in response:
            print(f"   ✅ [FABRIC VERDICT]: ALLOW. Verification parameters satisfied safely.")
            return payload_str
        else:
            print(f"   🛑 [FABRIC VERDICT]: DENY ({response}). Swarm execution aborted.")
            return None
    except Exception as e:
        print(f"   ⚠️  Fabric linkage integration error: {e}")
        return None

if __name__ == "__main__":
    print("=== Launching Hardened Jinn Guard Fabric Orchestration Suite ===")
    
    print("\n--- Running Scenario 1: Legitimate Inter-Agent Handoff ---")
    token_alpha = IntentToken(origin_agent="planner_01", intent_name="allocate_cache", baseline_risk=20.0)
    token_alpha.handoff(target_agent="driver_02", sub_intent="flush_sys_inodes", additional_risk=10.0)
    captured_payload = execute_fabric_pipeline(token_alpha, privilege_lane=1.0)

    if captured_payload:
        print("\n--- Running Scenario 4: Mitigating Malicious Token Replay Exploit Vector ---")
        print("   ⚠️  Adversary attempts to dispatch the exact same captured transaction block string verbatim...")
        execute_fabric_pipeline(token_alpha, privilege_lane=1.0, forced_raw_payload=captured_payload)
