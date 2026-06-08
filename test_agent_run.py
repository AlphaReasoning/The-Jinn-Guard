import os
import sys

os.environ["JINN_AGENT_PRIVATE_KEY"] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

try:
    from jinnguard_py.jinnguard.client import JinnGuardClient
except ImportError:
    sys.path.append(os.path.abspath("jinnguard_py"))
    from jinnguard.client import JinnGuardClient

# Target the standard execution socket track
client = JinnGuardClient(socket_path="/tmp/jinnguard.sock")

print("🚀 [TEST AGENT] Initializing mock tool loop execution paths...")

# 1. Test a mathematically safe intent path (Within the safety ceiling)
print("\n🔄 Sending Intent Track 01: Model Inference [Risk: 10, Seq: 1]")
try:
    response_01 = client.send_proposal("model_inference", 10.0, 1)
    print(f"📥 Daemon Response: {response_01}")
except Exception as e:
    print(f"❌ Transaction Blocked: {str(e)}")

# 2. Test an unverified risk threshold breach (Breaches the ceiling bounds)
print("\n🔄 Sending Intent Track 02: Unauthorized Escalation [Risk: 500, Seq: 2]")
try:
    response_02 = client.send_proposal("model_inference", 500.0, 2)
    print(f"📥 Daemon Response: {response_02}")
except Exception as e:
    print(f"❌ Transaction Blocked: {str(e)}")
