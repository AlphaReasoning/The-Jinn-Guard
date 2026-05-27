import sys
# Appending local path for instant dependency resolution
sys.path.append("./jinnguard_py")
import jinnguard

def simulate_agent_workflow(intent_name: str, privilege: float, current_risk: float):
    print(f"\n⚡ [AGENT ENGINE] Intent generated: '{intent_name}'")
    print(f"   Proposed State -> privilege: {privilege}, risk_score: {current_risk}")
    
    try:
        # Open up our newly minted client layer to check with the local background service
        with jinnguard.Guard() as gate:
            verdict = gate.audit(privilege=privilege, risk_score=current_risk)
            
            if verdict.is_allowed():
                print(f"   🎯 [FIREWALL SIGNAL]: ALLOW. Dispatching command execution payload safely.")
            else:
                print(f"   🛑 [FIREWALL SIGNAL]: DENY. Invariant security breach detected by SMT Core. Halting block.")
    except Exception as e:
        print(f"   ⚠️  Integration error: {e}")

if __name__ == "__main__":
    print("=== Launching Live Jinn Guard Client SDK Integration Run ===")
    
    # 1. Simulate a legitimate sequential agent call
    simulate_agent_workflow("Execute Routine Variable Sync", privilege=1.0, current_risk=30.0)
    
    # 2. Simulate an adversarial elevated boundary attempt that should be immediately stopped
    simulate_agent_workflow("Forced Memory Override Request", privilege=2.0, current_risk=74.0)
