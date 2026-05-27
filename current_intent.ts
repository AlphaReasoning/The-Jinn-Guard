system BranchingAgentSentinel:
    state RootAI_GraphNodes:
        session_privilege_bit: F64 [min=0.0] [max=2.0] [init=0.0]
        action_risk_score: F64 [min=0.0] [max=100.0] [init=20.0]
    execute StateDependentRouting:
        route:
            if session_privilege_bit == 2.0 ->
                transform action_risk_score -> action_risk_score + 5.0
            else_if session_privilege_bit == 1.0 ->
                transform action_risk_score -> min(action_risk_score + 10.0, 75.0)
            else ->
                transform action_risk_score -> 75.0
        proof:
            obligation branch_disjoint
            obligation branch_exhaustive
