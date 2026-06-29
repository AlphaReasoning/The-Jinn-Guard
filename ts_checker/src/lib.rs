use anyhow::{anyhow, Result};
use std::collections::HashMap;
use z3::ast::{Ast, Int, Real};
use z3::{Context, Solver};

pub struct PolicyEngine<'a> {
    ctx: &'a Context,
    solver: Solver<'a>,
    nonce_cache: std::collections::HashSet<u64>,
}

impl<'a> PolicyEngine<'a> {
    /// Per-`check()` solver timeout in milliseconds. Legitimate policy constraint checks
    /// here involve a handful of linear constraints and resolve in microseconds;
    /// this bound exists purely so a pathological or maliciously complex policy
    /// cannot stall a decision indefinitely. On timeout Z3 returns
    /// `SatResult::Unknown`, which every caller below treats as a DENY — so the
    /// timeout fails *closed*, never open.
    const SOLVER_TIMEOUT_MS: u32 = 250;

    pub fn new(ctx_ref: &'a Context) -> Self {
        let solver = Solver::new(ctx_ref);

        // Bound worst-case solve time and fail closed on timeout (Unknown -> deny).
        let mut params = z3::Params::new(ctx_ref);
        params.set_u32("timeout", Self::SOLVER_TIMEOUT_MS);
        solver.set_params(&params);

        Self {
            ctx: ctx_ref,
            solver,
            nonce_cache: std::collections::HashSet::new(),
        }
    }

    /// Backward-Compatible Alias for the Topology Mapping Layer
    pub fn register_bounded_geometry(&self) -> Result<()> {
        Ok(())
    }

    /// Verifies that the daemon-derived risk score remains inside the policy ceiling.
    pub fn execute_totality_audit(&self, assessed_risk: f64, ceiling: f64) -> Result<()> {
        self.verify_state_transition(0, assessed_risk.ceil() as i64, ceiling.floor() as i64)
    }

    /// Remediation 2: Deep Anti-Replay Nonce & Sequence Validation Durability
    pub fn validate_sequence(&mut self, nonce: u64, sequence_id: u32) -> Result<()> {
        if self.nonce_cache.contains(&nonce) {
            return Err(anyhow!(
                "SECURITY_BREACH: Replay attack detected. Nonce allocation exhausted."
            ));
        }
        self.nonce_cache.insert(nonce);
        if sequence_id == 0 {
            return Err(anyhow!(
                "MALFORMED_STREAM: Invalid initial sequence index primitive."
            ));
        }
        Ok(())
    }

    /// Checks the single bounded inequality `current_risk + action_weight <= ceiling`
    /// with one Z3 SAT query. This is a satisfiability check of one linear arithmetic
    /// constraint, not a temporal/multi-step proof: SAT => the bound holds for the
    /// supplied integers (ALLOW), anything else (incl. timeout `Unknown`) => DENY.
    pub fn verify_state_transition(
        &self,
        current_risk: i64,
        action_weight: i64,
        ceiling: i64,
    ) -> Result<()> {
        self.solver.reset();

        let ctx = self.solver.get_context();
        let r_initial = Int::from_i64(ctx, current_risk);
        let r_delta = Int::from_i64(ctx, action_weight);
        let r_ceiling = Int::from_i64(ctx, ceiling);

        let r_final = Int::add(ctx, &[&r_initial, &r_delta]);
        let safety_constraint = r_final.le(&r_ceiling);
        self.solver.assert(&safety_constraint);

        match self.solver.check() {
            z3::SatResult::Sat => Ok(()),
            _ => Err(anyhow!(
                "SIGNAL: REFUSED_DEGRADED_ENTROPY_THRESHOLD_BREACH. Safety constraint check failed."
            )),
        }
    }

    /// Phase 2.2 — Verify declarative policy invariants expressed as constraint strings.
    ///
    /// Each invariant is a simple infix expression of the form:
    ///   `<variable> <op> <literal>`
    /// where `<op>` is one of `<=`, `>=`, `<`, `>`, `==`.
    ///
    /// Variables are resolved from `context_vars`.  Variables not present in the
    /// map are skipped and the constraint is treated as vacuously satisfied so
    /// that missing telemetry never causes a spurious deny.
    pub fn verify_policy_invariants(
        &self,
        invariants: &[String],
        context_vars: &HashMap<String, f64>,
    ) -> Result<()> {
        self.solver.reset();
        let ctx = self.ctx;

        let mut constrained = false;

        for invariant in invariants {
            // Parse `lhs op rhs`.
            let (lhs, op, rhs_str) = parse_invariant(invariant)
                .ok_or_else(|| anyhow!("Cannot parse invariant expression: '{}'", invariant))?;

            // Resolve LHS variable; skip if unknown (vacuous).
            //
            // SECURITY NOTE (JG-RT-004, defense-in-depth): a missing variable makes
            // its invariant vacuously pass (fail-open). The daemon force-populates
            // every risk/telemetry variable it owns (observed_risk, fused_risk,
            // trust_score, privilege_tier, is_root, declared_risk, action_risk_score,
            // …) so those cannot be suppressed by a caller; but an invariant written
            // over a *caller-supplied* custom variable can be bypassed by omitting it.
            // This layer is defense-in-depth (the intent allowlist + kernel exec
            // enforcement are the primary gates). Likewise, very large caller-supplied
            // values saturate in the `as i32` scaling below. Recommendation: author
            // security-relevant invariants only over the daemon-guaranteed variables
            // above, whose presence and bounded range are not attacker-controlled.
            let lhs_val = match context_vars.get(lhs) {
                Some(&v) => v,
                None => {
                    println!("[Z3] invariant var '{}' not in context — skipping", lhs);
                    continue;
                }
            };

            let rhs_val: f64 = rhs_str
                .trim()
                .parse()
                .map_err(|_| anyhow!("Cannot parse RHS literal '{}' in invariant", rhs_str))?;

            let lhs_z3 = Real::from_real(ctx, (lhs_val * 1_000_000.0) as i32, 1_000_000);
            let rhs_z3 = Real::from_real(ctx, (rhs_val * 1_000_000.0) as i32, 1_000_000);

            let constraint = match op {
                "<=" => lhs_z3.le(&rhs_z3),
                ">=" => lhs_z3.ge(&rhs_z3),
                "<" => lhs_z3.lt(&rhs_z3),
                ">" => lhs_z3.gt(&rhs_z3),
                "==" => lhs_z3._eq(&rhs_z3),
                other => return Err(anyhow!("Unsupported operator '{}' in invariant", other)),
            };

            self.solver.assert(&constraint);
            constrained = true;
        }

        if !constrained {
            // No verifiable constraints — pass through.
            return Ok(());
        }

        match self.solver.check() {
            z3::SatResult::Sat => Ok(()),
            _ => Err(anyhow!(
                "POLICY_INVARIANT_VIOLATED: One or more Z3 invariants are unsatisfiable."
            )),
        }
    }
}

/// Parse a simple `lhs op rhs` invariant string.
/// Returns `(lhs_var, operator, rhs_literal)` or `None` on parse failure.
fn parse_invariant(s: &str) -> Option<(&str, &str, &str)> {
    for op in &["<=", ">=", "==", "<", ">"] {
        if let Some(pos) = s.find(op) {
            let lhs = s[..pos].trim();
            let rhs = s[pos + op.len()..].trim();
            if !lhs.is_empty() && !rhs.is_empty() {
                return Some((lhs, op, rhs));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invariants_satisfied_pass() {
        let config = z3::Config::new();
        let ctx = Context::new(&config);
        let engine = PolicyEngine::new(&ctx);

        let invariants = vec![
            "spending_ceiling_usd <= 150.00".to_string(),
            "privilege_escalation_depth < 3".to_string(),
        ];
        let context_vars: HashMap<String, f64> = [
            ("spending_ceiling_usd".to_string(), 75.0),
            ("privilege_escalation_depth".to_string(), 1.0),
        ]
        .into_iter()
        .collect();

        assert!(engine
            .verify_policy_invariants(&invariants, &context_vars)
            .is_ok());
    }

    #[test]
    fn invariants_violated_fail() {
        let config = z3::Config::new();
        let ctx = Context::new(&config);
        let engine = PolicyEngine::new(&ctx);

        let invariants = vec!["spending_ceiling_usd <= 150.00".to_string()];
        let context_vars: HashMap<String, f64> = [("spending_ceiling_usd".to_string(), 200.0)]
            .into_iter()
            .collect();

        assert!(engine
            .verify_policy_invariants(&invariants, &context_vars)
            .is_err());
    }

    #[test]
    fn invariants_unknown_var_vacuously_satisfied() {
        let config = z3::Config::new();
        let ctx = Context::new(&config);
        let engine = PolicyEngine::new(&ctx);

        let invariants = vec!["unknown_metric <= 100.0".to_string()];
        let context_vars: HashMap<String, f64> = HashMap::new();

        // Unknown variable should be skipped (vacuously pass).
        assert!(engine
            .verify_policy_invariants(&invariants, &context_vars)
            .is_ok());
    }

    #[test]
    fn invariants_empty_list_pass() {
        let config = z3::Config::new();
        let ctx = Context::new(&config);
        let engine = PolicyEngine::new(&ctx);

        assert!(engine
            .verify_policy_invariants(&[], &HashMap::new())
            .is_ok());
    }
}
