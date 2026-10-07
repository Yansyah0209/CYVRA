# Counterfactuals and remediation
Each simulation deep-copies the canonical dataset, applies declared interventions, and reruns reachability, contextual scores, candidate paths, portfolio maximum, and sum objective at the same analysis timestamp as baseline.

Patch resolves one finding. Remove exposure removes one entry flag; alternative entry paths may remain. Segment removes exposure and disables all incoming/outgoing asset relationships. Disable relationship removes one directed edge, modeling permission or network restriction. Apply control raises control_strength to one (a heuristic 50% discount under default weights).

Simulations never perform infrastructure actions. The operational effect depends on supplied topology and assumptions. Path IDs include edge IDs so overlapping and parallel paths remain distinguishable. Remediation results contain risk delta, objective delta, removed path IDs, and truncation.

The greedy optimizer recomputes marginal objective reduction per unit cost for each eligible candidate after each selected intervention; it chooses positive gains until budget is exhausted or no improving action remains. Patch and relation restriction cost one; exposure removal costs two. Units are illustrative, not estimated labor or currency. Operational impacts are warnings, not numeric constraints. At most the first 60 candidates are evaluated; the output discloses candidate limiting. Segmentation and apply_control are available through simulation API but are intentionally excluded from automatic recommendations because of broad business impact and arbitrary control effectiveness. There is no global optimality claim.

Future work: user supplied action costs, explicit downtime constraints, exact small-instance baselines, source uncertainty propagation, robust optimization, and independent calibration.
