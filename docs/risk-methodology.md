# Contextual risk v0.1
For every open finding:

`raw = 100 × (0.30 × CVSS/10 + 0.20 × reachability + 0.20 × criticality + 0.15 × known_exploitation + 0.10 × exploit_likelihood + 0.05 × telemetry)`

`risk = raw × (1 − 0.5 × control_strength)`

Reachability is 1 if an asset is a public entry or is reachable along enabled directed asset relationships, else 0. CVSS measures technical severity; reachability and criticality add context. Known exploitation and telemetry add bonuses only when supplied true. Missing exploit_likelihood defaults to 0.5. Missing inputs are exposed in confidence output. Resolved findings score zero.

Categories: critical ≥80, high ≥60, medium ≥35, low <35. Weights are visible, configurable through RiskConfig, sum to one, and are not empirically fitted. Contributions are returned individually; control discounts are separately returned.

Path risk is maximum open finding risk along its asset nodes times target criticality. Portfolio score is the maximum critical-asset finding risk or path risk, or zero if none. It deliberately represents exposure of critical resources, not all low-criticality findings. The objective for remediation is the sum of critical-asset finding scores plus enumerated path scores. It counts overlapping paths; it is not a probability union or monetary loss estimate. Portfolio maximum may remain unchanged after a useful intervention, so objective reduction is also shown.

Scores are ordinal heuristic indices, not breach probabilities. Evidence confidence does not lower risk: lack of evidence must not silently make a possibly serious condition look safe. Contradictory evidence lowers confidence; adjudication must precede trusted production decisions. Current risk does not include privilege semantics or empirically validated exploit prerequisites; no automatic real-world security claim follows.
