# Benchmark protocol
Run deterministic synthetic perturbations of the Aurora fixture over fixed random seeds and a fixed analysis clock. Compare CVSS ranking, severity plus known exploitation, contextual score ranking, asset betweenness ranking, and CYVRA greedy remediation. All action policies share candidate action/cost semantics; ranking baselines select patches only while CYVRA may restrict relationships, an important action-space confound.

Report modeled objective reduction, portfolio risk reduction, removed path count, runtime, and costs. Include mean and full per-seed results; ties deterministic. Metrics reuse the CYVRA model and are intentionally labeled circular/internal. They are regression and research infrastructure, not evidence of superiority.

Future independent evaluation: common action-space comparison, exact optimizer, external incident labels, analyst relevance labels, Precision@K, outcome-calibrated confidence (Brier/ECE with genuinely labeled data), source-dependence ablations, ranking stability under noise, latency on larger graphs, and adversarial data tests. Do not invent ground truth or report calibration on unlabeled synthetic evidence.
