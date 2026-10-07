# Evidence fusion and confidence
Evidence age in days is measured at analysis time. Weight = supplied reliability × exp(−age/90). The 90-day decay constant is heuristic and must be calibrated for each source. A fixed clock can be passed to analysis for reproducible tests.

For each independence group, choose its maximum supporting weight and maximum opposing weight. Sum those maxima across groups as S and O. This avoids repeatedly counting duplicate scanner observations as independent evidence.

coverage = min(1, (S+O)/2)

agreement = abs(S−O)/(S+O), or 0 when absent

completeness = fraction of known_exploited, exploit_likelihood, telemetry that are provided

confidence = 100 × coverage × agreement × (0.5 + 0.5 × completeness)

Confidence expresses evidence completeness and agreement in either direction, not the truth probability of the vulnerability or probability of compromise. Opposition-dominated evidence can have high agreement/confidence while contesting the finding: S/O and contradictory flags must be inspected. Supplied findings continue to determine modeled risk until adjudicated or resolved. No evidence yields zero confidence. Graph path confidence uses the bottleneck of supporting findings and relationship confidence.

The synthetic dataset has fixed January 2026 timestamps, intentionally producing lower confidence as time advances. Do not refresh timestamps without genuinely recollecting observations. Real calibration and source-dependence studies are future work.
