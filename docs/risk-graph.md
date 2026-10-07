# Risk graph
NetworkX MultiDiGraph preserves parallel asset relationships, their IDs, observed/inferred status, confidence, and provenance. Asset and finding nodes have canonical fields. AFFECTED_BY edges connect assets to findings; these are not traversable connectivity edges.

The browser displays asset and finding nodes and directed relation labels. Candidate paths traverse only enabled asset relationships; findings attach as supporting context. No public Internet node is necessary: internet_exposed marks entry assets.

This minimal ontology intentionally does not turn a vulnerability node into an assumed exploitation step. Future privilege-aware transitions require validated prerequisites and independent evidence before paths can be treated as more than connectivity hypotheses.
