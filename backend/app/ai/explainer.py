from typing import Protocol


class ExplanationProvider(Protocol):
    def explain(self, question: str, analysis: dict, recommendations: dict) -> dict: ...


class GroundedExplainer:
    """Offline provider: no network, tool execution, or unverified generated facts."""

    def explain(self, question: str, analysis: dict, recommendations: dict) -> dict:
        text = question.lower()
        if "path" in text or "expos" in text:
            records = analysis["paths"]["items"][:5]
            answer = "Potential connectivity paths: " + (
                "; ".join(" → ".join(p["nodes"]) for p in records) or "none found within configured bounds"
            )
            citations = [p["id"] for p in records]
        elif "fix" in text or "remediat" in text or "priorit" in text:
            records = recommendations["plan"]
            answer = "Suggested modeled plan: " + (
                "; ".join(r["label"] for r in records) or "no improving action found"
            )
            citations = [r["target_id"] for r in records]
        elif any(x in text for x in ("why", "risk", "manager", "explain")):
            records = analysis["findings"][:3]
            answer = " ".join(r["explanation"] for r in records) or "No findings supplied."
            citations = [r["id"] for r in records]
        else:
            answer = "I can explain supplied risks, possible paths, or remediation priorities. I cannot verify facts absent from this project's evidence."
            citations = []
        return {
            "answer": answer,
            "citations": citations,
            "provider": "offline-structured",
            "generated": False,
            "limitations": "Heuristic modeled decisions, not confirmed attacks or calibrated probabilities.",
        }
