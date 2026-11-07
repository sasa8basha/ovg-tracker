"""
collector/filter_engine.py — P3: Explainable Filter Engine.

Wraps the heavy analysis.py pipeline and provides a clean, standardized output
with a single primary `filter_reason` for rejected visits.
"""
from collector.orchestrator import analyze_full


def evaluate_visit(data: dict, ip_info: dict) -> dict:
    """
    Runs the full analysis pipeline and returns a standardized result
    with explicit filter reasoning.
    """
    # 1. Run the core analysis (contradiction engine, behavior deep, etc.)
    result = analyze_full(data, ip_info)
    
    verdict = result.get("verdict", "suspicious")
    evidence = result.get("evidence", [])
    
    # 2. Determine primary filter reason (only for rejected visits)
    filter_reason = None
    if verdict == "invalid":
        # Filter only positive scores (which indicate risk/bot signals)
        risks = [e for e in evidence if e.get("score", 0) > 0]
        
        if risks:
            # Sort by highest score to get the most severe reason
            risks.sort(key=lambda x: x.get("score", 0), reverse=True)
            filter_reason = risks[0].get("code")
        else:
            # Fallback if invalid but no positive score found
            filter_reason = "CRITICAL_IMPOSSIBILITY"
            
    # 3. Attach the reason to the result
    result["filter_reason"] = filter_reason
    
    return result
