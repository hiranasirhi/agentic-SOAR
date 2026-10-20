"""
Static technique -> action rule table for the baseline (non-agentic) dispatcher.

This is the deliberate contrast case for §10.1's comparison: the same 12
attack scenarios (Table 10.1), routed through fixed if-this-then-that logic
instead of the LLM Orchestrator's contextual ReAct reasoning. No asset
criticality weighting, no historical false-positive lookup, no threat-intel
confidence gating — just "technique X always gets response Y".

Each entry maps a MITRE technique to:
  - agent: which specialist agent's queue the task goes to
  - action: the action name (must match what that agent's executor expects)
  - severity_default: baseline doesn't compute a weighted severity score,
    so it uses a flat default per technique tier
"""

BASELINE_RULES = {
    "T1110":       {"agent": "containment", "action": "block_ip",              "severity_default": 6},
    "T1046":       {"agent": "notification", "action": "log_and_notify",       "severity_default": 3},
    "T1068":       {"agent": "response",     "action": "isolate_host",         "severity_default": 8},
    "T1059":       {"agent": "response",     "action": "kill_process",         "severity_default": 7},
    "T1059.001":   {"agent": "response",     "action": "kill_process",         "severity_default": 7},
    "T1565":       {"agent": "response",     "action": "isolate_host",         "severity_default": 7},
    "T1021":       {"agent": "containment",  "action": "block_ip",             "severity_default": 6},
    "T1053":       {"agent": "response",     "action": "remove_persistence",   "severity_default": 6},
    "T1547":       {"agent": "response",     "action": "remove_persistence",   "severity_default": 6},
    "T1003":       {"agent": "response",     "action": "isolate_host",         "severity_default": 9},
    "T1041":       {"agent": "containment",  "action": "block_ip",             "severity_default": 8},
}

DEFAULT_RULE = {"agent": "notification", "action": "log_and_notify", "severity_default": 5}


def resolve_action(technique: str) -> dict:
    return BASELINE_RULES.get(technique, DEFAULT_RULE)
