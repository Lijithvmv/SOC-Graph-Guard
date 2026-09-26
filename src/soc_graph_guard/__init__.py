"""soc-graph-guard: a security-first agentic SOC reference on LangGraph."""

__version__ = "0.1.0"

from soc_graph_guard.runner import evaluate, run_guarded
from soc_graph_guard.workflow import build_workflow

__all__ = ["__version__", "build_workflow", "evaluate", "run_guarded"]
