"""Command line: `soc-graph-guard eval` and `soc-graph-guard run <scenario-id>`."""

from __future__ import annotations

import argparse
import json
import sys

from soc_graph_guard.review import CautiousReviewer, DenyAll
from soc_graph_guard.runner import evaluate, load_scenarios, run_guarded, to_markdown


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="soc-graph-guard", description="A security-first agentic SOC reference on LangGraph.")
    sub = p.add_subparsers(dest="cmd", required=True)
    ev = sub.add_parser("eval", help="run every scenario through the naive agent and the guarded graph")
    ev.add_argument("--naive-model", help="drive the naive agent with this model instead of the scripted reasoner")
    ev.add_argument("--base-url", default="http://127.0.0.1:11434/v1", help="OpenAI-compatible endpoint (default: local Ollama)")
    ev.add_argument("--reps", type=int, default=1, help="repetitions with the model (temperature 0, but local models still vary)")
    run = sub.add_parser("run", help="run one scenario through the guarded graph and print the report + audit log")
    run.add_argument("scenario_id")
    run.add_argument("--reviewer", choices=["cautious", "deny-all"], default="cautious")
    args = p.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if args.cmd == "eval":
        if not args.naive_model:
            print(to_markdown(evaluate()))
            return 0
        from soc_graph_guard.reasoners import ModelReasoner

        for rep in range(1, args.reps + 1):
            reasoner = ModelReasoner(args.naive_model, args.base_url)
            print(f"### Naive agent driven by {args.naive_model} (run {rep}/{args.reps})\n")
            print(to_markdown(evaluate(naive_reasoner=reasoner)))
            print(f"\nModel replies that named no allowed action: {reasoner.failures}\n")
        return 0
    scenarios = {s["id"]: s for s in load_scenarios()}
    if args.scenario_id not in scenarios:
        print(f"unknown scenario; choose from: {', '.join(scenarios)}", file=sys.stderr)
        return 2
    reviewer = CautiousReviewer() if args.reviewer == "cautious" else DenyAll()
    report, log, _ = run_guarded(scenarios[args.scenario_id], reviewer)
    print(json.dumps(report, indent=2))
    print(f"\naudit log: {len(log.entries)} entries, chain {'intact' if log.verify() else 'BROKEN'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
