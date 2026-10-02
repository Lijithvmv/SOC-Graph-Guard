# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-10-02

First release on PyPI: `pip install soc-graph-guard`.

### Added
- **A real model as the naive baseline:** `soc-graph-guard eval --naive-model <model> [--base-url ...] [--reps N]` drives
  the prompt-only agent with any OpenAI-compatible endpoint (local Ollama by default), with a prompt that tells it to treat
  the data as data. `ModelReasoner` uses only the standard library.
- Results with a local 7B model (qwen2.5-coder, temperature 0, 3 identical runs): **3/7 fully correct, 5 unsafe actions**.
  It followed both injected triage alerts and closed real incidents despite the warning. The scripted CI baseline (2/7,
  12 unsafe actions) overstates the damage; the central finding holds. Raw output in `results/`.
- Release workflow: PyPI trusted publishing with provenance attestations; CI actions pinned by commit; Python 3.13 in CI.

### Changed
- Depends on `guardlayer>=0.8.2` from PyPI instead of a git URL (needed to publish, and no longer tracks GuardLayer's
  main branch). Results unchanged: guarded 7/7, 0 unsafe actions.
- README: install from PyPI; the banner loads from GitHub so it shows on PyPI too.

## [0.1.0] - 2026-09-27

First version: alert triage and phishing containment as LangGraph workflows with graded autonomy, human approval before
irreversible actions, GuardLayer injection screening, decisions computed from structured evidence, evidence-bound
reports, a hash-chained audit log, and an outcome-scored evaluation (7 labelled scenarios; property test over 42
injected variants).
