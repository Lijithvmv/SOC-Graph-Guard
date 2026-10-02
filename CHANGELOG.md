# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Live tools over MCP** (`mcp` extra): `MCPBackend` runs the guarded graph against an MCP server you choose (stdio),
  with an example server (`examples/mcp_soc_server.py`) and `soc-graph-guard live --kind ... <server command>`, whose default
  reviewer refuses every approval. Results are parsed strictly (unknown fields dropped; scores outside 0–100 are "no
  data") and every string a live server returns is screened by GuardLayer. All 12 scenarios reach the same decisions over
  MCP as on replay; a hostile server's bogus score is ignored and its injected text taints the session. Uses the official
  `mcp` SDK (2.x), checked for telemetry: none.
- Five scenarios (08–12): account takeover, a ransomware precursor with no known indicator, a benign backup rotation, a
  phishing reply inside a hijacked supplier thread, and a benign marketing newsletter. Ground truth written from an
  analyst's judgement before any run. The injection property test now covers 72 cases.

### Fixed
- **The guarded graph closed a ransomware precursor automatically** (scenario 09): no threat-intel data and few events
  counted as benign. Benign now needs positive evidence (a known reputation or the asset inventory); with no threat-intel
  data, a human decides. Guarded: 10/12 fully correct, 0 unsafe actions; the two misses are documented safe escalations.

### Changed
- Tests split safety (must hold in every scenario) from full correctness (two documented limits, strict expected failures).

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
