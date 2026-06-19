# Agentic SOC Analyst

This is a defensive, human-in-the-loop AI-style analyst for the Splunk Mastery Lab.

It queries Splunk through the management REST API, runs curated SPL detections, ranks findings, explains suspicious behavior, and writes an investigation report.

It does not kill processes, block IPs, quarantine files, or modify endpoints.

## Quick Start

From the repo root:

```powershell
python -m agent.run_triage --mode all --earliest -24h --latest now --report reports\latest_triage.md --html-report reports\latest_triage.html --json-output reports\latest_triage.json
```

Focused modes:

```powershell
python -m agent.run_triage --mode endpoint --earliest -24h
python -m agent.run_triage --mode identity --earliest -7d
python -m agent.run_triage --mode cloud --earliest -7d
python -m agent.run_triage --mode web --earliest -24h
python -m agent.run_triage --mode network --earliest -24h
```

## Environment Variables

```powershell
$env:SPLUNK_HOST="localhost"
$env:SPLUNK_PORT="8089"
$env:SPLUNK_USERNAME="admin"
$env:SPLUNK_PASSWORD="SplunkLab!2026"
```

## Detection Coverage

- Identity brute force and password spray
- Impossible travel
- Suspicious living-off-the-land process execution
- Suspicious endpoint egress
- Cloud privilege escalation and persistence
- Risky web/API clients
- Network beacon candidates

## Design Notes

This first version uses deterministic reasoning so the lab works without an external AI API key. It is still "agentic" in the practical SOC sense: it selects detection tasks, queries Splunk, interprets evidence, prioritizes severity, and produces recommended pivots.
