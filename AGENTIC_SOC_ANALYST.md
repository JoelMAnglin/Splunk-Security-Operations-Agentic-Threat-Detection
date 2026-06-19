# Agentic SOC Analyst

The lab includes a local defensive analyst agent in `agent/`.

It behaves like a junior SOC analyst with a curated playbook:

1. Connect to Splunk over the management REST API.
2. Run domain-specific SPL detections.
3. Rank finding groups by severity.
4. Explain why the evidence is suspicious.
5. Recommend the next investigation pivot.
6. Write a Markdown report.

It is human-in-the-loop and read-only. It does not terminate processes, block addresses, quarantine files, or change endpoint state.

## Run It

```powershell
python -m agent.run_triage --mode all --earliest -24h --latest now --report reports\latest_triage.md --html-report reports\latest_triage.html --json-output reports\latest_triage.json
```

Or generate and open the visual report:

```powershell
.\scripts\Run-AgentDashboard.ps1
```

## Modes

| Mode | Focus |
| --- | --- |
| `all` | Full cross-domain triage |
| `identity` | Brute force, password spray, impossible travel |
| `endpoint` | Suspicious process chains and egress |
| `cloud` | Cloud identity escalation and persistence |
| `web` | Web/API attack clients |
| `network` | Beacon-like traffic candidates |

## Portfolio Talking Points

- Demonstrates Splunk REST automation.
- Shows curated SPL as reusable detection content.
- Produces explainable, analyst-friendly findings.
- Keeps response actions separate from detection logic.
- Can be extended with a ticketing system, SOAR approvals, or an LLM narrative layer.
