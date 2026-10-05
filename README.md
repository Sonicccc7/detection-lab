# detection-lab

A detection engineering portfolio: custom Sigma detections mapped to MITRE
ATT&CK, compiled to real SIEM queries, and validated against synthetic logs —
**no lab hardware required** to develop and test.

**Author:** hokage_787
**Status:** detection pipeline working; live-lab validation pending

## How it works (hardware-free)

```
detections/*.yml  (Sigma rules, the source of truth)
        │
        ├─► tools/compile.py ──► compiled/elasticsearch/*.txt (EQL)
        │                        compiled/splunk/*.txt        (SPL)
        │                        compiled/manual/*            (hand-authored
        │                                                     threshold logic)
        │
        └─► tools/synth_logs.py ──► data/*.jsonl (labeled Sysmon/sshd events)
                                        │
                             tools/harness.py
                                        │
                                        ▼
                            tests/synthetic_validation.md
                            (TP/FP/FN per rule)
```

## Detections

| Rule | ATT&CK | Data source | Synthetic validation |
|---|---|---|---|
| Suspicious Encoded PowerShell Command Line | T1059.001 | Sysmon Event ID 1 | 12/12 TP, 0 FP |
| Office Application Spawning Shell | T1059 | Sysmon Event ID 1 | 4/4 TP, 0 FP |
| Registry Run Key Persistence | T1547.001 | Sysmon Event ID 13 | 2/2 TP, 0 FP |
| Suspicious Scheduled Task Creation | T1053.005 | Sysmon Event ID 1 | 2/2 TP, 0 FP (tuned from 3 FP) |
| LSASS Process Access for Credential Dumping | T1003.001 | Sysmon Event ID 10 | 2/2 TP, 0 FP |
| Windows Event Log Cleared | T1070.001 | Sysmon Event ID 1 | 2/2 TP, 0 FP |
| Potential SSH Brute Force | T1110.001 | Linux sshd auth logs | attacker caught, slow scan ignored, 0 FP |

## Run it yourself

```bash
python3 -m venv venv && venv/bin/pip install pysigma \
    pysigma-backend-elasticsearch pysigma-backend-splunk
venv/bin/python tools/compile.py      # Sigma -> EQL + SPL
venv/bin/python tools/synth_logs.py   # generate labeled logs
venv/bin/python tools/harness.py      # score every rule
```

Or open in **GitHub Codespaces** — no local setup at all.

## Going live (when you have a lab or cloud SIEM)

1. Paste the compiled queries from `compiled/` into Elastic / Splunk
   (see `compiled/manual/ssh_brute_force.threshold.txt` for the threshold rule setup).
2. Run the matching Atomic Red Team tests — see `docs/atomic_red_team_validation.md`.
3. Record results in `tests/validation_log.md` and tune.

## Write-ups

- `docs/writeup_schtasks_tuning.md` — showcase: tuning the scheduled-task
  rule from 60% FP rate to 0% with full before/after evidence.
- `docs/` — more deep dives: technique → hypothesis → rule logic → test evidence → tuning.
- `docs/writeup_template.md` — template for each new detection.
