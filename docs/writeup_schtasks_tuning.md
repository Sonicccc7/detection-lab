# Write-up: Tuning the Scheduled Task Detection (T1053.005)

## 1. Technique
**T1053.005 — Scheduled Task/Job: Scheduled Task.** Attackers love scheduled
tasks because they're built into Windows, run as SYSTEM, survive reboots, and
blend in with the dozens of legitimate tasks every machine already has. It's
one of the most common persistence mechanisms in real intrusions.

## 2. Hypothesis
"If an attacker creates persistence via `schtasks.exe`, we should see a
process-creation event (Sysmon Event ID 1) for `schtasks.exe` with `/create`
in the command line — and legitimate software updaters are the main source
of lookalike noise."

## 3. Data source
Sysmon Event ID 1 (ProcessCreate): `Image`, `CommandLine`, `ParentImage`.
Blind spot: an attacker using the Task Scheduler COM API or PowerShell
`schtasks` alternatives (`Register-ScheduledTask`) won't spawn `schtasks.exe`
— that needs a companion rule (future work).

## 4. Rule logic
`detections/windows/scheduled_task_creation.yml` (v2, current):
- `Image endswith schtasks.exe` AND `CommandLine contains /create`
- minus `filter_vendor_updaters`: excludes command lines containing
  `GoogleUpdate`, `OneDrive`, `AdobeARM`, `MicrosoftEdgeUpdate`

## 5. Test evidence
Ran `tools/harness.py` against 957 seeded synthetic events (49 malicious).

**v1 (before tuning)** — no exclusions:
| | fired | TP | FP |
|---|---|---|---|
| v1 | 5 | 2 | 3 |

The 3 false positives were all vendor updaters:
- `schtasks.exe /create /tn "GoogleUpdateTaskMachineUA" ...`
- `schtasks.exe /create /tn "OneDrive Standalone Update Task" ...`
- `schtasks.exe /create /tn "AdobeARM" ...`

**v2 (after tuning)** — vendor-updater exclusion added:
| | fired | TP | FP |
|---|---|---|---|
| v2 | 2 | 2 | 0 |

Both malicious tasks still fire:
- `schtasks.exe /create /tn "SysCheck" /tr "C:\ProgramData\sys\svc.exe" /sc minute /mo 30 /ru SYSTEM`
- `schtasks.exe /create /tn "Updater" /tr "C:\Windows\Temp\evil.exe" /sc onlogon /ru SYSTEM`

Full per-rule results: `tests/synthetic_validation.md`.
Compiled queries: `compiled/elasticsearch/scheduled_task_creation.txt`,
`compiled/splunk/scheduled_task_creation.txt`.

## 6. Tuning
The change was a single `filter_vendor_updaters` block: 4 `contains`
exclusions on well-known updater task names. FP rate went from 60% (3/5) to
0% with no loss in true positives. The exclusion list is environment-specific
by design — a real deployment would build it from the org's software inventory.

## 7. Residual risk
- An attacker can name their task `GoogleUpdateTaskMachineUA2` and dodge the
  filter. Mitigation: alert on tasks whose *binary path* (`/tr`) points to
  Temp/AppData/ProgramData regardless of name — planned as rule v3.
- COM/PowerShell task creation bypasses `schtasks.exe` entirely — needs a
  `Register-ScheduledTask` / TaskScheduler event-log rule.
