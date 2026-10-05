# Phase 3 — Validate & Tune with Atomic Red Team

A detection you haven't tested is a guess. Atomic Red Team lets you fire real
ATT&CK techniques at your lab and prove each rule works — then tune it.

## Safety first
Run Atomic Red Team **only on the lab Windows VM**. Never on your host or any
machine you care about. The lab VMs are disposable by design.

## Step 1 — Install (on the Windows lab VM)
In an elevated PowerShell:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
```
This downloads the atomics library (each technique's test commands).

## Step 2 — Map tests to your detections
| Rule | Technique | Atomic test to run |
|---|---|---|
| `powershell_encoded_command.yml` | T1059.001 | `Invoke-AtomicTest T1059.001 -TestNumbers 1` (encoded PowerShell) |
| `ssh_brute_force.yml` | T1110 | Run from the Linux VM or Kali: `hydra -l root -P passwords.txt ssh://<linux-vm>` (11+ bad attempts) |

List available tests any time: `Invoke-AtomicTest T1059.001 -ShowDetails`.

## Step 3 — Execute and observe
```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 1
```
Then check Kibana: did your rule fire? Screenshot the alert — that's portfolio
evidence. Clean up after each test:
```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
```

## Step 4 — Record results
Fill in `tests/validation_log.md`: date, test ID, expected vs actual, TP/FP,
and notes. One row per run. Be honest about misses — documenting a miss and
the fix is stronger than claiming perfection.

## Step 5 — The tuning loop (this is the skill employers pay for)
1. Run the attack → confirm the alert fires (true positive).
2. Look at the last 7 days of baseline noise: does the rule fire on benign
   activity? Those are your false positives.
3. Tighten the logic: add exclusions for known-benign processes/paths,
   raise thresholds, narrow the timeframe.
4. Re-run the attack to confirm you didn't break the true positive.
5. Record the before/after alert volume in the validation log.

Example tuning story for interviews: *"My encoded-PowerShell rule fired 40
times a day from our software deploy tool. I excluded its signed binary path,
kept the Atomic test firing, and got it to zero FPs with no loss in coverage."*

## Step 6 — Coverage map
Once 5+ rules are validated, build an ATT&CK Navigator heatmap
(mitre-attack.github.io/attack-navigator): mark tested techniques green,
in-progress yellow. Export the JSON layer into `docs/` and screenshot it for
the README.

## Done when
- [ ] Every rule has at least one validated test run with evidence
- [ ] Tuning notes show FP reduction per rule
- [ ] ATT&CK Navigator layer exported
- [ ] Cleanup run after every test (lab stays pristine)
