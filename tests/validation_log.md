# Detection validation log

One row per rule per test run. Evidence over claims.

| Date | Rule | Atomic test (ID) | Expected | Fired? | True/False positive | Notes / tuning action |
|---|---|---|---|---|---|---|
| | powershell_encoded_command.yml | T1059.001 (T1059.001-1) | Alert on encoded payload | | | |
| | ssh_brute_force.yml | T1110.001 (manual hydra) | Alert after 10+ fails/5m | | | |

## Tuning notes
- Record every logic change here with the *reason* (which false positive it killed).
- Interviewers love the tuning story more than the rule itself.
