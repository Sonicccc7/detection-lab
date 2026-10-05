# Write-up template

Copy this file per detection deep-dive. Aim for one page: dense, evidence-backed.

## 1. Technique
ATT&CK ID and name. Why attackers use it, in one or two sentences.

## 2. Hypothesis
"If an attacker does X, we should see Y in data source Z."

## 3. Data source
What logs you used (e.g. Sysmon Event ID 1), and why they're the right ones.
Note any blind spots.

## 4. Rule logic
Link the Sigma rule. Explain the key fields and thresholds, and what you
deliberately excluded.

## 5. Test evidence
Atomic Red Team test ID, what you ran, screenshot/description of the alert.
Did it fire as expected?

## 6. Tuning
False positives you observed in baseline noise, what you changed, and the
before/after alert volume. This section is the interview gold.

## 7. Residual risk
What this detection still misses, and what you'd build next.
