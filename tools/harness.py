"""Test harness: run detection logic (mirroring the Sigma rules) over synthetic logs.

Each rule function mirrors its Sigma rule field-for-field; the SSH rule
implements the Sigma correlation (event_count, group-by SourceIP,
timespan 5m, threshold 10). Reports TP/FP/FN per rule and writes
tests/synthetic_validation.md.

Usage: venv/bin/python tools/harness.py
"""
import json
from datetime import datetime, timedelta
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
DATA = BASE / "data"


def load(name):
    with open(DATA / name) as f:
        return [json.loads(line) for line in f]


# ---------------- rule logic (mirrors detections/*.yml) ----------------

def r_encoded_ps(e):
    """powershell_encoded_command.yml (T1059.001)."""
    img = e.get("Image", "").lower()
    cli = e.get("CommandLine", "").lower()
    return (
        e.get("EventID") == 1
        and (img.endswith("powershell.exe") or img.endswith("pwsh.exe"))
        and (" -encodedcommand" in cli or " -enc " in cli or " -e " in cli)
    )


OFFICE = ("winword.exe", "excel.exe", "powerpnt.exe", "mspub.exe", "visio.exe")
SHELLS = ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe")


def r_office_shell(e):
    """office_app_spawning_shell.yml."""
    return (
        e.get("EventID") == 1
        and e.get("ParentImage", "").lower().endswith(OFFICE)
        and e.get("Image", "").lower().endswith(SHELLS)
    )


RUN_KEYS = (
    "\\software\\microsoft\\windows\\currentversion\\run",
    "\\software\\microsoft\\windows\\currentversion\\runonce",
    "\\software\\wow6432node\\microsoft\\windows\\currentversion\\run",
)
ALLOWLIST = ("onedrivesetup.exe", "securityhealthsystray.exe")


def r_registry_run(e):
    """registry_run_key_persistence.yml (T1547.001)."""
    if e.get("EventID") != 13:
        return False
    tgt = e.get("TargetObject", "").lower()
    img = e.get("Image", "").lower()
    return any(k in tgt for k in RUN_KEYS) and not img.endswith(ALLOWLIST)


def r_ssh_bruteforce(events):
    """ssh_brute_force.yml correlation: >10 fails per SourceIP in 5 minutes."""
    by_ip = {}
    for e in events:
        if e.get("EventType") == "Failed password":
            t = datetime.fromisoformat(e["@timestamp"].rstrip("Z"))
            by_ip.setdefault(e["SourceIP"], []).append(t)
    alerted = set()
    for ip, times in by_ip.items():
        times.sort()
        j = 0
        for i, t in enumerate(times):
            while (t - times[j]) > timedelta(minutes=5):
                j += 1
            if i - j + 1 > 10:
                alerted.add(ip)
                break
    return alerted


VENDOR_UPDATERS = ("googleupdate", "onedrive", "adobearm", "microsoftedgeupdate")


def r_schtasks(e):
    """scheduled_task_creation.yml v2 (T1053.005), tuned."""
    cli = e.get("CommandLine", "").lower()
    return (
        e.get("EventID") == 1
        and e.get("Image", "").lower().endswith("schtasks.exe")
        and "/create" in cli
        and not any(v in cli for v in VENDOR_UPDATERS)
    )


LSASS_MASKS = ("0x1010", "0x1410", "0x1438", "0x143a")
LSASS_ALLOW = ("msmpeng.exe", "nissrv.exe")


def r_lsass(e):
    """lsass_process_access.yml (T1003.001)."""
    if e.get("EventID") != 10:
        return False
    return (
        e.get("TargetImage", "").lower().endswith("lsass.exe")
        and any(m in e.get("GrantedAccess", "").lower() for m in LSASS_MASKS)
        and not e.get("SourceImage", "").lower().endswith(LSASS_ALLOW)
    )


def r_wevtutil(e):
    """clear_event_logs.yml (T1070.001)."""
    return (
        e.get("EventID") == 1
        and e.get("Image", "").lower().endswith("wevtutil.exe")
        and " cl " in e.get("CommandLine", "").lower()
    )


# ---------------- scoring ----------------

def score_event_rule(events, rule_fn, rule_name):
    tp = fp = fn = 0
    fp_examples, fn_examples = [], []
    for e in events:
        fired = rule_fn(e)
        expected = rule_name in e.get("_rule", [])
        malicious = e.get("_label") == "malicious"
        if fired and expected:
            tp += 1
        elif fired and not malicious:
            fp += 1
            if len(fp_examples) < 3:
                fp_examples.append(e.get("CommandLine") or e.get("TargetObject"))
        elif not fired and expected:
            fn += 1
            fn_examples.append(e.get("CommandLine") or e.get("TargetObject"))
    return tp, fp, fn, fp_examples, fn_examples


def main():
    sysmon = load("sysmon.jsonl")
    sshd = load("sshd.jsonl")
    rows = []

    for name, fn in [
        ("powershell_encoded_command", r_encoded_ps),
        ("office_app_spawning_shell", r_office_shell),
        ("registry_run_key_persistence", r_registry_run),
        ("scheduled_task_creation", r_schtasks),
        ("lsass_process_access", r_lsass),
        ("clear_event_logs", r_wevtutil),
    ]:
        tp, fp, fn, fp_ex, fn_ex = score_event_rule(sysmon, fn, name)
        precision = tp / (tp + fp) if tp + fp else 0
        recall = tp / (tp + fn) if tp + fn else 0
        rows.append((name, tp, fp, fn, precision, recall, fp_ex, fn_ex))

    # SSH correlation scores per-IP
    alerted = r_ssh_bruteforce(sshd)
    ssh_tp = 1 if "203.0.113.45" in alerted else 0
    ssh_fp_ips = [ip for ip in alerted if ip != "203.0.113.45"]
    rows.append(("ssh_brute_force", ssh_tp, len(ssh_fp_ips),
                 0 if ssh_tp else 1,
                 1.0 if ssh_tp and not ssh_fp_ips else 0.0,
                 float(ssh_tp), ssh_fp_ips, []))

    lines = ["# Synthetic validation results", "",
             "Generated by `tools/harness.py` over seeded synthetic logs "
             "(`tools/synth_logs.py`). Rule logic mirrors `detections/*.yml`.",
             "", "| Rule | TP | FP | FN | Precision | Recall |",
             "|---|---|---|---|---|---|"]
    for name, tp, fp, fn, prec, rec, fp_ex, fn_ex in rows:
        lines.append(f"| {name} | {tp} | {fp} | {fn} | {prec:.2f} | {rec:.2f} |")
    lines += ["", "## Notes"]
    for name, tp, fp, fn, prec, rec, fp_ex, fn_ex in rows:
        if fp_ex:
            lines.append(f"- **{name}** false positives: {fp_ex}")
        if fn_ex:
            lines.append(f"- **{name}** MISSED (false negatives): {fn_ex}")
    if not any(r[5] < 1.0 or r[2] > 0 for r in rows):
        lines.append("- Clean run: no false positives, no misses on this dataset.")
    lines.append("")

    out = BASE / "tests" / "synthetic_validation.md"
    out.write_text("\n".join(lines))

    print(f"{'rule':32} {'TP':>4} {'FP':>4} {'FN':>4} {'prec':>6} {'rec':>6}")
    for name, tp, fp, fn, prec, rec, *_ in rows:
        print(f"{name:32} {tp:>4} {fp:>4} {fn:>4} {prec:>6.2f} {rec:>6.2f}")
    print(f"\nWrote {out.relative_to(BASE)}")


if __name__ == "__main__":
    main()
