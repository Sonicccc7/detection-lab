# Phase 1 — Lab Build Guide

Goal: Windows + Linux endpoints shipping logs to a SIEM you control.
Pick **Option A** (local) or **Option B** (cloud). Both end at the same place:
Sysmon and auth logs queryable in Kibana.

---

## Option A — Local lab (recommended if you have 16 GB+ RAM)

### What you need
- 16 GB RAM minimum (32 GB comfortable), ~100 GB free disk
- CPU virtualization enabled in BIOS (VT-x / AMD-V)

### Step 1 — Hypervisor
Install **VirtualBox** (free). Create a host-only network for the lab
(`File → Host Network Manager`), plus NAT for internet access on each VM.
Keep lab traffic off your home LAN.

### Step 2 — The SIEM VM (Elastic)
- VM: Ubuntu Server 22.04, 4 GB RAM, 2 vCPU, 40 GB disk.
- Install Elasticsearch + Kibana (single node). The simplest path is the
  official `docker-compose` for Elastic Stack, or the Debian packages.
- Note the Kibana URL (`http://<vm-ip>:5601`) and the Elastic Agent
  enrollment token (Fleet → Enrollment tokens).

### Step 3 — Windows victim VM
- VM: Windows 10/11 **Evaluation** (free 90-day ISO from Microsoft), 4 GB RAM.
- Install **Sysmon** with the SwiftOnSecurity config:
  `sysmon64.exe -accepteula -i sysmonconfig.xml`
- Install **Elastic Agent**, enroll via Fleet using the token from Step 2.
  Enable the Windows integration — this collects Sysmon (Event ID 1, 3, 7…)
  and Security event logs.

### Step 4 — Linux VM
- VM: Ubuntu Server 22.04, 2 GB RAM, 20 GB disk.
- Install Elastic Agent, enroll via Fleet. Enable the System integration
  (auth logs → `/var/log/auth.log`, syslog).

### Step 5 — Verify log flow
In Kibana → Discover, confirm data streams exist:
- `logs-windows.*` — search `event.code: 1` → you should see process creations
- `logs-system.auth-*` — SSH/auth events from the Linux VM
Run `whoami`, open Notepad, `ssh` into the Linux box — then watch the events land.

### Step 6 — Generate baseline noise (do this before writing detections)
Use the Windows VM normally for a day or two: browse, install 7-Zip/VS Code,
run Windows Update. Normal traffic is what you'll tune false positives against.

---

## Option B — Cloud SIEM (if your machine is weak)

- **Elastic Cloud**: 14-day free trial, no hardware needed. Endpoints can be
  two small local VMs (or even your own machine's logs) with Elastic Agent
  pointed at the cloud deployment.
- **Azure free tier + Microsoft Sentinel**: free 31-day trial + 10 GB/day
  ingestion free for the first 31 days. Good if you want KQL on your resume —
  Sentinel is huge in enterprise.
- Trade-off: trials expire. Export anything you want to keep (rules live in
  Git anyway — that's the point of detection-as-code).

Endpoints are the same as Option A (Windows eval + Sysmon, Ubuntu). Only the
Elasticsearch/Kibana piece moves to the cloud.

---

## Troubleshooting checklist
- [ ] All VMs can ping each other on the host-only network
- [ ] VM clocks in sync (NTP) — skewed timestamps break correlation
- [ ] Elastic Agent shows **Healthy** in Fleet (not just installed)
- [ ] Sysmon running: `sc query sysmon64` on Windows
- [ ] If no logs: check agent policy has the right integrations enabled

## Done when
- [ ] `event.code: 1` (process creation) flowing from Windows
- [ ] SSH auth events flowing from Linux
- [ ] A day of baseline noise generated
- [ ] You can write a KQL/EQL query in Discover and get results

Next: Phase 2 — convert the sample Sigma rules in `detection-lab/` to your
SIEM's query language and deploy them.
