# LogSentinel Pro v4.0 — MVP Testing Guide

## 📋 Prerequisites

### System Requirements
- **Python**: 3.8 or higher
- **OS**: Windows 10/11, Linux, macOS
- **RAM**: 512MB minimum
- **Network**: LAN access for Industry Share testing

### Installation
```bash
cd LogSentinel-Pro
pip install -r requirements.txt
```

### Verify Installation
```bash
python src/cli/logsentinel_main.py version
```
Expected: Version 4.0.0 with all engines loaded.

---

## 🧪 Test Scenarios

### Test 1: Single-Machine Scan (Basic)
**Purpose**: Verify core threat detection works.

1. Create a sample log file:
```bash
# Create test log with realistic entries
cat > test_logs/auth_test.log << 'EOF'
Apr  6 10:15:33 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
Apr  6 10:15:34 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
Apr  6 10:15:35 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
Apr  6 10:15:36 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
Apr  6 10:15:37 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
Apr  6 10:15:38 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Apr  6 10:16:01 server sshd[1234]: Invalid user test from 10.0.0.50 port 22 ssh2
Apr  6 10:16:05 server sudo[5678]: admin : COMMAND=/bin/bash
Apr  6 10:17:00 server kernel: kernel panic - not syncing
Apr  6 10:18:00 web apache2[9999]: GET /login?user=admin' OR 1=1-- HTTP/1.1
Apr  6 10:19:00 web apache2[9999]: GET /path/../../etc/passwd HTTP/1.1
Apr  6 10:20:00 server sshd[1234]: Accepted publickey for admin from 172.16.0.1 port 22
EOF
```

2. Run scan:
```bash
python src/cli/logsentinel_main.py scan test_logs/auth_test.log -v
```

3. **Expected Results**:
   - ✅ 5+ SSH failed password detections (T1110.001)
   - ✅ Brute force escalation after 5 failures
   - ✅ SQL injection detection (T1190)
   - ✅ Path traversal detection (T1083)
   - ✅ Kernel panic detection (T1499)
   - ✅ Risk score >= 75 (CRITICAL)

### Test 2: CVE Analysis
**Purpose**: Verify CVE vulnerability correlation.

```bash
python src/cli/logsentinel_main.py cve test_logs/auth_test.log -v
```

**Expected Results**:
- ✅ Detects `openssh/sshd` from log entries
- ✅ Detects `sudo` from sudo entries
- ✅ Detects `apache` from apache2 entries
- ✅ Maps to relevant CVEs (CVE-2023-38408, CVE-2021-3156, etc.)
- ✅ Shows remediation recommendations with `-v` flag

### Test 3: Blockchain Integrity
**Purpose**: Verify blockchain log integrity chain.

```bash
# Scan with blockchain recording
python src/cli/logsentinel_main.py scan test_logs/auth_test.log -b

# Verify chain
python src/cli/logsentinel_main.py blockchain --verify

# Show blocks
python src/cli/logsentinel_main.py blockchain --show
```

**Expected Results**:
- ✅ Block mined with SHA-256 (4 leading zeros)
- ✅ Chain verification passes
- ✅ Blocks display with hash, timestamp, data

### Test 4: PDF Report Generation
**Purpose**: Verify professional PDF output.

```bash
# Generate threat report
python src/cli/logsentinel_main.py scan test_logs/auth_test.log -v -r

# Generate compliance report
python src/cli/logsentinel_main.py scan test_logs/auth_test.log --compliance PCI-DSS -r
```

**Expected Results**:
- ✅ PDF file generated in current directory
- ✅ Contains risk score, threat table, timeline
- ✅ Professional formatting with branding

---

## 🌐 Industry Share Testing

### Option A: Single-Machine (Two Terminals)

```
Terminal 1 (Instance A):                Terminal 2 (Instance B):
─────────────────────────               ─────────────────────────
python logsentinel_main.py              python logsentinel_main.py
> share --start                         > share --start
> share --connect localhost:9100        > share --status
> scan test.log -v                      > share --received
> share --send report.json              > share --audit
```

**Steps:**
1. Open **two terminal windows** in `src/cli/`
2. In **Terminal 1**: Start LogSentinel, authenticate, then `share --start`
3. In **Terminal 2**: Start LogSentinel, authenticate, then `share --start`
4. In **Terminal 1**: `share --connect localhost:9100`
5. Run a scan in Terminal 1: `scan test_logs/auth_test.log -v`
6. Share: `share --send report.json`
7. In **Terminal 2**: `share --received` — should show the anonymized report

**Verify Anonymization:**
- ✅ Organization name is REMOVED
- ✅ License key is REMOVED
- ✅ Raw log lines are REMOVED
- ✅ Private IPs are replaced with `ANON_HOST_001` etc.
- ✅ Usernames are REMOVED
- ✅ Risk score and threat types are PRESERVED

### Option B: LAN Testing (Two Machines, Same Network)

**Prerequisites:**
- Both machines on the same WiFi/Ethernet
- Python + LogSentinel Pro installed on both
- Know each machine's IP (run `ipconfig` on Windows, `ip addr` on Linux)

**Firewall Setup (Windows):**
```powershell
# Run as Administrator on BOTH machines
netsh advfirewall firewall add rule name="LogSentinel Share" dir=in action=allow protocol=TCP localport=9100
netsh advfirewall firewall add rule name="LogSentinel Discovery" dir=in action=allow protocol=UDP localport=9199
```

**Steps:**
```
Machine A (192.168.1.10):               Machine B (192.168.1.20):
─────────────────────────               ─────────────────────────
> share --start                         > share --start
                                        (Auto-discovers A via broadcast)
> share --status                        > share --status
  Peers: 1 (192.168.1.20)                Peers: 1 (192.168.1.10)
> scan auth.log -v                      
> share --send report.json              > share --received
                                          ✅ Report from A (anonymized)
```

**If auto-discovery fails:**
```
Machine A> share --connect 192.168.1.20:9100
Machine B> share --connect 192.168.1.10:9100
```

### Option C: VPN Testing (Remote Locations)

**1. VPN Server Setup (Ubuntu VPS — $5/month):**
```bash
# Install WireGuard
sudo apt update && sudo apt install wireguard

# Generate keys
wg genkey | tee /etc/wireguard/server_private | wg pubkey > /etc/wireguard/server_public

# Configure /etc/wireguard/wg0.conf
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = <server_private_key>

[Peer]   # Machine A
PublicKey = <machine_A_public_key>
AllowedIPs = 10.0.0.2/32

[Peer]   # Machine B
PublicKey = <machine_B_public_key>
AllowedIPs = 10.0.0.3/32

# Start
sudo wg-quick up wg0
```

**2. Client Setup (Windows):**
- Install [WireGuard for Windows](https://www.wireguard.com/install/)
- Import tunnel config with VPN IP `10.0.0.2` or `10.0.0.3`

**3. Test:**
```
Machine A (VPN: 10.0.0.2):             Machine B (VPN: 10.0.0.3):
─────────────────────────               ─────────────────────────
> share --start                         > share --start
> share --connect 10.0.0.3:9100        > share --connect 10.0.0.2:9100
> scan auth.log -v                      > share --received
> share --send report.json              
```

---

## ✅ Complete Testing Checklist

### Core Features
- [ ] Authentication / License activation works
- [ ] `scan` detects SSH brute force (5+ failed logins)
- [ ] `scan` detects SQL injection patterns
- [ ] `scan` detects XSS, path traversal, RCE patterns
- [ ] `scan -v` shows detailed threat information
- [ ] `scan -r` generates PDF report
- [ ] `scan --compliance PCI-DSS -r` generates compliance PDF
- [ ] `blockchain --verify` validates chain integrity
- [ ] Risk score calculation is accurate (CRITICAL/HIGH/MEDIUM/LOW)

### v4.0 Features
- [ ] `cve FILE` detects software from log patterns (sshd, apache, etc.)
- [ ] `cve FILE -v` shows CVE matches with remediation
- [ ] `share --start` starts Industry Share services
- [ ] `share --status` shows node ID and connection info
- [ ] `share --connect IP` connects to a peer
- [ ] `share --send FILE` sends anonymized report
- [ ] `share --received` shows reports from peers
- [ ] `share --audit` shows share audit trail
- [ ] Anonymizer strips ALL sensitive fields (org, user, raw logs)
- [ ] Anonymizer preserves threat data (risk score, types)
- [ ] Private IPs are anonymized consistently

### Performance & Security
- [ ] Scans complete in < 5 seconds for 10K lines
- [ ] No sensitive data in shared reports (verify JSON output)
- [ ] Blockchain hash starts with "0000" (difficulty 4)
- [ ] Session expires correctly on logout
- [ ] Device fingerprint is consistent across runs

### Multi-Node (LAN/VPN)
- [ ] Peer auto-discovery works on same subnet
- [ ] Manual peer connection works cross-subnet
- [ ] Reports transfer successfully between nodes
- [ ] Audit trail records all share operations
- [ ] 3+ nodes can operate simultaneously

---

## 🐛 Common Issues

| Issue | Solution |
|-------|----------|
| `Premium features unavailable` | Run `pip install -r requirements.txt` |
| `Industry Share error` | Ensure port 9100 is available |
| `Cannot reach peer` | Check firewall rules, verify IP |
| `Auto-discovery fails` | Use `share --connect IP:PORT` manually |
| `CVE database empty` | Database auto-seeds on first run |
| `PDF generation fails` | Install `reportlab`: `pip install reportlab` |
