# OpenSIEM Windows Watcher — Administrator Guide

## Files

`watcher_windows.py`: This is the client File, you need to run it with Administrative Rights 
`parse_windows_evtlog.py`: This is parser to parse Windows events. You will find it in `modules/` folder. It contains all the info the admin will need.

No other files are needed. No config file. Everything the administrator needs to change is at the top of `watcher_windows.py`.

---

## Prerequisites

### On the Windows machine

**Python 3.8 or later** — download from python.org. Tick "Add Python to PATH" during install.

**Required packages** — open Command Prompt or PowerShell as Administrator and run:

```
pip install pywin32 psutil
```

After installing pywin32, also run:

```
python -m pywin32_postinstall -install
```

This registers the win32 COM extensions. Without this step the watcher will fail to start.

---

## Configuration

Open `watcher_windows.py` in a text editor. Everything you need to change is between the lines marked `ADMINISTRATOR CONFIGURATION` and `END OF ADMINISTRATOR CONFIGURATION`.

### Basic settings

```python
SERVER      = "192.168.1.10"          # IP of your OpenSIEM server
PORT        = 11514                    # Leave this unless you changed it on the server
CLIENT_NAME = "Windows-Workstation-01" # Friendly name shown in Chronicler
BOOKMARK_FILE = r"C:\ProgramData\OpenSIEM\evtlog_bookmarks.json"
```

The bookmark file is how the watcher remembers where it stopped. If the watcher is offline for two hours, when it comes back it reads every event that happened during those two hours and sends them all. No events are lost as long as the Windows Event Log itself has not rolled over and overwritten them.

### Choosing channels

The `CHANNELS` dictionary controls what gets forwarded:

```python
CHANNELS = {
    "Security": [4624, 4625, 4740],   # Only these three event IDs
    "System":   [],                   # Empty list = forward EVERYTHING
}
```

Remove a channel entirely to stop monitoring it.

**Standard channel names:**

| Channel | What it contains |
|---|---|
| `Security` | Logons, logoffs, account changes, policy changes, privilege use |
| `System` | Service installs, driver errors, reboots, unexpected shutdowns |
| `Application` | Application crashes, errors from installed software |
| `Setup` | Windows Update, feature installs |
| `Microsoft-Windows-PowerShell/Operational` | PowerShell command execution (requires enabling) |
| `Microsoft-Windows-Sysmon/Operational` | Sysmon events (requires Sysmon to be installed) |

For custom application logs, use the exact channel name as it appears in Event Viewer under **Applications and Services Logs**.

---

## Event ID Reference

### Security Channel — Logon and Authentication

| Event ID | Meaning | Severity |
|---|---|---|
| 4624 | Successful logon | Low |
| 4625 | Failed logon | **High** |
| 4634 | Account logoff | Low |
| 4647 | User-initiated logoff | Low |
| 4648 | Logon with explicit credentials (runas) | Mid |
| 4672 | Special privileges assigned at logon (admin logon) | Mid |
| 4768 | Kerberos TGT requested | Low |
| 4769 | Kerberos service ticket requested | Low |
| 4771 | Kerberos pre-authentication failed (wrong password, domain) | **High** |
| 4776 | NTLM authentication attempt | **High** |

### Security Channel — Account Management

| Event ID | Meaning | Severity |
|---|---|---|
| 4720 | User account created | Mid |
| 4722 | User account enabled | Low |
| 4723 | Password change attempted by user | Low |
| 4724 | Password reset by administrator | Mid |
| 4725 | User account disabled | Low |
| 4726 | User account deleted | Mid |
| 4728 | Member added to global security group | Mid |
| 4732 | Member added to local security group | Mid |
| 4738 | User account changed | Mid |
| 4740 | User account locked out | **High** |
| 4756 | Member added to universal security group | Mid |

### Security Channel — Process and Task Tracking

| Event ID | Meaning | Severity |
|---|---|---|
| 4688 | New process created | Low |
| 4689 | Process exited | Low |
| 4698 | Scheduled task created | Mid |
| 4699 | Scheduled task deleted | Mid |
| 4700 | Scheduled task enabled | Low |
| 4701 | Scheduled task disabled | Low |

> **Note:** Event 4688 only appears if Process Tracking auditing is enabled. See Enabling Auditing below.

### Security Channel — Network and Shares

| Event ID | Meaning | Severity |
|---|---|---|
| 5140 | Network share accessed | Low |
| 5145 | Network share object access check | Low |

### System Channel

| Event ID | Meaning | Severity |
|---|---|---|
| 7034 | Service crashed unexpectedly | Mid |
| 7036 | Service started or stopped | Low |
| 7040 | Service start type changed | Mid |
| 7045 | New service installed | **High** — malware often installs services |
| 1074 | System shutdown or restart initiated | Low |
| 6005 | Event log service started (machine booted) | Low |
| 6006 | Event log service stopped (clean shutdown) | Low |
| 6008 | Previous shutdown was unexpected (power loss or crash) | Mid |

### Application Channel

| Event ID | Meaning | Severity |
|---|---|---|
| 1000 | Application error / crash | Mid |
| 1001 | Windows Error Reporting crash dump details | Mid |
| 1002 | Application hang | Mid |

---

## Permissions

### Reading Security channel

The Security channel requires elevated privileges. The watcher must run as one of:

- `SYSTEM` account (recommended for a Windows service)
- A member of the **Event Log Readers** built-in group
- A local Administrator

To add a user to Event Log Readers without making them an admin:

```
net localgroup "Event Log Readers" DOMAIN\username /add
```

### Reading Application and System channels

Standard user accounts can read these channels. No special permissions needed.

---

## Running as a Windows Service

Running the watcher as a service means it starts automatically at boot and runs even when no user is logged in. This is the recommended production setup.

### Option 1 — NSSM (Non-Sucking Service Manager)

1. Download NSSM from nssm.cc and place `nssm.exe` somewhere on the PATH.

2. Open an Administrator Command Prompt and run:

```
nssm install OpenSIEM-Watcher
```

3. In the GUI that opens:
   - **Path**: `C:\Python311\python.exe` (your Python path)
   - **Arguments**: `C:\OpenSIEM\watcher_windows.py`
   - **Startup directory**: `C:\OpenSIEM`

4. Under the **Log on** tab, set the account to `Local System` (for Security channel access).

5. Click Install service, then:

```
nssm start OpenSIEM-Watcher
```

### Option 2 — sc.exe (built-in, no extra download)

This requires wrapping the Python script in a small Windows service wrapper. Use NSSM instead unless you have a specific reason not to.

### Checking service status

```
sc query OpenSIEM-Watcher
```

### Viewing watcher logs

The watcher writes a log file to the same directory as the bookmark file:

```
C:\ProgramData\OpenSIEM\watcher_windows.log
```

---

## Enabling Auditing on Windows

By default, Windows does not log process creation (Event 4688) or detailed object access. To enable:

### Group Policy (domain-joined machines)

`Computer Configuration` → `Windows Settings` → `Security Settings` → `Advanced Audit Policy Configuration` → `System Audit Policies`

Enable:
- **Logon/Logoff** → Logon (Success and Failure)
- **Account Management** → User Account Management (Success)
- **Detailed Tracking** → Process Creation (Success) — for Event 4688
- **Object Access** → File Share (Success and Failure) — for Event 5140/5145

### Local Policy (standalone machines)

Run `gpedit.msc` and navigate the same path as above, or use:

```
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable
auditpol /set /subcategory:"Process Creation" /success:enable
```

---

## Troubleshooting

**"pywin32 is not installed"** — Run `pip install pywin32` then `python -m pywin32_postinstall -install` as Administrator.

**"Cannot open channel 'Security'"** — The watcher is not running with sufficient privileges. Run as Administrator or add the account to Event Log Readers.

**Events are not appearing in Chronicler** — Check `watcher_windows.log`. Also verify `parse_windows_evtlog.py` is in the `modules/` directory on the OpenSIEM server and that the server is reachable on port 11514 from the Windows machine.

**Watcher starts from scratch every time** — The bookmark file path is wrong or the process does not have write access to it. Check `BOOKMARK_FILE` in the configuration and ensure the directory exists.

**Old events are flooding in on first start** — This is expected behaviour on the very first run. The watcher bookmarks the current position and starts forwarding only new events from that point. It will not happen again unless the bookmark file is deleted.
