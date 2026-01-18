# SOC Home Lab -- Detection & Incident Response

This guide walks through building a realistic SOC home lab suitable for
GitHub and SOC Analyst job applications.

------------------------------------------------------------------------

## 1. Lab Objectives

This lab demonstrates: - Centralized logging and monitoring - Detection
engineering - Incident triage and investigation - MITRE ATT&CK mapping -
Clear documentation and reporting

------------------------------------------------------------------------

## 2. Architecture

**Virtual Machines** - Kali Linux (Attacker) - Windows 10 (Endpoint) -
Ubuntu Server (Web / Network Sensor) - Splunk Enterprise (SIEM)

**Network** - Host-only or Internal Network - All logs forwarded to
Splunk via Universal Forwarder

      ____            ____              ____
     ||__||          ||__||            ||__||  
     [ -= ]  ----->  [ -= ]    -----   [ -= ]
     ======          ======            ======
     kali            ubuntu            Windows
     10.10.230.*     10.10.230.*       192.168.228.*
                     192.168.228.*
                     
                         \               /
                          \             /
                           \           /
                                ____
                               ||__||  
	                           [ -= ]  
                               ======                       
                               SIEM
                               192.168.228.*

------------------------------------------------------------------------

## 3. Required Tools

### SIEM

-   Splunk Enterprise (Free, requires account)

### Endpoint Logging
-   Splunk Universal Forwarder (requires free account)
-   Sysmon (Windows)
-   Windows Event Logs
-   auditd (Linux)

### Network

-   Suricata
-   Wireshark

### Attacker Tools

-   nmap
-   Hydra

------------------------------------------------------------------------

## 4. Environment Setup

### Step 1: Virtual Machines

-   Install VirtualBox or VMware
-   Create four VMs
-   Assign 2--4 GB RAM per VM

### Step 2: Networking

-   Configure VMs on the same internal or host-only network
-   Verify connectivity via ping

------------------------------------------------------------------------

## 5. Logging Configuration

### Windows Endpoint

-   Install Sysmon with SwiftOnSecurity config
```
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml

	PS > Sysmon64.exe -i -accepteula sysmonconfig-export.xml
- Enable:
    -   Security logs
	From Powershell:
	auditpol /set /category:"Account Logon" /success:enable /failure:enable
	auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
	auditpol /set /category:"Account Management" /success:enable /failure:enable
	auditpol /set /category:"Privilege Use" /failure:enable
	auditpol /set /category:"System" /success:enable /failure:enable
	auditpol /set /subcategory:"Process Creation" /success:enable

	Verify:
        PS> auditpol /get /category:*

	Enable Command-Line Logging (Critical for SOC)
	PS> reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit `
 		/v ProcessCreationIncludeCmdLine_Enabled `
 		/t REG_DWORD `
 		/d 1 `
 		/f
	(reboot after this setting)
	
  -     PowerShell Operational logs
  
	PS> wevtutil sl Microsoft-Windows-PowerShell/Operational /e:true
	PS> reg add HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging `
	 /v EnableScriptBlockLogging `
	 /t REG_DWORD `
	 /d 1 `
	 /f

	PS> reg add HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging `
	 /v EnableModuleLogging `
	 /t REG_DWORD `
	 /d 1 `
	 /f

	PS> reg add HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames `
	 /v * `
	 /t REG_SZ `
	 /d * `
	 /f

	PS> gpupdate /force

-Install Splunk Universal Forwarder
	https://www.splunk.com/en_us/download/universal-forwarder.html?locale=en_us
	Deployment Server -> leave blank
	Receiving Indexer: SIEM_IP:9997
- Verify Forwarder is Running
	PS> Get-Service SplunkForwarder
- Open Firewall 
        PS> New-NetFirewallRule -DisplayName "Splunk Forwarder Outbound" `
	     -Direction Outbound -Protocol TCP -RemotePort 9997 -Action Allow
- Test Connection
	PS> Test-NetConnection 192.168.228.129 -Port 9997
- Verify Forwarder is Sending Data:
	PS> cd "C:\Program Files\SplunkUniversalForwarder\bin"
	PS> .\splunk.exe list forward-server
```
### Linux Server

-   Enable auditd
-   Log:
    -   /var/log/auth.log
    -   /var/log/syslog
-   Install Splunk Universal Forwarder
```
https://www.splunk.com/en_us/download/universal-forwarder.html?locale=en_us
```

### Network Monitoring

-   Install Suricata
-   Enable eve.json output
-   Forward traffic through Ubuntu-Server
1. Enable IP Forwarding on Ubuntu
```
$ sudo nano /etc/sysctl.conf

uncomment:
		net.ipv4.ip_forward=1
$ sudo sysctl -p
```
2. Configure NAT
```
$ sudo iptables -t nat -A POSTROUTING -o ens33 -j MASQUERADE
$ sudo iptables -A FORWARD -i ens33 -o ens33 -m state --state RELATED,ESTABLISHED -j ACCEPT
$ sudo iptables -A FORWARD -i ens33 -o ens33 -j ACCEPT
Verify:
$ sudo iptables -t nat -L -v
```

3. Point Windows VM to Ubuntu as Gateway
```
PS>	Get-NetIPConfiguration
PS>	New-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceAlias "Ethernet" -NextHop 192.168.228.130
    Confirm:
PS>	route print
```
4. Forward Suricata logs to Splunk
   Add Stanzas to /opt/splunkforwarder/etc/system/local/inputs.conf for each log ingested
```	
[monitor:///var/log/suricata/eve.json]
index = suricata
sourcetype = suricata:json
disabled = false
```
  Restart Universal Forwarder

```
$ sudo /opt/splunkforwarder/bin/splunk restart
```

### Build Splunk Alert
1. Trigger when Suricata detects ET POLICY activity from any host.
	ET POLICY rules are from Emerging Threats;
	
	Network activity that may violate security policy or indicate risky behavior.
	
	Examples:
	
		- HTTP instead of HTTPS
		- FTP
		- Telnet
		- POP3 / IMAP without TLS

------------------------------------------------------------------------

## 6. Attack Simulation

### Brute Force (MITRE T1110)

-   Tool: Hydra
-   Target: SSH or RDP

### PowerShell Abuse (T1059.001)

-   Run encoded or obfuscated PowerShell commands

### Port Scanning (T1046)

-   Tool: nmap
-   Scan Ubuntu server

------------------------------------------------------------------------

## 7. Detection Engineering

### Example: Brute Force Detection (Splunk SPL)

    index=security EventCode=4625
    | stats count by src_ip, user
    | where count > 5

### Example: PowerShell Detection

    EventCode=4104 OR CommandLine="*EncodedCommand*"

------------------------------------------------------------------------

## 8. Incident Response Workflow

For each alert: 
1. Alert description 
2. Initial triage 
3. Evidence
reviewed 
4. MITRE technique 
5. Containment recommendations

Document findings in markdown incident reports.

------------------------------------------------------------------------

## 9. Disclaimer

All attacks are performed in a controlled lab environment for
educational purposes only.
