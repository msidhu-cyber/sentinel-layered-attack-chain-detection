# Layered Attack Chain Detection – Microsoft Sentinel

## 🎯 Objective

This lab focuses on detecting a multi-stage attack sequence by correlating authentication, privilege escalation, and beaconing behaviour within Microsoft Sentinel.

The goal is to identify suspicious activity that may individually appear benign, but together forms a high-confidence indicator of compromise.

---

## 🧠 Detection Concept

This detection is based on the following behaviour chain:

> Successful login  
→ Privilege escalation shortly afterwards  
→ Followed by outbound beaconing activity

This sequence reflects a realistic attacker workflow:

1. Gain access  
2. Escalate privileges  
3. Establish persistence or command-and-control communication

---

## 🔎 Detection Logic

The detection identifies:

- A successful login event  
- Followed by privilege escalation within 2 minutes  
- Followed by beaconing activity within 10 minutes  

---

### 🚨 Detection Condition

> Login  
→ Privilege escalation within 2 minutes  
→ Beaconing behaviour within 10 minutes  

This layered approach provides much higher confidence than analysing any of these events individually.

---

## 🔬 Detection Query (KQL)

```kql
let logins =
Syslog
| where TimeGenerated > ago(1h)
| where SyslogMessage contains "Accepted password"
| extend Account = extract(@"for (\w+)", 1, SyslogMessage)
| project LoginTime = TimeGenerated, Computer, Account;

let privilege =
Syslog
| where TimeGenerated > ago(1h)
| where SyslogMessage has_any ("sudo", "session opened for user root")
| project PrivTime = TimeGenerated, Computer;

let beacon =
Syslog
| where TimeGenerated > ago(1h)
| where SyslogMessage contains "beacon_test"
| project BeaconTime = TimeGenerated, Computer;

logins
| join kind=inner privilege on Computer
| where PrivTime between (LoginTime .. LoginTime + 2m)
| join kind=inner beacon on Computer
| where BeaconTime between (PrivTime .. PrivTime + 10m)
| project LoginTime, PrivTime, BeaconTime, Account, Computer
| order by LoginTime desc
```

---

## 🧠 Investigation Methodology

When this detection triggers, the investigation should follow the sequence of the activity:

### 1. Login Review
- Identify the account involved  
- Determine whether the login source is expected  
- Assess whether the account has previously been associated with suspicious activity  

### 2. Privilege Escalation Analysis
- Determine whether privilege escalation is normal for this account  
- Review whether the account typically uses sudo or root access  
- Identify whether escalation occurred unusually quickly after login  

### 3. Beaconing Investigation
- Review outbound communication behaviour  
- Determine whether the beaconing destination or timing is suspicious  
- Assess whether the activity aligns with known attacker persistence or command-and-control techniques  

---

## 🚨 Detection Strengths

- Correlates multiple suspicious behaviours into a single high-confidence detection  
- Reduces noise compared to individual alerts  
- Reflects a realistic attack chain  
- Combines authentication, privilege escalation, and post-compromise activity  

---

## ⚠️ Detection Limitations

This detection may fail or generate false positives in cases such as:

- Legitimate administrative activity following login  
- New employees or role changes requiring elevated access  
- Compromised accounts that already regularly use sudo or outbound activity  
- Attackers delaying actions outside the defined time windows  
- Missing or incomplete telemetry  

Additionally, attackers may avoid detection by:

- Using different privilege escalation methods  
- Avoiding logged outbound activity  
- Spacing activity over longer periods of time  

---

## 🔧 Potential Improvements

This detection could be improved by adding:

- IP address and geolocation analysis  
- User behaviour baselining  
- Multiple failed logins prior to access  
- Frequency-based beacon detection  
- Integration with external threat intelligence or IP reputation  

---

## 📊 Skills Demonstrated

- Multi-stage attack detection  
- Event correlation and behaviour chaining  
- KQL query design and logic structuring  
- Detection engineering using Microsoft Sentinel  
- Identification of detection gaps and false positives  

---

## 📌 MITRE ATT&CK Mapping

- T1078 – Valid Accounts  
- T1548 – Abuse Elevation Control Mechanism  
- T1071 – Application Layer Protocol  
- T1105 – Ingress Tool Transfer  
- T1070 – Indicator Removal on Host  

---

## 🧠 SOC Analyst Reflection

This lab reinforced that high-confidence detections often come from correlating multiple low-confidence events.

A login, privilege escalation, or outbound communication alone may not be enough to indicate compromise.

However, when these events occur together in sequence, they form a much stronger signal that aligns with real attacker behaviour.

This reflects how modern SOC teams build layered detections to identify sophisticated threats.
