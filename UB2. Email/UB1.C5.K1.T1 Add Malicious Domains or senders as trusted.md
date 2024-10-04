**SCKIPT - UB1.C5.K1.T1 Add Malicious Domains or senders as trusted**

Detect senders or domains added in the mailbox Sender List by a User which are delivering Threats
```
//SCKIPT - UB1.C5.K1.T1 Add Malicious Domains or senders as trusted
EmailEvents
| where isnotempty(UserLevelPolicy) and UserLevelAction has "Allow" and isnotempty(ThreatTypes)
| where EmailAction !in ("Send to quarantine", "Move to junk mail folder")
```
