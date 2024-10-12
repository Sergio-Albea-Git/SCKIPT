**SCKIPT - UB1.C5.K1.T1 - Email Rules can forward sensitive data or trigger risky activities**

This query help to identify actions related to Inbox Rules
```
//SCKIPT - UB1.C5.K1.T1 - Email Rules can forward sensitive data or trigger risky activities
CloudAppEvents
// Detect new Inbox Rules
| where ActionType has "New-InboxRule"
// Detect activation of InboxRules --> | where ActionType has "Set-InboxRule"
// Detect InboxRule  Updates --> | where ActionType has "UpdateInboxRules"
// Detect removed Inbox Rules --> | where ActionType has "Remove-InboxRule"
| project ActionType, Application, AccountDisplayName,IPAddress, CountryCode, ISP, ActivityType, ObjectName, ObjectType
```

**Author** : Sergio Albea (sergioalbea.com)
