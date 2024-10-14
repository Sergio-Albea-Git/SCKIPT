**(SCKIPT UB1.C6) Multiple emails removed during specific period of time**

Detect multiple emails removed during specific period of time. You can modify the bin(Timestamp, 8h) field (twice!), to specify the timerange that you would like to monitor.
In addition, you have a commented column (// where EmailsRemoved > 200) which help you to configure the threshold.
```
// (SCKIPT UB1.C6) Multiple emails removed during specific period of time
CloudAppEvents
| where  ActionType has "SoftDelete" or ActionType has "HardDelete"
| summarize EmailsRemoved=count() by ObjectId, bin(Timestamp, 8h),Application, ActionType, AccountDisplayName, IPAddress, CountryCode, ActivityType
| project EmailsRemoved, bin(Timestamp, 8h),Application, ActionType, AccountDisplayName, IPAddress, CountryCode, ActivityType
// where EmailsRemoved > 200
| sort by EmailsRemoved

```
