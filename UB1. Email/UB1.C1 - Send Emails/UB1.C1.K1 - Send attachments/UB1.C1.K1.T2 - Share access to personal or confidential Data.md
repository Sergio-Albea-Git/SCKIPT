**UB1.C1.K1.T2 - Share access to personal or confidential Data**

User can share or add permissions to acces to organization files which can be non-allowed. This query is really helpful for managing threats like unauthorized access, data leakage, malware distribution, and gives you better visibility and control over what’s being shared.

```
//SCKIPT UB1.C1.K1.T2 - Share access to personal or confidential Data
CloudAppEvents
| extend EventSource= (todynamic(RawEventData).EventSource),
 SourceFileName = (todynamic(RawEventData).SourceFileName),
 GeoLocation = (todynamic(RawEventData).GeoLocation),
 SourceFileExtension = (todynamic(RawEventData).SourceFileExtension),
 TargetUserOrGroupType = (todynamic(RawEventData).TargetUserOrGroupType),
 TargetUserOrGroupName = (todynamic(RawEventData).TargetUserOrGroupName),
 Operation = (todynamic(RawEventData).Operation),
 AuthenticationType = (todynamic(RawEventData).AuthenticationType),
 UserId = (todynamic(RawEventData).UserId)
| where TargetUserOrGroupType == "Guest" or TargetUserOrGroupName contains '#EXT#'
| project ['Shared by']= AccountDisplayName, UserId,GeoLocation, Application,ActivityType, SourceFileName, SourceFileExtension, Operation,TargetUserOrGroupType, ['Guest Granted Access'] = TargetUserOrGroupName
```
