**Users with SMS authentication as default method**

Using the source mentioned below, I updated one of the KQL Queries to detect specific cases where users are adding SMS Authentication as default method:

 [Source/Reference: Hunting for MFA manipulations in Entra ID tenants using KQL ](https://techcommunity.microsoft.com/t5/microsoft-security-experts-blog/hunting-for-mfa-manipulations-in-entra-id-tenants-using-kql/ba-p/4154039)


```
//Advanced Hunting query to parse modified StrongAuthenticationMethod

let AuthenticationMethods = dynamic(["TwoWayVoiceMobile","TwoWaySms","TwoWayVoiceOffice","TwoWayVoiceOtherMobile","TwoWaySmsOtherMobile","OneWaySms","PhoneAppNotification","PhoneAppOTP"]);
let AuthenticationMethodChanges = CloudAppEvents
| where ActionType == "Update user." and RawEventData contains "StrongAuthenticationMethod"
| extend Target = tostring(RawEventData.ObjectId)
| extend Actor = tostring(RawEventData.UserId)
| mv-expand ModifiedProperties = parse_json(RawEventData.ModifiedProperties)
| where ModifiedProperties.Name == "StrongAuthenticationMethod"
| project Timestamp,Actor,Target,ModifiedProperties,RawEventData,ReportId;
let OldValues = AuthenticationMethodChanges
| extend OldValue = parse_json(tostring(ModifiedProperties.OldValue))
| mv-apply OldValue on (extend Old_MethodType=tostring(OldValue.MethodType),Old_Default=tostring(OldValue.Default) | sort by Old_MethodType);
let NewValues = AuthenticationMethodChanges
| extend NewValue = parse_json(tostring(ModifiedProperties.NewValue))
| mv-apply NewValue on (extend New_MethodType=tostring(NewValue.MethodType),New_Default=tostring(NewValue.Default) | sort by New_MethodType);
let RemovedMethods = AuthenticationMethodChanges
| join kind=inner OldValues on ReportId
| join kind=leftouter  NewValues  on ReportId,$left.Old_MethodType==$right.New_MethodType
| project Timestamp,ReportId,ModifiedProperties,Actor,Target,Old_MethodType,New_MethodType
| where Old_MethodType != New_MethodType
| extend Action = strcat("Removed (" , AuthenticationMethods[toint(Old_MethodType)], ") from Authentication Methods.")
| extend ChangedValue = "Method Removed";
let AddedMethods = AuthenticationMethodChanges
| join kind=inner NewValues on ReportId
| join kind=leftouter  OldValues  on ReportId,$left.New_MethodType==$right.Old_MethodType
| project Timestamp,ReportId,ModifiedProperties,Actor,Target,Old_MethodType,New_MethodType
| where Old_MethodType != New_MethodType
| extend Action = strcat("Added (" , AuthenticationMethods[toint(New_MethodType)], ") as Authentication Method.") 
| extend ChangedValue = "Method Added";
let DefaultMethodChanges = AuthenticationMethodChanges
| join kind=inner OldValues on ReportId
| join kind=inner NewValues on ReportId
| where Old_Default != New_Default and Old_MethodType == New_MethodType and New_Default == "true"
| join kind=inner OldValues on ReportId | where Old_Default1 == "true" and Old_MethodType1 != New_MethodType | extend Old_MethodType = Old_MethodType1
| extend Action = strcat("Default Authentication Method was changed to (" , AuthenticationMethods[toint(New_MethodType)], ").")
| extend ChangedValue = "Default Method";
union RemovedMethods,AddedMethods,DefaultMethodChanges
| where ChangedValue has "Default Method" and NewValue has "5:OneWaySms"
| project Timestamp,Action,Actor,Target,ChangedValue,OldValue=case(isempty(Old_MethodType), "",strcat(Old_MethodType,": ", AuthenticationMethods[toint(Old_MethodType)])),NewValue=case(isempty( New_MethodType),"", strcat(New_MethodType,": ", AuthenticationMethods[toint(New_MethodType)]))
| distinct * 
```
