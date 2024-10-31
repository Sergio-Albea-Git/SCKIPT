

**Monitor device service tampering**

**Description:** Detecting tampering attempts on device services and filtering by Blocked attempts or ignored attempts which could means that the devices was modified.

```
DeviceEvents
| where ActionType == "TamperingAttempt"
| extend OriginalRegistryValue = tostring(parse_json(AdditionalFields).OriginalValue)
| extend Status = tostring(parse_json(AdditionalFields).Status)
| extend TamperingAction = tostring(parse_json(AdditionalFields).TamperingAction)
| extend AttemptedRegistryValue = tostring(parse_json(AdditionalFields).TamperingAttemptedValue)
| where TamperingAction == "RegistryModification"
| extend TamperingAttemptStatus = case(
 Status contains "Blocked", 0,
 Status contains "Ignored", 1,
 -1 )// Default value if neither "Blocked" nor "Ignored" is found)
| extend Status_Result = iif(TamperingAttemptStatus == 0,'🟩💡','🟥🚨')
| distinct DeviceName, TamperingAction, Status_Result,Status, OriginalRegistryValue, AttemptedRegistryValue
```

**Author** : Sergio Albea (sergioalbea.com)

