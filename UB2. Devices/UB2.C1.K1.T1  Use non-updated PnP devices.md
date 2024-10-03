```
//SCKIPT - UB2.C1.K1.T1  Use non-updated PnP devices
let connected = DeviceEvents
| where ActionType has "PnpDeviceConnected"
| extend ClassName = tostring(parse_json(AdditionalFields).ClassName),
 DeviceDescription = tostring(parse_json(AdditionalFields).DeviceDescription),
 ClassID = tostring(parse_json(AdditionalFields).ClassId),
 DevID0 = tostring(parse_json(AdditionalFields).DeviceId);
DeviceEvents
| where ActionType has "PnpDeviceAllowed"
| extend DeviceInstanceId = tostring(parse_json(AdditionalFields).DeviceInstanceId),
 DriverProvider = tostring(parse_json(AdditionalFields).DriverProvider), 
 DriverDate = tostring(parse_json(AdditionalFields).DriverDate),
 DeviceUpdated = tostring(parse_json(AdditionalFields).DeviceUpdated),
 DriverVersion = tostring(parse_json(AdditionalFields).DriverVersion),
 DriverName = tostring(parse_json(AdditionalFields).DriverName)
| join kind=inner (connected) on $left.DeviceInstanceId == $right.DevID0
| where DeviceUpdated == "false"
| distinct DeviceName, ClassName, DeviceDescription, ClassID, DriverProvider, DriverDate, DeviceUpdated, DriverVersion, DriverName```
