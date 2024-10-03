**SCKIPT - UB2.C1.K1.T3 - PnP devices from Unknown vendors**

This query help to identify what type of Devices are connected into our Endpoint 
```
//SCKIPT - UB2.C1.K1.T3 - PnP devices from Unknown vendors
DeviceEvents
| where ActionType has "PnpDeviceConnected"
| extend ClassName = tostring(parse_json(AdditionalFields).ClassName),
 DeviceDescription = tostring(parse_json(AdditionalFields).DeviceDescription)
 | distinct ClassName, DeviceDescription
```
