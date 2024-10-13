# Microsoft KQL Queries related to Files Copied to USB Drives

  This query lists files copied to USB external drives with USB drive information based on FileCreated events associated with most recent USBDriveMount events befor file creations. But be aware that Advanced Hunting is not monitoring all the file types.


 [Source/Reference: KQL Queries related to Files Copied to USB Drives by Microsoft  ](https://github.com/Azure/Azure-Sentinel/blob/3b75b9928ae40f2684c4d17893652f66d43cadc3/Solutions/Microsoft%20Defender%20XDR/Hunting%20Queries/Exfiltration/FilesCopiedToUSBDrives.yaml)


Files Copied to USB Drives

```
  let UsbDriveMount = DeviceEvents
  | where ActionType=="UsbDriveMounted"
  | extend ParsedFields=parse_json(AdditionalFields)
  | project DeviceId, DeviceName, DriveLetter=ParsedFields.DriveLetter, MountTime=TimeGenerated,
  ProductName=ParsedFields.ProductName,SerialNumber=ParsedFields.SerialNumber,Manufacturer=ParsedFields.Manufacturer
  | order by DeviceId asc, MountTime desc;
  let FileCreation = DeviceFileEvents
  | where InitiatingProcessAccountName != "system"
  | where ActionType == "FileCreated"
  | where FolderPath !startswith "C:\\"
  | where FolderPath !startswith "\\"
  | project ReportId,DeviceId,InitiatingProcessAccountDomain,
  InitiatingProcessAccountName,InitiatingProcessAccountUpn,
  FileName, FolderPath, SHA256, TimeGenerated, SensitivityLabel, IsAzureInfoProtectionApplied
  | order by DeviceId asc, TimeGenerated desc;
  FileCreation | lookup kind=inner (UsbDriveMount) on DeviceId
  | where FolderPath startswith DriveLetter
  | where TimeGenerated >= MountTime
  | partition hint.strategy=native by ReportId ( top 1 by MountTime )
  | order by DeviceId asc, TimeGenerated desc
```
