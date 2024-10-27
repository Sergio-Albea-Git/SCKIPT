**Detect Screenshots taken on devices**

**Description:** Detect devices taking screenshots and the software used for it. You can comment the Allowlist if you want to see all results or add new cases on it to be excluded to detect unknown or non-approved software.
```
DeviceEvents
| where  ActionType has "ScreenshotTaken" 
| where Allowlist= InitiatingProcessFileName !in ("zoom.exe", "excel.exe","powerpnt.exe", "acrobat.exe","ms-teams.exe","outlook.exe", "onenote.exe","winword.exe")
| summarize make_set(InitiatingProcessFileName) by DeviceName
```

**Author** : Sergio Albea (sergioalbea.com)
