# Microsoft KQL Queries related to URL Click

 [Source/Reference: KQL Queries related to URL Click by Microsoft  ](https://github.com/Azure/Azure-Sentinel/tree/3b75b9928ae40f2684c4d17893652f66d43cadc3/Solutions/Microsoft%20Defender%20XDR/Hunting%20Queries/Email%20Queries/URL%20Click/).


- End user malicious clicks
 ```
  UrlClickEvents
  | where ThreatTypes contains "Phish"
  | extend UrlBlocked = ActionType has_any("ClickBlocked")
  | extend UrlAllowed = ActionType has_any('ClickAllowed')
  | extend UrlPendingVerdict = ActionType has_any('UrlScanInProgress')
  | extend ErrorPage = ActionType has_any('UrlErrorPage')
  | summarize Blocked = countif(UrlBlocked), Allowed = countif(UrlAllowed), PendingVerdict = countif(UrlPendingVerdict), Error = countif(ErrorPage), ClickedThrough = countif(IsClickedThrough)  by AccountUpn
  | sort by Blocked desc
```

- URL click count by click action
 ```
  UrlClickEvents 
  | extend UrlBlocked = ActionType has_any("ClickBlocked") 
  | extend UrlAllowed = ActionType has_any('ClickAllowed') 
  | extend UrlPendingVerdict = ActionType has_any('UrlScanInProgress') 
  | extend ErrorPage = ActionType has_any('UrlErrorPage') 
  | summarize Blocked = countif(UrlBlocked), Allowed = countif(UrlAllowed), PendingVerdict = countif(UrlPendingVerdict), Error = countif(ErrorPage), ClickedThrough = countif(IsClickedThrough)

```

- URL click on ZAP Email
```
AlertInfo
  | where Title contains "Email messages containing malicious URL removed after delivery" and Timestamp > ago (7d)
  | join kind=inner (AlertEvidence| where EntityType == "MailMessage") on AlertId 
  | join UrlClickEvents on NetworkMessageId
```

- URL clicks actions by URL

```
  UrlClickEvents
  | extend UrlBlocked = ActionType has_any("ClickBlocked")
  | extend UrlAllowed = ActionType has_any('ClickAllowed')
  | extend UrlPendingVerdict = ActionType has_any('UrlScanInProgress')
  | extend ErrorPage = ActionType has_any('UrlErrorPage')
  | summarize Blocked = countif(UrlBlocked), Allowed = countif(UrlAllowed), PendingVerdict = countif(UrlPendingVerdict), Error = countif(ErrorPage), ClickedThrough = countif(IsClickedThrough) by Url
```

- URLClick details based on malicious URL click alert
```
  AlertInfo
  | where Title contains "Potentially malicious" and Timestamp > ago (30d)
  | join kind=inner (AlertEvidence| where EntityType == "MailMessage") on AlertId 
  | join UrlClickEvents on NetworkMessageId
```

- User clicked through events
```
  UrlClickEvents 
  | where ActionType == "ClickAllowed" or IsClickedThrough !="0" 
  | where ThreatTypes has "Phish" 
  | summarize by ReportId, IsClickedThrough, AccountUpn, NetworkMessageId, ThreatTypes
```

- User clicks on malicious inbound emails
```
  let UrlClicked = (UrlClickEvents
  | where ActionType == "ClickAllowed" or IsClickedThrough !="0"
  | extend Device_IPv4 = IPAddress
  | project ActionType, Device_IPv4, Url, UrlChain, IPAddress, NetworkMessageId);
  EmailEvents
  | where Timestamp > ago(30d)
  | where isnotempty(ThreatTypes) and EmailDirection == "Inbound"
  | where ThreatTypes has_any ("Malware", "Phish")
  | extend SenderFromAddress_IPv4 = strcat(SenderFromAddress, ", ", SenderIPv4)
  | join kind = inner UrlClicked on NetworkMessageId
  | project Timestamp,NetworkMessageId, Subject, SenderFromAddress_IPv4, RecipientEmailAddress, ThreatTypes, ActionType, Url, UrlChain, Device_IPv4, LatestDeliveryLocation, LatestDeliveryAction, EmailAction, EmailActionPolicy

```

- User clicks on phishing URLs in emails
```
  UrlClickEvents 
  | where ThreatTypes has "Phish" 
  | join EmailEvents on NetworkMessageId,  $left.AccountUpn == $right.RecipientEmailAddress 
  | project Timestamp, Url, ActionType, AccountUpn, ReportId, NetworkMessageId, ThreatTypes, IsClickedThrough, DeliveryLocation, OrgLevelAction, UserLevelAction

```

