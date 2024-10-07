
**Volume of inbound emails with QR code in last 30 days:**
```
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| join EmailUrlInfo on NetworkMessageId
| where UrlLocation == "QRCode"
| summarize dcount(NetworkMessageId) by bin(Timestamp, 1d)
| render timechart
```

**Emails delivered having URLs in the form of QR codes:**

```
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound"
| where DeliveryAction == "Delivered"
| join EmailUrlInfo on NetworkMessageId
| where UrlLocation == "QRCode"
| project Timestamp, NetworkMessageId, SenderFromAddress, Subject, Url, UrlDomain, UrlLocation
 ```

**Emails with suspicious keywords in subject:**
```
let SubjectKeywords = ()
{
    pack_array("authorize", "authenticate", "account", "confirmation", "QR", "login", "password",  "payment", "urgent", "verify");
};
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound"
| where DeliveryAction == "Delivered"
| where Subject has_any (SubjectKeywords)
| join EmailUrlInfo on NetworkMessageId
| where UrlLocation == "QRCode"
```
 
Reference: https://techcommunity.microsoft.com/t5/microsoft-defender-for-office/hunting-and-responding-to-qr-code-based-phishing-attacks-with/ba-p/4074730
