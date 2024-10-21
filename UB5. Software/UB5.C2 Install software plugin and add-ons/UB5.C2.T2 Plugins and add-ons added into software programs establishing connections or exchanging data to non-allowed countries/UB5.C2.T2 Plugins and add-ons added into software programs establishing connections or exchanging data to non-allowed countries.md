**UB5.C2.T2 Plugins and add-ons added into software programs establishing connections or exchanging data to non-allowed countries**

One of the daily battles I've seen throughout my IT career is the classic scenario: the company restricts what software can be installed, and people lose it, demanding a million programs that they might use... once... maybe.
In scenarios where, after the necessary requests and discussions, the software is approved, I’ve noticed a recurring problem: once we allow new software, are we also monitoring all the marketplace plugins and add-ons that come with it? In some cases, like with Microsoft Teams, I’ve seen good practices in place, such as restricting what can be used within the program.
However, I don’t have the same confidence when it comes to other software and processes. For example:

- SAP Marketplace
- Power BI plugins
- ServiceNow Store
- Atlassian Marketplace
- And many others...

Are we sure that allowing access to these marketplaces doesn’t expose us to risks, such as plugins or add-ons establishing connections or sending data to malicious actors or high-risk countries?

Are we certain that the software in question doesn’t contain vulnerabilities that could allow hackers to access our information?

Based on these concerns, I decided to add a new SCKIPT case and create a KQL query to identify whether non-browser software (which is a separate topic I’ll address later) is establishing connections to high-risk countries (as listed by ChatGPT).

```
//SCKIPT - UB5.C2.T2 Plugins and add-ons added into software programs establishing connections or exchanging data to non-allowed countries 
DeviceNetworkEvents
| where ActionType has "ConnectionSuccess"
| extend countryip = tostring(geo_info_from_ip_address(RemoteIP).country)
| where isnotempty(countryip) and isnotempty( InitiatingProcessFileName)
// at your convenience, focus on non-Microsoft software in this query
| where InitiatingProcessVersionInfoCompanyName !has "Microsoft Corporation"
// excluding browser-related processes
| where InitiatingProcessFileName !in ("firefox.exe","msedge.exe","brave.exe","chrome.exe","firefox","google chrome helper","brave browser helper","microsoft edge helper")
// Top list of countries most associated with cyber threats or dangerous cybersecurity activities( by ChatGPT)
| where countryip has "Russia" or countryip has "China" or countryip has "India" or countryip has "Korea" or countryip has "Iran"
| summarize Different_IPs=make_set(countryip),make_set(RemoteIP), DifferentCountries= dcount(countryip) by InitiatingProcessVersionInfoCompanyName,InitiatingProcessFileName, ActionType, DeviceName, InitiatingProcessCommandLine
```

**Author** : Sergio Albea (sergioalbea.com)
