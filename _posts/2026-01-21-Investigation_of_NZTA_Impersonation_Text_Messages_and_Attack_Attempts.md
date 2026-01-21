---
title: "Threat Intelligence - Investigation of NZTA Impersonation Text Messages and Attack Attempts"
description: "Investigation of Phishing Attempts Impersonating NZTA and Results of Attacker Attribution Investigation"
date: 2026-01-21 00:00:00 +0900
categories: [Threat Intelligence, Threat Investigation]
tags: [research, phishing, web]
media_subpath: /assets/img/2026-01-21-Investigation_of_NZTA_Impersonation_Text_Messages_and_Attack_Attempts
---

## 1. Report Metadata
| Metadata                      | Information                           |
|:------------------------------|:--------------------------------------|
| Report ID                     | TR-RUSTY-2026-0001                    |
| Report Version                | 1.0                                   |
| Report Classification         | PUBLIC DISTRIBUTION                   |
| Investigation Started At      | 2026-01-21 PM 3:00 NZT                |
| Investigation Ended At        | 2026-01-21 PM 5:21 NZT                |
| Investigation Status          | DOMAIN SEIZED or IP BLOCKED           |
| Investigator                  | @therustymate                         |

## 2. Executive Summary
At around 3:00 PM NZT on 2026-01-21, an **attacker impersonating NZTA (New Zealand Transport Agency) attempted to attack us via SMS text message (believed to be typical phishing)**.

However, it appears that **victims have experienced persistent phishing attacks for approximately 5 years since arriving in New Zealand**, and it seems the attacker **uses unspecified methods to obtain phone numbers** to carry out these attempts. The **primary targets are international students**, and there have also been **confirmed attacks specifically targeting Chinese students**.

**It is currently uncertain whether this is the work of the same attack group**. We have secured the phishing URL the attacker attempted to use and immediately commenced an investigation.

## 3. Detailed Technical Analysis

### 3.1 Indicators of Compromise (IoCs)

| Type          | Indicator                                                 |
|:--------------|:----------------------------------------------------------|
| URL           | `https://nzta-govt312[.]help/nz/secure`                   |
| Domain        | `nzta-govt312[.]help`                                     |
| IPv4          | 104.21.12[.]216                                           |
| Phone Number  | `RANDOM`                                                  |

### 3.2 Adversary TTPs Analysis
* **`T1583 (Acquire Infrastructure)`**
  * `T1583.001 (Acquire Infrastructure: Domains)`
  * `T1583.006 (Acquire Infrastructure: Web Services)`
* **`T1566 (Phishing)`**
  * `T1566.002 (Phishing: Spearphishing Link)`
* **`T1657 (Financial Theft)`**

### 3.3 Infrastructure Analysis & Correlations

#### **VirusTotal URL Scan**
![4 Detected](virus_total_url_scan.png)

#### **WhoIs Information**
The Whois information revealed that domain fronting is present through Cloudflare.



|||
|:-|:-|
| Registrar | NameSilo, LLC |
| | IANA ID: 1479 |
| | URL: https://www.namesilo.com/,https://www.namesilo.com |
| | Whois Server: whois.namesilo.com |
| | abuse@namesilo.com |
| | (p) +1.4805240066 |


|||
|:-|:-|
| Registrar Status | addPeriod, client, clientTransferProhibited, serverTransferProhibited |


|||
|:-|:-|
| Dates | Created on 2026-01-20 |
| | Expires on 2027-01-20 |
| | Updated on 2026-01-20 |


|||
|:-|:-|
| Name Servers | GLORIA.NS.CLOUDFLARE.COM (has 37,693,223 domains) |
| | RIDGE.NS.CLOUDFLARE.COM (has 37,693,223 domains) |

**Whois Record ( last updated on 2026-01-21 )**
```
Domain Name: nzta-govt312.help
Registry Domain ID: 
Registrar WHOIS Server: whois.namesilo.com
Registrar URL: https://www.namesilo.com/
Updated Date: 2026-01-20T07:00:00Z
Creation Date: 2026-01-20T07:00:00Z
Registrar Registration Expiration Date: 2027-01-20T07:00:00Z
Registrar: NameSilo, LLC
Registrar IANA ID: 1479
Registrar Abuse Contact Email: 
Registrar Abuse Contact Phone: +1.4805240066
Domain Status: client transfer prohibited https://www.icann.org/epp#client transfer prohibited
Registrant Name: User #ce74831c Privacy
Registrant Organization: See PrivacyGuardian.org
Registrant Street: 1928 E. Highland Ave. Ste F104 PMB# 255
Registrant City: Phoenix
Registrant State/Province: AZ
Registrant Postal Code: 85016
Registrant Country: US
Registrant Phone: +1.3478717726
Registrant Phone Ext: 
Registrant Fax: 
Registrant Fax Ext: 
Registrant Email: 
Admin Name: User #ce74831c Privacy
Admin Organization: See PrivacyGuardian.org
Admin Street: 1928 E. Highland Ave. Ste F104 PMB# 255
Admin City: Phoenix
Admin State/Province: AZ
Admin Postal Code: 85016
Admin Country: US
Admin Phone: +1.3478717726
Admin Phone Ext: 
Admin Fax: 
Admin Fax Ext: 
Admin Email: 
Tech Name: User #ce74831c Privacy
Tech Organization: See PrivacyGuardian.org
Tech Street: 1928 E. Highland Ave. Ste F104 PMB# 255
Tech City: Phoenix
Tech State/Province: AZ
Tech Postal Code: 85016
Tech Country: US
Tech Phone: +1.3478717726
Tech Phone Ext: 
Tech Fax: 
Tech Fax Ext: 
Tech Email: 
Name Server: gloria.ns.cloudflare.com
Name Server: ridge.ns.cloudflare.com
DNSSEC: unsigned
URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/

For more information on Whois status codes, please visit https://icann.org/epp
```

#### **Web Page UserAgent-based Cloaking**

When making a request using Python requests' default User-Agent header, the server responded with the string `Not Found`. This behavior strongly suggests a form of web page cloaking.

```python
>>> import requests
>>> url = "https://nzta-govt312.help/nz/secure"
>>> r = requests.get(url)
>>> r.text
'Not Found'
>>> r.content
b'Not Found'
>>> custom_user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'
>>> headers = {
...     'User-Agent': custom_user_agent
... }
>>> response = requests.get(url, headers=headers)
>>> response.text
'<!DOCTYPE html>\n<html lang=...
>>>
```

Bypassing the cloaking mechanism confirmed that the page is loaded through an abnormal internal method. It was verified that JavaScript is used to load the page.

```html
<!DOCTYPE html>
<html lang="en">

<head>
  <style>
    @charset "UTF-8";

    [ng\:cloak],
    [ng-cloak],
    [data-ng-cloak],
    [x-ng-cloak],
    .ng-cloak,
    .x-ng-cloak,
    .ng-hide:not(.ng-hide-animate) {
      display: none !important;
    }

    ng\:form {
      display: block;
    }

    .ng-animate-shim {
      visibility: hidden;
    }

    .ng-anchor {
      position: absolute;
    }
  </style>
  <title>Transaction Centre | NZ Transport Agency</title>

  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <meta http-equiv="X-UA-Compatible" content="IE=Edge">
  <link href="/k372_nz_etc_nzta_index/favicon.ico?v=1" rel="shortcut icon" type="image/x-icon">
  <link href="/k372_nz_etc_nzta_index/font-awesome/css/font-awesome.min.css" rel="stylesheet" type="text/css">

  <link href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,600,300italic,400italic,600italic"
    rel="stylesheet" type="text/css">
  <link href="/k372_nz_etc_nzta_index/css/style.css?v=NvxbZSRAvCEBJz5ejHIaIfAS1Ay6H5-4o0IpiMKf7_81" rel="stylesheet">



  <base href="/">
  
  <script type="module" crossorigin src="/assets/index-1b5fff30.js"></script>
  <link rel="stylesheet" href="/assets/index-511c37f3.css">
</head>

<body>
  <div id="app"></div>
  
</body>

</html>
```

According to [AngularJS - ngCloak API Reference Docs](https://docs.angularjs.org/api/ng/directive/ngCloak), the following tags are used to prevent raw, uncompiled AngularJS HTML templates from being temporarily displayed in the browser:
* `[ng\:cloak]`
* `[ng-cloak]`
* `[data-ng-cloak]`
* `[x-ng-cloak]`
* `.ng-cloak`
* `.x-ng-cloak`

#### **Ofbuscated JavaScript Web Page Loader**
The JavaScript code loaded from `/assets/index-1b5fff30.js` is the actual website loader containing heavily obfuscated code:

```js
let a=o.data;const c=Bn.from(o.headers).normalize();let{responseType:f,onUploadProgress:h,onDownloadProgress:p}=o,g,m,E,O,N;...
```

Analysis of the assets_index-1b5fff30.js.artifact artifact revealed the following malicious properties:
* `(c) 2018-present Yuxi (Evan) You and Vue contributors`
  * `@vue/shared v3.5.3`
  * `@vue/reactivity v3.5.3`
  * `@vue/runtime-core v3.5.3`
  * `@vue/runtime-dom v3.5.3`
* `(c) 2024 Eduardo San Martin Morote`
  * `pinia v2.2.2`
* `(c) 2024 Eduardo San Martin Morote`
  * `vue-router v4.4.3`
* `(c) 2024 kazuya kawaguchi`
  * `shared v10.0.4`
  * `message-compiler v10.0.4`
  * `core-base v10.0.4`
  * `vue-i18n v10.0.4`
* `(c) 2019 Randjelovic Igor`
  * `vue-scrollto v2.20.0`

#### Dynamic Analysis
After confirming that the malicious JS file is not associated with exploits, we proceeded to dynamic analysis. Direct investigation revealed through the Server header that web hosting is being provided via Cloudflare.

Translation of the string from the console view `页面可见，检查 WebSocket 连接状态` identified message as `The page is visible, check WebSocket connection status`. Analysis of the WSS protocol revealed that it is monitoring the user's heartbeat in real-time.

As confirmed, the site appears to be developed by an individual suspected to be a Chinese hacker.

![Dynamic Analysis](web_page.png)

**2026-01-21-17:17 Live IP Blocked**

## 4. Victimology / Targeting Analysis
The **primary attackers have been identified as Chinese nationals**. They **primarily employ phone scams, text message scams, and phishing scams** to carry out their attacks, all confirmed to be **aimed at stealing financial information or resources (money)**. They **target all international students, regardless of age**, and have been confirmed to **conduct large-scale phishing attacks based on collected phone numbers**.

Furthermore, the design has been confirmed to be similar to that used by an Instagram phishing scammer investigated approximately 3 years ago in a previous Incident Response (`T1531 (Account Access Removal)` was the impact TTP). This **confirms the existence of a large-scale phishing cybercrime organization operated by Chinese nationals**, **targeting New Zealand international students and their guardians, regardless of age**.

## 5. Attribution & Motivation
Analysis of the **attack techniques indicates that all appear to be the work of the same attack group**. It resembles or is a copycat group inspired by the recently prevalent large-scale scam compound operations in Cambodia (operated by Chinese nationals).

Based on the higher frequency of targeting the guardians of international students rather than the students themselves in the surrounding area, their method **seems to exploit the language barrier to intimidate victims and extort money**.

## 6. Impact Assessment
The impact of the attack is assessed as <u>**Medium**</u>. Although the method is a conventional phishing attack rather than a professional hacking intrusion, its **massive scale suggests a potential for evolution into a more powerful transnational cybercrime group in the future**.

Specifically, **the fact that a mobile number created at the airport was leaked and received a phishing email within just 24 hours**, combined with **observations of persistent, large-scale cyber attack attempts over 4-5 years**, <u>**indicates a potential for development into an APT (Advanced Persistent Threat) group**</u>. This leads to a personal assessment of medium impact.

## 7. Response & Mitigation Recommendations
At the New Zealand ISP level, information about existing phishing cybercrimes can be provided to the main targets (international students and their guardians). Detection and removal of illegal relay devices or other phishing-related equipment operations can be enhanced. Additionally, quarantine procedures for new number registrations can be improved and strengthened. (The fact that all phishing messages are mass-produced with the same pattern and yet are not filtered or blocked as spam indicates a clear lack of phishing message signature-based warnings.)

Alternatively, an officially recognized New Zealand anti-phishing app could be developed and provided to the main targets (international students and their guardians), offering a more effective and cost-efficient method for improving warnings about phishing texts.

Another method would be to add phishing prevention features to already developed financial security apps, allowing detection of phishing texts based on signatures or reputation, thereby achieving improvement.

---

For individuals, the solution appears to be deleting, blocking, and reporting. Always being suspicious of unknown numbers is a response individuals can take. Given the massive scale of these phishing operations, it seems unreasonable to expect individuals to implement specialized countermeasures directly.

## 8. Conclusion
In conclusion, **this attack also appears to be a long-prevalent China-originated phishing campaign in New Zealand**. It **exhibits the same mass-produced pattern, but the attack context seems to have shifted** from visa issues to New Zealand highway toll fees. This is **viewed as a typical scenario-based phishing attack by a phishing cybercrime organization**.