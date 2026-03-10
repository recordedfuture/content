# Recorded Future Intelligence

Get quick reputation and risk context for IPs, domains, URLs, files, and CVEs from Recorded Future.

This integration was integrated and tested with the Recorded Future BFI XSOAR gateway and SOAR enrichment API used by the RecordedFutureV3 content pack.

## Configure Recorded Future Intelligence in Cortex

| **Parameter**                                               | **Description**                                                             | **Required** |
|-------------------------------------------------------------|-----------------------------------------------------------------------------|--------------|
| Server URL (e.g., https://api.recordedfuture.com/gw/xsoar/) | Base URL of the Recorded Future BFI gateway.                                | True         |
| API Token                                                   | Recorded Future API token.                                                  | False        |
| IP Suspicious Threshold                                     | Minimum Recorded Future risk score required to mark an IP as suspicious.    | False        |
| IP Bad Threshold                                            | Minimum Recorded Future risk score required to mark an IP as malicious.     | False        |
| Domain Suspicious Threshold                                 | Minimum Recorded Future risk score required to mark a domain as suspicious. | False        |
| Domain Bad Threshold                                        | Minimum Recorded Future risk score required to mark a domain as malicious.  | False        |
| URL Suspicious Threshold                                    | Minimum Recorded Future risk score required to mark a URL as suspicious.    | False        |
| URL Bad Threshold                                           | Minimum Recorded Future risk score required to mark a URL as malicious.     | False        |
| File Suspicious Threshold                                   | Minimum Recorded Future risk score required to mark a file as suspicious.   | False        |
| File Bad Threshold                                          | Minimum Recorded Future risk score required to mark a file as malicious.    | False        |
| CVE Suspicious Threshold                                    | Minimum Recorded Future risk score required to mark a CVE as suspicious.    | False        |
| CVE Bad Threshold                                           | Minimum Recorded Future risk score required to mark a CVE as malicious.     | False        |
| Collective Insights                                         | Enable to send lookup context to Recorded Future Collective Insights.       | True         |
| Source Reliability                                          | Reliability value returned in the DBot score for this integration.          | False        |
| Trust any certificate (not secure)                          | Disable certificate verification.                                           | False        |
| Use system proxy settings                                   | Use the system proxy configuration.                                         | False        |

## Notes

- All lookup commands call the BFI endpoint `POST /v3/lookup/reputation`.
- The BFI layer owns the risk translation, portal URL generation, CVE enrichment handling, and the constructor-ready indicator payload returned to XSOAR.
- Each lookup command supports multi-value input because the backend enrichment request uses the Recorded Future SOAR enrichment API.
- Output includes a Recorded Future portal link in `RecordedFuture.<Type>.portalUrl` with `utm_source=xsoar`.
- CVE lookup returns a normal `Common.CVE` object with DBotScore assignment handled consistently with the other indicator types, so severity is populated correctly.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Common DBot Output

All lookup commands return the following DBot score fields:

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. |
| DBotScore.Type | string | The indicator type. |
| DBotScore.Vendor | string | The vendor used to calculate the score. |
| DBotScore.Score | number | The actual score. |
| DBotScore.Reliability | string | Reliability of the source providing the intelligence data. |

### ip

***
Gets a quick indicator of the risk associated with an IP address.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address for which to get the reputation. Supports multiple values. | Required |
| collective_insights | Override the instance-level Collective Insights setting for this command. Possible values are: `on`, `off`. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | string | IP address. |
| IP.Malicious.Vendor | string | For malicious IP addresses, the vendor that made the decision. |
| IP.Malicious.Description | string | For malicious IP addresses, the reason that the vendor made the decision. |
| RecordedFuture.IP.riskScore | number | Recorded Future IP risk score. |
| RecordedFuture.IP.riskLevel | number | Recorded Future IP risk level. |
| RecordedFuture.IP.id | string | Recorded Future IP entity identifier. |
| RecordedFuture.IP.description | string | Recorded Future IP description. |
| RecordedFuture.IP.Evidence.rule | string | Recorded Future risk rule name. |
| RecordedFuture.IP.Evidence.mitigation | string | Recorded Future risk rule mitigation. |
| RecordedFuture.IP.Evidence.description | string | Recorded Future risk rule description. |
| RecordedFuture.IP.Evidence.timestamp | date | Recorded Future risk rule timestamp. |
| RecordedFuture.IP.Evidence.level | number | Recorded Future risk rule level. |
| RecordedFuture.IP.Evidence.ruleid | string | Recorded Future risk rule ID. |
| RecordedFuture.IP.name | string | IP address. |
| RecordedFuture.IP.maxRules | number | Maximum number of Recorded Future IP risk rules. |
| RecordedFuture.IP.rules | string | All triggered rules concatenated by comma. |
| RecordedFuture.IP.ruleCount | number | Number of triggered Recorded Future IP risk rules. |
| RecordedFuture.IP.portalUrl | string | Recorded Future intelligence card URL. |

### domain

***
Gets a quick indicator of the risk associated with a domain.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain for which to get the reputation. Supports multiple values. | Required |
| collective_insights | Override the instance-level Collective Insights setting for this command. Possible values are: `on`, `off`. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | string | Domain name. |
| Domain.Malicious.Vendor | string | For malicious domains, the vendor that made the decision. |
| Domain.Malicious.Description | string | For malicious domains, the reason that the vendor made the decision. |
| RecordedFuture.Domain.riskScore | number | Recorded Future domain risk score. |
| RecordedFuture.Domain.riskLevel | number | Recorded Future domain risk level. |
| RecordedFuture.Domain.id | string | Recorded Future domain entity identifier. |
| RecordedFuture.Domain.description | string | Recorded Future domain description. |
| RecordedFuture.Domain.Evidence.rule | string | Recorded Future risk rule name. |
| RecordedFuture.Domain.Evidence.mitigation | string | Recorded Future risk rule mitigation. |
| RecordedFuture.Domain.Evidence.description | string | Recorded Future risk rule description. |
| RecordedFuture.Domain.Evidence.timestamp | date | Recorded Future risk rule timestamp. |
| RecordedFuture.Domain.Evidence.level | number | Recorded Future risk rule level. |
| RecordedFuture.Domain.Evidence.ruleid | string | Recorded Future risk rule ID. |
| RecordedFuture.Domain.name | string | Domain name. |
| RecordedFuture.Domain.maxRules | number | Maximum number of Recorded Future domain risk rules. |
| RecordedFuture.Domain.rules | string | All triggered rules concatenated by comma. |
| RecordedFuture.Domain.ruleCount | number | Number of triggered Recorded Future domain risk rules. |
| RecordedFuture.Domain.portalUrl | string | Recorded Future intelligence card URL. |

### url

***
Gets a quick indicator of the risk associated with a URL.

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL for which to get the reputation. Supports multiple values. | Required |
| collective_insights | Override the instance-level Collective Insights setting for this command. Possible values are: `on`, `off`. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | string | URL value. |
| URL.Malicious.Vendor | string | For malicious URLs, the vendor that made the decision. |
| URL.Malicious.Description | string | For malicious URLs, the reason that the vendor made the decision. |
| RecordedFuture.URL.riskScore | number | Recorded Future URL risk score. |
| RecordedFuture.URL.riskLevel | number | Recorded Future URL risk level. |
| RecordedFuture.URL.id | string | Recorded Future URL entity identifier. |
| RecordedFuture.URL.description | string | Recorded Future URL description. |
| RecordedFuture.URL.Evidence.rule | string | Recorded Future risk rule name. |
| RecordedFuture.URL.Evidence.mitigation | string | Recorded Future risk rule mitigation. |
| RecordedFuture.URL.Evidence.description | string | Recorded Future risk rule description. |
| RecordedFuture.URL.Evidence.timestamp | date | Recorded Future risk rule timestamp. |
| RecordedFuture.URL.Evidence.level | number | Recorded Future risk rule level. |
| RecordedFuture.URL.Evidence.ruleid | string | Recorded Future risk rule ID. |
| RecordedFuture.URL.name | string | URL value. |
| RecordedFuture.URL.maxRules | number | Maximum number of Recorded Future URL risk rules. |
| RecordedFuture.URL.rules | string | All triggered rules concatenated by comma. |
| RecordedFuture.URL.ruleCount | number | Number of triggered Recorded Future URL risk rules. |
| RecordedFuture.URL.portalUrl | string | Recorded Future intelligence card URL. |

### file

***
Gets a quick indicator of the risk associated with a file.

#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | File hash for which to get the reputation. Supports MD5, SHA1, SHA256, and SHA512, including multiple values. | Required |
| collective_insights | Override the instance-level Collective Insights setting for this command. Possible values are: `on`, `off`. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.SHA256 | string | SHA-256 hash of the file. |
| File.SHA512 | string | SHA-512 hash of the file. |
| File.SHA1 | string | SHA-1 hash of the file. |
| File.MD5 | string | MD5 hash of the file. |
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. |
| File.Malicious.Description | string | For malicious files, the reason that the vendor made the decision. |
| RecordedFuture.File.riskScore | number | Recorded Future file risk score. |
| RecordedFuture.File.riskLevel | number | Recorded Future file risk level. |
| RecordedFuture.File.id | string | Recorded Future file entity identifier. |
| RecordedFuture.File.description | string | Recorded Future file description. |
| RecordedFuture.File.Evidence.rule | string | Recorded Future risk rule name. |
| RecordedFuture.File.Evidence.mitigation | string | Recorded Future risk rule mitigation. |
| RecordedFuture.File.Evidence.description | string | Recorded Future risk rule description. |
| RecordedFuture.File.Evidence.timestamp | date | Recorded Future risk rule timestamp. |
| RecordedFuture.File.Evidence.level | number | Recorded Future risk rule level. |
| RecordedFuture.File.Evidence.ruleid | string | Recorded Future risk rule ID. |
| RecordedFuture.File.name | string | File value. |
| RecordedFuture.File.maxRules | number | Maximum number of Recorded Future file risk rules. |
| RecordedFuture.File.rules | string | All triggered rules concatenated by comma. |
| RecordedFuture.File.ruleCount | number | Number of triggered Recorded Future file risk rules. |
| RecordedFuture.File.portalUrl | string | Recorded Future intelligence card URL. |

### cve

***
Gets a quick indicator of the risk associated with a CVE.

#### Base Command

`cve`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve | CVE for which to get the reputation. Supports multiple values. | Required |
| collective_insights | Override the instance-level Collective Insights setting for this command. Possible values are: `on`, `off`. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CVE.ID | string | CVE identifier. |
| CVE.CVSS.Score | number | CVSS score. |
| CVE.CVSS.Version | string | CVSS version. |
| CVE.CVSS.Vector | string | CVSS vector. |
| CVE.Published | date | CVE published date. |
| CVE.Modified | date | CVE last modified date. |
| CVE.Description | string | CVE description. |
| RecordedFuture.CVE.riskScore | number | Recorded Future CVE risk score. |
| RecordedFuture.CVE.riskLevel | number | Recorded Future CVE risk level. |
| RecordedFuture.CVE.id | string | Recorded Future CVE entity identifier. |
| RecordedFuture.CVE.description | string | Recorded Future CVE description. |
| RecordedFuture.CVE.cvss | number | CVSS score selected for display. |
| RecordedFuture.CVE.cvssScore | number | Raw CVSS score selected for the CVE indicator. |
| RecordedFuture.CVE.cvssVersion | string | CVSS version selected for the CVE indicator. |
| RecordedFuture.CVE.cvssVector | string | CVSS vector selected for the CVE indicator. |
| RecordedFuture.CVE.published | date | CVE published date. |
| RecordedFuture.CVE.modified | date | CVE last modified date. |
| RecordedFuture.CVE.Evidence.rule | string | Recorded Future risk rule name. |
| RecordedFuture.CVE.Evidence.mitigation | string | Recorded Future risk rule mitigation. |
| RecordedFuture.CVE.Evidence.description | string | Recorded Future risk rule description. |
| RecordedFuture.CVE.Evidence.timestamp | date | Recorded Future risk rule timestamp. |
| RecordedFuture.CVE.Evidence.level | number | Recorded Future risk rule level. |
| RecordedFuture.CVE.Evidence.ruleid | string | Recorded Future risk rule ID. |
| RecordedFuture.CVE.name | string | CVE identifier. |
| RecordedFuture.CVE.maxRules | number | Maximum number of Recorded Future CVE risk rules. |
| RecordedFuture.CVE.rules | string | All triggered rules concatenated by comma. |
| RecordedFuture.CVE.ruleCount | number | Number of triggered Recorded Future CVE risk rules. |
| RecordedFuture.CVE.portalUrl | string | Recorded Future intelligence card URL. |
