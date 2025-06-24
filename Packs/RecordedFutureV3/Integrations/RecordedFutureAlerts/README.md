Fetch and triage **Recorded Future Classic Alerts** and **Recorded Future Playbook Alerts** directly from Cortex
XSOAR.  
The integration allows you to:

* Search and fetch alerts from the Recorded Future platform.
* Update alert status, assignee and comment/note from inside XSOAR.
* Automatically fetch screenshots that accompany the alert.

## Configure Recorded Future Alerts in Cortex

| **Parameter**                         | **Description**                                                                                                                                                          | **Required** |
|---------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| Fetch incidents                       |                                                                                                                                                                          | False        |
| Incident type                         |                                                                                                                                                                          | False        |
| Your server URL                       |                                                                                                                                                                          | True         |
| API Key                               | The API Key to use for the connection                                                                                                                                    | True         |
| Source Reliability                    | Reliability of the source providing the intelligence data.                                                                                                               | False        |
| Incidents fetch interval              |                                                                                                                                                                          | False        |
| Maximum number of incidents per fetch | The max number of incidents to fetch per run. Cannot be bigger than 50.                                                                                                  | False        |
| First fetch time                      | How far back we should fetch alerts on the first incident fetch. This value is not used for subsequent fetches. Cannot be bigger than 90 days.                           | False        |
| Enable Classic Alerts                 |                                                                                                                                                                          | False        |
| Classic Alerts: Rule names to fetch   | Rule names to fetch alerts by, separated by semicolon. If empty, all alerts will be fetched.                                                                             | False        |
| Classic Alerts: Statuses to fetch     |                                                                                                                                                                          | True         |
| Enable Playbook Alerts                |                                                                                                                                                                          | False        |
| Playbook Alerts: Priority to fetch    | Fetch playbook alerts with this priority and higher                                                                                                                      | False        |
| Playbook Alerts: Categories to fetch  | Playbook Alert categories to filter by. If empty, all alerts will be fetched. Note that your Recorded Future licensing also affects which Playbook Alerts are available. | False        |
| Playbook Alerts: Statuses to fetch    |                                                                                                                                                                          | True         |
| Trust any certificate (not secure)    |                                                                                                                                                                          | False        |
| Use system proxy settings             |                                                                                                                                                                          | False        |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### rf-alerts

***
List Classic or Playbook alerts.

#### Base Command

`rf-alerts`

#### Input

| **Argument Name**         | **Description**                                                                                                                                                                                      | **Required** |
|---------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| include_classic_alerts    | Whether classic alerts should be included in the response. Possible values are: true, false. Default is true.                                                                                        | Optional     | 
| include_playbook_alerts   | Whether playbook alerts should be included in the response. Possible values are: true, false. Default is true.                                                                                       | Optional     | 
| classic_alert_rule_ids    | Comma-separated Classic Alert Rule IDs. Only applied to Classic Alert search.                                                                                                                        | Optional     | 
| playbook_alert_categories | Comma-separated Playbook Alert categories. Only applied to Playbook Alert search. Possible values are: domain_abuse, cyber_vulnerability, code_repo_leakage, third_party_risk, geopolitics_facility. | Optional     | 
| playbook_alert_priorities | Comma-separated Playbook Alert priorities. Only applied to Playbook Alert search. Possible values are: Informational, Moderate, High.                                                                | Optional     | 
| statuses                  | Comma-separated list of statuses to include. Possible values are: New, InProgress, Resolved, Dismissed.                                                                                              | Optional     | 
| limit                     | Maximum number of alerts to return. Maximum allowed value is 50. Default is 10.                                                                                                                      | Optional     | 
| order_by                  | Field to sort by. created_at or updated_at (default). Possible values are: created_at, updated_at.                                                                                                   | Optional     | 
| order_direction           | asc or desc (default desc). Possible values are: asc, desc.                                                                                                                                          | Optional     | 
| created_from              | Return only alerts created on or after this datetime (ex. "2025-05-17T16:06:00Z").                                                                                                                   | Optional     | 
| created_to                | Return only alerts created on or before this datetime (ex. "2025-05-17T16:06:00Z").                                                                                                                  | Optional     | 
| updated_from              | Return only alerts updated on or after this datetime (ex. "2025-05-17T16:06:00Z").                                                                                                                   | Optional     | 
| updated_to                | Return only alerts updated on or before this datetime (ex. "2025-05-17T16:06:00Z").                                                                                                                  | Optional     | 

#### Context Output

| **Path**                                           | **Type** | **Description**                                                                                                                   |
|----------------------------------------------------|----------|-----------------------------------------------------------------------------------------------------------------------------------|
| RecordedFutureAlerts.Alert.id                      | string   | Unique id of the alert in Recorded Future.                                                                                        | 
| RecordedFutureAlerts.Alert.title                   | string   | Title of the alert.                                                                                                               | 
| RecordedFutureAlerts.Alert.type                    | string   | Alert type (classic-alert / playbook-alert).                                                                                      | 
| RecordedFutureAlerts.Alert.subtype                 | string   | Alert subtype (domain_abuse / cyber_vulnerability / code_repo_leakage / third_party_risk / geopolitics_facility / classic-alert). | 
| RecordedFutureAlerts.Alert.status                  | string   | Status of the alert.                                                                                                              | 
| RecordedFutureAlerts.Alert.created                 | string   | When the alert was created as an ISO8601 string.                                                                                  | 
| RecordedFutureAlerts.Alert.updated                 | string   | When the alert was updated as an ISO8601 string.                                                                                  | 
| RecordedFutureAlerts.Alert.classic_alert_rule_name | string   | If alert is a classic alert, this is the name of the rule that triggered the alert.                                               | 
| RecordedFutureAlerts.Alert.classic_alert_rule_id   | string   | If alert is a classic alert, this is the name of the rule that triggered the alert.                                               | 
| RecordedFutureAlerts.Alert.playbook_alert_category | string   | If alert is a playbook alert, this is the category of the alert.                                                                  | 
| RecordedFutureAlerts.Alert.playbook_alert_priority | string   | If alert is a playbook alert, this is the priority of the alert.                                                                  | 

#### Command Example

```bash
!rf-alerts include_classic_alerts=false playbook_alert_categories=domain_abuse playbook_alert_priorities=High statuses=New limit=5 order_by=updated_at order_direction=desc created_from="2025-05-17T12:06:00Z"
```

#### Context Example

```json
{
  "RecordedFutureAlerts": {
    "Alert": [
      {
        "id": "task:fc34c790-293b-42bd-8f23-c1f571323f8f",
        "title": "Potential Typosquat of example.com",
        "type": "playbook-alert",
        "subtype": "domain_abuse",
        "status": "New",
        "created": "2025-05-17T16:06:00Z",
        "updated": "2025-05-17T17:14:12Z",
        "playbook_alert_category": "domain_abuse",
        "playbook_alert_priority": "High"
        "classic_alert_rule_name": null,
        "classic_alert_rule_id": null
      },
      {
        "id": "7SKZ26",
        "title": "ClassiAlert",
        "type": "classic-alert",
        "subtype": "classic-alert",
        "status": "New",
        "created": "2025-05-17T15:58:30Z",
        "updated": "2025-05-17T16:40:00Z",
        "classic_alert_rule_name": "Alert rule name 1",
        "classic_alert_rule_id": "fDasdfwea"
        "playbook_alert_category": null,
        "playbook_alert_priority": null
      }
    ]
  }
}
```

### rf-alert-update

***
Update an alert in the Recorded Future platform.

#### Base Command

`rf-alert-update`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                            | **Required** |
|-------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| alert_id          | ID of alert to update.                                                                                                                                                                                                                                     | Required     | 
| status            | New status to set for the alert. Possible values are: New, InProgress, Dismissed, Resolved.                                                                                                                                                                | Optional     | 
| comment           | Add comment / Replace note.                                                                                                                                                                                                                                | Optional     | 
| reopen            | Only for Playbook Alerts. Set the reopen strategy for the alert. Reopen on significant updates or keep the alert Resolved. Can only be used with status=Resolved. Possible values are: never, significant_updates. Default: reopen on significant updates. | Optional     | 

#### Context Output

| **Path**                           | **Type** | **Description**                                             |
|------------------------------------|----------|-------------------------------------------------------------|
| RecordedFutureAlerts.Alert.id      | string   | Unique id of the alert in Recorded Future.                  | 
| RecordedFutureAlerts.Alert.type    | string   | Alert type (classic-alert / playbook-alert).                | 
| RecordedFutureAlerts.Alert.status  | string   | Status of alert in Recorded Future.                         | 
| RecordedFutureAlerts.Alert.comment | string   | Note (Classic) or comment (Playbook) that was just applied. | 

#### Command Example

```bash
!rf-alert-update alert_id=task:fc34c790-293b-42bd-8f23-c1f571323f8f status=Resolved comment="Alert resolved - false-positive." reopen=never
```

#### Context Example

```json
{
  "RecordedFutureAlerts": {
    "Alert": {
      "id": "task:fc34c790-293b-42bd-8f23-c1f571323f8f",
      "type": "playbook-alert",
      "status": "Resolved",
      "comment": "Alert resolved - false-positive."
    }
  }
}
```

### rf-alert-rules

***
Search for alert rule IDs.

#### Base Command

`rf-alert-rules`

#### Input

| **Argument Name** | **Description**                                                  | **Required** |
|-------------------|------------------------------------------------------------------|--------------|
| rule_name         | Rule name to search. Can be a partial name.                      | Optional     | 
| limit             | Maximum number of rules to return. Default is 10. Default is 10. | Optional     | 

#### Context Output

| **Path**                            | **Type** | **Description**  |
|-------------------------------------|----------|------------------|
| RecordedFutureAlerts.AlertRule.id   | string   | Alert rule ID.   | 
| RecordedFutureAlerts.AlertRule.name | string   | Alert rule name. | 

#### Command Example

```bash
!rf-alert-rules rule_name="malware" limit=3
```

#### Context Example

```json
{
  "RecordedFutureAlerts": {
    "AlertRule": [
      {
        "id": "mZbDYT",
        "name": "Malware Communication - External IP"
      },
      {
        "id": "mZbDZT",
        "name": "Malware Communication - Suspicious Domain"
      },
      {
        "id": "mxbDZT",
        "name": "Malware Communication - Command & Control"
      }
    ]
  }
}
```

### rf-alert-images

***
Fetch alert images and attach to incident in context Files.

#### Base Command

`rf-alert-images`

#### Command Example

```bash
!rf-alert-images
```

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description**                              |
|----------|----------|----------------------------------------------|
| Files    | Unknown  | New images are attached into incident Files. | 

---

## Pre-process Rule (Recommended)

When the integration fetches alerts, every status change in Recorded Future is delivered as a separate event.  
To prevent duplicate incidents in Cortex XSOAR, create the following **Pre-Process Rule** so that incoming alerts update
the existing incident instead of opening additional ones.

1. Go to **Settings & Info** -> **Settings**
2. Open **Object Setup**  -> **Pre-Process Rules** section.
3. Click **New Rule** and give it a descriptive name - for example *Recorded Future Alert Update*.
4. Under **Conditions for Incoming Incident** add:
    - **Name** **Includes** `RF`
5. In the **Action** section select **Link and close**.
6. In **Link to** choose **newest incident** -> Created within the last: **&lt;appropriate timeframe&gt;** (for example
   *14 days*).
7. And for additional condition:
    - **DbotMirrorId** **Is identical (Incoming Incident) to incoming incident**.
8. And click **Save** to save the Preprocessing rule.
9. You should now see the new rule in the list of Preprocessing rules. Make sure the rule is **Enabled**.

![Pre-process Rule](../../../RecordedFutureV3/doc_files/rf_alerts_pre_process_rule.png)

> Although optional, the rule is highly recommended because it ensures that a single incident in XSOAR tracks all
> updates for a particular Recorded Future Playbook Alert.

