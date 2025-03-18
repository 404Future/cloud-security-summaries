# Respond to alerts and incidents in the Microsoft Defender portal

## Respond to alerts and incidents in the Microsoft Defender portal

**Threat Detection and Alerts**
  - **Preset Security Policies**: Automatically detect threats like phishing, malware, and spoofing with Microsoft’s predefined policies (e.g., Anti-Phishing, Anti-Malware, Spoof Intelligence).
  - Alerts are categorized by severity (Low, Medium, High), with **High** severity alerts requiring immediate action.

**Investigation Process**
  1. **Review Alerts**: Navigate to **Microsoft Defender portal** to view detailed alerts. Focus on affected entities, threat type, and event timeline.
  2. **Correlate with Threat Intelligence**: Use **Office 365 Threat Intelligence (TI)** data to understand the broader context—analyze threat actors, attack methods, and indicators of compromise (IOCs) (e.g., malicious IPs, URLs, domains).
  3. **Assess the Impact**: Determine the scope of the attack and identify affected users, devices, or emails.

**Remediation Actions**
  1. **Block Malicious Content**: Quarantine or block phishing emails, malicious attachments, or URLs.
  2. **Automated Investigation and Response (AIR)**: Use automated workflows to remediate threats, such as isolating compromised accounts or blocking malicious IPs.
  3. **Create Custom Policies**: Adjust or create new policies based on detected threats to prevent recurrence (e.g., stricter spam filters, advanced phishing protection).
  
**Using Threat Intelligence (TI)**
  - **Contextual Data**: Leverage TI to understand the threat’s origin and actors behind the attack.
  - **Indicators of Compromise (IOCs)**: Utilize IOCs to block future attacks and enrich the alert data.
  - **Threat Actor Profiles**: Enhance detection by mapping observed attack tactics and techniques used by known threat actors.

**Best Practices**
  - Continuously **fine-tune** preset security policies for evolving threats.
  - Regularly review **Office 365 Threat Intelligence** to stay updated on emerging threats and attack patterns.
  - Use **Automated Investigation** to speed up response time and reduce manual intervention.

📌 Source:
- [Preset security policies in EOP and Microsoft Defender for Office 365](https://learn.microsoft.com/en-us/defender-office-365/preset-security-policies)
- [Threat investigation and response](https://learn.microsoft.com/en-us/defender-office-365/office-365-ti)

---
## Investigate and remediate ransomware and business email compromise incidents identified by automatic attack disruption

**Automatic Attack Disruption**: Triggers automatic containment actions (e.g., device isolation, user suspension).

**Containment Steps**:
  - Block communication of affected devices.
  - Suspend compromised user accounts.

**Ransomware & BEC Detection**: Identified and tracked via alerts and automatic disruption actions.

**Next Steps**: Investigate alerts, apply remediation measures, and monitor for recurrence.

📌 Source: [Automatic attack disruption in Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption)

---
## Investigate and remediate compromised entities identified by Microsoft Purview data loss prevention (DLP) policies

**Key Concepts**
- **Data Loss Prevention (DLP)**: Helps to protect sensitive information from accidental or malicious exposure.
- **Compromised Entities**: Entities flagged by DLP for potential data exposure or breaches.
  
**Investigation Process**
- **View Alerts**: Access DLP alerts in the Microsoft Purview compliance portal.
- **Review the Alert Details**:
  - Identify the policy violation.
  - Determine the severity of the incident.
  - Examine the entity involved, such as user or device.
  
**Remediation Steps**
1. **Investigate Alerts**: 
   - Open alert details in the Microsoft Purview portal.
   - Check entity activity and violation context.
2. **Take Action**:
   - **User Remediation**: Block or restrict user actions, reset passwords, or initiate multi-factor authentication (MFA).
   - **Policy Changes**: Modify or refine DLP policies to prevent recurrence.
   - **Data Access Review**: Restrict access to sensitive data, conduct forensic reviews.
3. **Monitor and Document**: 
   - Log all actions taken.
   - Continually monitor for further issues related to the compromised entity.
  
**Best Practices**
- **Use DLP Policy Tuning**: Adjust sensitivity of policies based on alert patterns.
- **Proactive Monitoring**: Regularly check for anomalous activity and adjust policies as necessary.
- **Cross-Team Coordination**: Work with security, compliance, and IT teams during incident investigation and remediation.

📌 Source: [Learn about investigating data loss prevention alerts](https://learn.microsoft.com/en-us/purview/dlp-alert-investigation-learn)

---
## Investigate and remediate threats identified by Microsoft Purview insider risk policies

**Key Concepts**
- **Insider Risk Management**: Detects and mitigates risks posed by internal threats (e.g., data theft, leakage).
- **Insider Risk Policies**: Policies to monitor activities that may indicate insider threats (e.g., data exfiltration, unauthorized access).
- **Risk Detection**: Combines signals from Microsoft 365 services to identify suspicious user behavior.

**Steps to Investigate and Remediate**
- **Review Insider Risk Alerts**:
  - Access through Microsoft Purview portal.
  - Alerts can indicate actions like downloading sensitive files, accessing confidential data, or excessive file sharing.
- **Use Case Identification**: 
  - Identify specific policies like "Unauthorized Access," "Data Exfiltration," or "Sensitive Data Sharing."
- **Investigate User Activity**:
  - Review detailed user activity timelines.
  - Cross-check alerts with context (e.g., user role, file types, locations).
- **Manage Incidents**:
  - **Create Incidents**: Associate alerts with incidents to track progress.
  - **Remediate**: Based on findings, use remediation actions like:
    - **User Action**: Disable access, reset passwords, or issue warnings.
    - **Monitor**: Continue tracking suspicious behavior or escalate to legal teams.

**Best Practices**
- **Policy Customization**: Tailor policies to your organization's risk profile for accurate detection.
- **Collaboration**: Work with security, legal, and HR teams during investigation and remediation.
- **Timely Remediation**: Ensure swift action to limit potential data leakage or compromise.

📌 Source: [Investigate insider risk management activities](https://learn.microsoft.com/en-us/purview/insider-risk-management-activities?tabs=purview-portal)

---
## Investigate and remediate alerts and incidents identified by Microsoft Defender for Cloud workload protections

**Overview**
- Microsoft Defender for Cloud offers unified threat detection and protection for cloud resources. It generates security alerts and correlates them into incidents to assist in identifying and mitigating security risks.

**Investigating Alerts**
1. **Access Security Alerts**:
   - Sign in to the Azure portal.
   - Navigate to **Microsoft Defender for Cloud**.
   - Select **Security alerts** to view current alerts.
2. **Review Alert Details**:
   - Click on an alert to see:
     - **Description**: Summary of the detected issue.
     - **Affected Resources**: Details of impacted resources.
     - **Severity**: Level of threat (e.g., high, medium, low).
     - **Remediation Steps**: Recommended actions to resolve the issue.

**Investigating Incidents**
1. **Access Incidents**:
   - In the Defender for Cloud dashboard, select **Security incidents**.
2. **Analyze Incident Details**:
   - Each incident aggregates related alerts, providing:
     - **Incident Timeline**: Chronological sequence of events.
     - **Affected Entities**: Users, applications, or services involved.
     - **Attack Vector**: Method of attack identified.
     - **Recommended Actions**: Steps to mitigate and remediate.

**Remediation Actions**
- **For Alerts**:
  - Follow the provided remediation steps to address specific issues.
- **For Incidents**:
  - Implement recommended actions to resolve the underlying causes.
  - Utilize Defender for Cloud's tools to monitor the effectiveness of remediation efforts.

**Best Practices**
- **Regular Monitoring**: Consistently review security alerts and incidents to stay informed about potential threats.
- **Incident Correlation**: Understand how individual alerts relate to broader incidents to identify comprehensive attack patterns.
- **Timely Remediation**: Promptly address identified issues to minimize potential impact.
- **Continuous Improvement**: Use insights gained from investigations to enhance security measures and prevent future incidents.

📌 Source: [Review workload protection](https://learn.microsoft.com/en-us/azure/defender-for-cloud/workload-protections-dashboard)

---
## Investigate and remediate security risks identified by Microsoft Defender for Cloud Apps

**Overview**
- Microsoft Defender for Cloud Apps (MDCA) enables organizations to detect, investigate, and remediate security risks within their cloud environments by monitoring user activities, app behaviors, and data flows.

**Investigating Anomaly Detection Alerts**
1. **Access Anomaly Detection Alerts**:
   - Navigate to the Microsoft 365 Defender portal.
   - Go to **Alerts** to view a list of triggered anomaly detection alerts.
2. **Analyze Alert Details**:
   - Click on an alert to view its specifics, including:
     - **Description**: Summary of the detected anomaly.
     - **Affected Entities**: Users, IP addresses, or apps involved.
     - **Timestamp**: When the anomaly occurred.
     - **Activity Log**: Detailed events leading to the alert.
3. **Determine Alert Classification**:
   - **True Positive (TP)**: Confirmed malicious activity.
   - **Benign True Positive (B-TP)**: Suspicious but non-malicious activity (e.g., authorized testing).
   - **False Positive (FP)**: Non-malicious activity incorrectly flagged.
4. **Investigative Steps**:
   - Review user activities for other indicators of compromise.
   - Examine device information: operating system, browser version, IP address, and location.
   - Correlate with other alerts to assess the scope of potential breaches.

**Remediation Actions**
1. **For True Positives**:
   - **Suspend User**: Temporarily disable the user's account.
   - **Mark User as Compromised**: Flag the account for further investigation.
   - **Reset Password**: Force a password change to prevent unauthorized access.
2. **For Benign True Positives**:
   - **Dismiss Alert**: Acknowledge the alert as non-threatening (e.g., authorized security testing).
3. **For False Positives**:
   - **Dismiss Alert**: Mark the alert as a false positive to refine future detections.

**Best Practices**
- **Regular Monitoring**:
  - Consistently review anomaly detection alerts to identify potential threats promptly.
- **Automated Investigations**:
  - Utilize automated investigation and response (AIR) capabilities to swiftly address common threats.
- **Policy Management**:
  - Create and fine-tune policies to detect specific events of interest.
  - Add automated actions to respond and remediate risks automatically.

📌 Source: [How to investigate anomaly detection alerts](https://learn.microsoft.com/en-us/defender-cloud-apps/investigate-anomaly-alerts)

---
## Investigate and remediate compromised identities that are identified by Microsoft Entra ID

**Overview**
- Microsoft Entra ID Protection helps organizations detect, investigate, and remediate identity-based risks, enhancing security by identifying compromised identities and mitigating potential threats.

**Investigating Risks**
1. **Access Risk Reports**:
   - Navigate to the Microsoft Entra admin center.
   - Go to **Protection** > **Identity Protection**.
   - Review the following reports:
     - **Risky Users**: Users flagged for potential compromise.
     - **Risky Sign-Ins**: Sign-in attempts with detected risks.
     - **Risk Detections**: Specific risk events identified.
2. **Analyze Risky Users**:
   - In the **Risky Users** report, select a user to view details such as:
     - **User Information**: User ID, location, etc.
     - **Recent Risky Sign-Ins**: List of suspicious sign-in attempts.
     - **Risk History**: Chronology of risk detections and actions.

**Remediation Actions**
1. **User-Level Actions**:
   - **Reset Password**: Forces the user to change their password, revoking current sessions.
   - **Confirm User Compromised**: Marks the user as compromised, setting their risk level to high.
   - **Confirm User Safe**: Indicates a false positive, removing associated risks.
   - **Dismiss User Risk**: Ignores the current risk, marking it as benign.
2. **Sign-In Level Actions**:
   - **Confirm Compromised**: Validates the sign-in as malicious, prompting necessary remediation.
   - **Dismiss Risk**: Marks the sign-in risk as benign, removing the alert.

**Automated Remediation**
- **Risk-Based Policies**:
  - Configure policies to automate responses to detected risks:
    - **User Risk Policy**: Applies actions based on the user's risk level.
    - **Sign-In Risk Policy**: Applies actions based on the risk level of sign-in attempts.
- **Self-Remediation**:
  - Allow users to address their own risks by:
    - **Performing Multi-Factor Authentication (MFA)**: Validates user identity during risky sign-ins.
    - **Password Reset**: Users can reset their passwords to mitigate risks.

**Best Practices**
- **Regular Monitoring**: Consistently review risk reports to identify and address potential compromises promptly.
- **Policy Configuration**: Set up risk-based Conditional Access policies to automate responses to detected risks.
- **User Education**: Educate users on recognizing and responding to security prompts, such as MFA challenges and password reset procedures.

📌 Source: [How To: Investigate risk](https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-investigate-risk)

---
## Investigate and remediate security alerts from Microsoft Defender for Identity

**Overview**
- Microsoft Defender for Identity (MDI) detects and raises security alerts for suspicious activities related to identities within your network. These alerts are integrated into Microsoft Defender XDR, providing enriched cross-domain signals and automated response capabilities.

**Accessing Security Alerts**
1. **Navigate to Alerts**:
   - Sign in to the Microsoft Defender portal.
   - Go to **Incidents & alerts** > **Alerts**.
2. **Filter for MDI Alerts**:
   - Select **Filter** in the top-right corner.
   - Under **Service sources**, choose **Microsoft Defender for Identity**.
   - Click **Apply** to view MDI-specific alerts.

**Investigating Alerts**
- **Alert Details**:
  - Click on an alert's name to access detailed information, including:
    - **What happened**: Summary of the suspicious activity.
    - **Involved entities**: Accounts, devices, IP addresses, and domains linked to the alert.
- **Entity Exploration**:
  - Select any entity (e.g., account, device) to view its profile and related activities.

**Managing Alerts**
- **Classification**:
  - Designate the alert as **True** or **False** based on investigation findings.
- **Assignment**:
  - Assign the alert to yourself or another analyst for tracking and resolution.
- **Comments & History**:
  - Add investigation notes and review the alert's action history for collaboration and auditing.

**Automated Investigation and Response (AIR)**
- **Automated Actions**:
  - MDI alerts can trigger AIR capabilities, automatically investigating and remediating threats.
- **Action Center**:
  - Monitor and manage all remediation actions, both pending and completed, within the Action Center.

**Best Practices**
- **Regular Monitoring**:
  - Consistently review and investigate alerts to maintain a robust security posture.
- **Cross-Domain Correlation**:
  - Leverage the integration of MDI alerts with other Microsoft Defender products for comprehensive threat analysis.
- **Documentation**:
  - Maintain detailed records of investigations and remediation steps for future reference and compliance.

📌 Source: [Investigate Defender for Identity security alerts in Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-for-identity/manage-security-alerts)

---
# Respond to alerts and incidents identified by Microsoft Defender for Endpoint

## Investigate device timelines

**Overview**
- The **Device Timeline** in Microsoft Defender for Endpoint offers a chronological view of events and alerts on a specific device, aiding in the investigation of anomalous behaviors and potential security incidents. 

**Key Features**
- **Chronological Event View**: Displays events and associated alerts in sequence, facilitating correlation and analysis.
- **Custom Time Range Selection**: Allows filtering of events within specific time frames using a custom date picker.
- **Process Tree Visualization**: Provides a hierarchical view of processes to understand parent-child relationships and process lineage.
- **MITRE ATT&CK Techniques Integration**: Highlights detected techniques with corresponding MITRE ATT&CK IDs, offering deeper insight into adversary behaviors.
- **Event Flagging**: Enables marking of specific events for follow-up or further investigation.

**Investigation Steps**
1. **Access Device Timeline**:
   - Navigate to the **Devices list** in the Microsoft Defender portal.
   - Select the device of interest.
   - Click on the **Timeline** tab to view events.
2. **Analyze Events**:
   - Review the chronological list for anomalies or suspicious activities.
   - Utilize the process tree to trace process origins and hierarchies.
3. **Filter and Search**:
   - Apply date filters to narrow down events to specific periods.
   - Use the search function to locate particular events or indicators.
4. **Investigate Techniques**:
   - Identify highlighted MITRE ATT&CK techniques within the timeline.
   - Select a technique to open a side pane with detailed information and related tactics.
   - Utilize the "Hunt for related events" option to perform advanced hunting queries based on the technique.
5. **Flag Events**:
   - Mark significant events using the flag feature for easy reference and follow-up.
6. **Export Data**:
   - Export the timeline data for reporting or offline analysis as needed.

**Best Practices**
- **Regular Monitoring**: Consistently review device timelines to promptly identify and address potential threats.
- **Comprehensive Analysis**: Leverage the integration with MITRE ATT&CK to understand the context and methodology of detected techniques.
- **Collaboration**: Use event flagging to coordinate investigations among team members effectively.

📌 Source: [Microsoft Defender for Endpoint device timeline](https://learn.microsoft.com/en-us/defender-endpoint/device-timeline-event-flag)

---
## Perform actions on the device, including live response and collecting investigation packages

**Essential Concepts**
- **Live Response**: A feature in Microsoft Defender for Endpoint that provides instantaneous remote shell access to a device, enabling in-depth investigations and immediate response actions. 
- **Investigation Package**: A collected set of data from a device, including logs and artifacts, used to analyze the current state and understand potential threats. 

**Initiating a Live Response Session**
1. **Access Device Inventory**:
   - Sign in to the Microsoft Defender portal.
   - Navigate to **Endpoints > Device inventory**.
2. **Select Device**:
   - Choose the device to investigate.
3. **Start Session**:
   - Click on **Initiate live response session**.
   - Wait for the command console to connect.

**Common Live Response Commands**
- **File Operations**:
  - `dir` – List directory contents.
  - `getfile <file_path>` – Download a file from the device.
  - `putfile <file_path>` – Upload a file to the device.
- **Process Management**:
  - `processes` – Display running processes.
  - `kill <process_id>` – Terminate a process.
- **Network Operations**:
  - `netstat` – Show network connections.
  - `connections` – List active network connections.
- **Registry Operations**:
  - `reg query <key>` – Query registry keys.
  - `reg set <key> <value>` – Set registry values.

**Collecting an Investigation Package**
1. **Initiate Collection**:
   - On the device's page, select **Collect investigation package**.
2. **Provide Justification**:
   - Enter the reason for collecting the package.
3. **Confirm Action**:
   - Click **Confirm** to start the collection process.
4. **Download Package**:
   - Once ready, download the zipped investigation package for analysis.

**Best Practices**
- **Script Management**:
  - Upload and execute only signed scripts to maintain security integrity.
- **Data Collection**:
  - Regularly collect investigation packages for comprehensive analysis.
- **Access Control**:
  - Restrict live response capabilities to authorized personnel.
- **Documentation**:
  - Maintain detailed logs of actions performed during live response sessions.

📌 Source: [Take response actions on a device](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts)

---
## Perform evidence and entity investigation

**Essential Concepts**
- **Live Response**: A remote shell connection feature in Microsoft Defender for Endpoint that allows security teams to perform in-depth investigations and immediate response actions on devices. 
- **Supported Actions**:
  - Collect forensic data
  - Run scripts
  - Analyze suspicious entities
  - Remediate threats
  - Proactively hunt for emerging threats

**Prerequisites**
- **Supported Operating Systems**:
  - Windows 10 & 11 (Version 1909 or later)
  - macOS (Minimum version: 101.43.84)
  - Linux (Minimum version: 101.45.13)
  - Windows Server 2012 R2, 2016, 2019, 2022, 2025
- **Configuration**:
  - Enable live response in the advanced features settings.
  - Ensure appropriate user permissions are assigned.

**Initiating a Live Response Session**
1. **Access Device Inventory**:
   - Sign in to the Microsoft Defender portal.
   - Navigate to **Endpoints > Device inventory**.
2. **Select Device**:
   - Choose the device to investigate.
3. **Start Session**:
   - Click on **Initiate live response session**.
   - Wait for the command console to connect.

**Common Live Response Commands**
- **File Operations**:
  - `dir` – List directory contents.
  - `getfile <file_path>` – Download a file from the device.
  - `putfile <file_path>` – Upload a file to the device.
- **Process Management**:
  - `processes` – Display running processes.
  - `kill <process_id>` – Terminate a process.
- **Network Operations**:
  - `netstat` – Show network connections.
  - `connections` – List active network connections.
- **Registry Operations**:
  - `reg query <key>` – Query registry keys.
  - `reg set <key> <value>` – Set registry values.

**Best Practices**
- **Script Management**:
  - Upload and execute only signed scripts to maintain security integrity.
- **Data Collection**:
  - Regularly collect investigation packages for comprehensive analysis.
- **Access Control**:
  - Restrict live response capabilities to authorized personnel.
- **Documentation**:
  - Maintain detailed logs of actions performed during live response sessions.

📌 Source: [Investigate entities on devices using live response](https://learn.microsoft.com/en-us/defender-endpoint/live-response)

---
# Investigate Microsoft 365 activities

## Investigate threats by using the unified audit log

**Essential Concepts**
- **Unified Audit Log**: A centralized log in Microsoft 365 that captures user and administrator activities across various services, aiding in security investigations and compliance reporting. 
- **Audited Activities**: Includes operations like changes to data retention settings, advanced feature configurations, creation of indicators of compromise, device isolations, role modifications, custom detection rule management, and incident assignments. 

**Prerequisites**
- **Permissions**: Membership in the "View-Only Audit Logs" or "Audit Logs" role in Exchange Online is required. These roles are part of the Compliance Management and Organization Management role groups. 
- **Enable Auditing**: Auditing must be enabled in the Microsoft Purview compliance portal to start recording activities. 

**Accessing the Unified Audit Log**
1. **Navigate to the Audit Log**:
   - Go to the Microsoft Defender portal's Audit page or access the Purview compliance portal and select 'Audit'. 
2. **Configure Search Parameters**:
   - On the 'New Search' page, set filters for activities, dates, and users to specify the search criteria. 
3. **Execute the Search**:
   - Click 'Search' to retrieve the audit log entries matching the defined parameters. 
4. **Export Results**:
   - After obtaining the search results, export them to Excel for detailed analysis or record-keeping. 

**Best Practices**
- **Regular Monitoring**: Consistently review audit logs to promptly detect and respond to unauthorized or suspicious activities.
- **Granular Filtering**: Utilize specific filters such as activity types, date ranges, and user details to streamline investigations.
- **Data Retention Policies**: Understand and configure audit log retention policies to ensure compliance with organizational and regulatory requirements. 
- **Role-Based Access Control**: Assign appropriate permissions to personnel accessing audit logs to maintain data security and integrity.

📌 Source: [Search the audit log for events in Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/microsoft-xdr-auditing#using-the-audit-search-in-microsoft-defender-xdr)

---
## Investigate threats by using Content Search

**Essential Concepts**
- **Content Search**: A feature in the Microsoft Purview compliance portal that allows searching across in-place content such as emails, documents, and instant messaging conversations within Microsoft 365 data sources.
- **Supported Data Sources**:
  - Exchange Online mailboxes
  - SharePoint Online sites and OneDrive for Business accounts
  - Microsoft Teams
  - Microsoft 365 Groups
  - Viva Engage Groups

**Prerequisites**
- **Permissions**: Membership in the eDiscovery Manager role group within the Purview portal is required to access and utilize Content Search features. :contentReference[oaicite:1]{index=1}
- **Licensing**: An appropriate Microsoft 365 subscription that includes compliance features is necessary.

**Creating and Running a Content Search**
1. **Access the Purview Portal**:
   - Sign in to the Microsoft Purview portal with the necessary permissions.
2. **Initiate a New Search**:
   - Navigate to the 'Content search' section.
   - Click on 'New search'.
3. **Define Search Parameters**:
   - **Name and Description**: Provide a unique name and an optional description for the search.
   - **Locations**: Select the content locations to search, such as specific mailboxes, sites, or all available sources.
   - **Conditions**: Set specific keywords, date ranges, or other conditions to refine the search criteria.
4. **Execute the Search**:
   - Review the settings and run the search.
   - Monitor the search's progress and view the number of items found.

**Viewing and Exporting Search Results**
- **Preview Results**:
  - After the search completes, preview the results directly within the portal to assess relevance.
- **Export Results**:
  - If necessary, export the search results for further analysis or record-keeping.
  - Choose appropriate export settings, such as output formats and data to include.

**Best Practices**
- **Regular Monitoring**: Consistently perform content searches to identify and address potential threats promptly.
- **Granular Search Criteria**: Utilize specific keywords, date ranges, and other conditions to narrow down search results effectively.
- **Compliance and Security**: Ensure that searches and handling of results comply with organizational policies and regulatory requirements.
- **Access Control**: Limit Content Search permissions to authorized personnel to maintain data security and integrity.

📌 Source: [Get started with Content search](https://learn.microsoft.com/en-us/purview/ediscovery-content-search)

---
## Investigate threats by using Microsoft Graph activity logs

**Essential Concepts**
- **Microsoft Graph Activity Logs**: Audit trails of all HTTP requests received and processed by the Microsoft Graph service for a tenant. 
- **Azure Monitor Integration**: Logs can be collected and configured to downstream destinations using diagnostic settings in Azure Monitor. 
- **Log Destinations**:
  - **Log Analytics**: For analysis.
  - **Azure Storage**: For long-term storage.
  - **Azure Event Hubs**: For streaming to external SIEM tools.

**Prerequisites**
- **Licensing**: Microsoft Entra ID P1 or P2 tenant license. 
- **Administrative Roles**: Security Administrator role is required to configure diagnostic settings. 
- **Azure Subscription**: With configured log destinations and permissions to access data. 

**Data Available in Logs**
- **Key Attributes**:
  - **AadTenantId**: Azure AD tenant ID.
  - **AppId**: Identifier for the application.
  - **ClientAuthMethod**: Client authentication method used.
  - **IPAddress**: Client's IP address.
  - **RequestMethod**: HTTP method of the request.
  - **RequestUri**: URI of the request.
  - **ResponseStatusCode**: HTTP response status code.
  - **TimeGenerated**: Date and time the request was received.

**Accessing and Analyzing Logs**
1. **Enable Diagnostic Settings**:
   - Configure diagnostic settings in Azure Monitor to collect Microsoft Graph activity logs. 
2. **Access Logs via Azure Monitor**:
   - Navigate to the configured log destination (e.g., Log Analytics workspace) to view and analyze logs. 
3. **Analyze Logs**:
   - Use Log Analytics queries to filter and examine specific activities, such as identifying unusual API request patterns or unauthorized access attempts.

**Best Practices**
- **Regular Monitoring**: Continuously monitor activity logs to detect anomalies or potential threats promptly.
- **Automated Alerts**: Set up alerts for suspicious activities, such as repeated failed authentication attempts or access from unfamiliar IP addresses.
- **Data Retention Policies**: Define appropriate retention policies for logs to comply with organizational and regulatory requirements.
- **Integration with SIEM Tools**: Stream logs to Security Information and Event Management (SIEM) tools for advanced threat detection and correlation analysis.
- **Access Control**: Ensure that only authorized personnel have access to activity logs to maintain data integrity and confidentiality.

📌 Source: [Access Microsoft Graph activity logs](https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview)

---
# Respond to incidents in Microsoft Sentinel

## Investigate and remediate incidents in Microsoft Sentinel

**Essential Concepts**
- **Incident**: An aggregation of alerts and related evidence representing a potential security threat. 
- **Alert**: Individual pieces of evidence generated by analytics rules or imported from third-party security products. 
- **Entity**: Objects such as users, hosts, IP addresses, or files involved in alerts and incidents. 
- **Playbook**: A collection of automated remediation actions to respond to threats. 
- **Automation Rule**: A centralized method to manage and automate incident handling processes. 

**Investigation Procedures**
1. **Access Incidents**:
   - Navigate to the "Incidents" page in Microsoft Sentinel to view all incidents. 
2. **Triage Incidents**:
   - Filter incidents by status or severity to prioritize investigation.
   - Assign incidents to appropriate analysts. 
3. **Analyze Incident Details**:
   - Review the "Overview" tab for basic information.
   - Examine the "Entities" tab to identify involved objects.
4. **Investigate Alerts and Evidence**:
   - Assess each alert within the incident to understand the threat's scope.
   - Utilize the "Investigation" graph to visualize relationships between entities. 
5. **Consult Activity Log**:
   - Check the activity log for previous actions taken and comments added.

**Remediation Steps**
1. **Apply Playbooks**:
   - Run relevant playbooks to automate response actions, such as isolating affected systems.
2. **Implement Automation Rules**:
   - Set up automation rules to standardize responses to similar future incidents.
3. **Manual Remediation**:
   - Perform necessary manual actions, like blocking IP addresses or disabling compromised accounts. 
4. **Document Actions**:
   - Record all remediation steps and findings in the incident's activity log for auditing and future reference.

**Best Practices**
- **Standardize Processes**:
   - Use tasks to ensure consistent investigation and remediation procedures across the team.
- **Continuous Improvement**:
   - Regularly review incident responses to identify areas for process enhancement.
- **Leverage Automation**:
   - Utilize automation rules and playbooks to reduce manual intervention and accelerate response times.
- **Collaborate Effectively**:
   - Use integrated tools like Microsoft Teams to coordinate responses among stakeholders.
- **Stay Informed**:
   - Keep abreast of updates and new features in Microsoft Sentinel to enhance security operations.

📌 Source: [Investigate Microsoft Sentinel incidents in depth in the Azure portal](https://learn.microsoft.com/en-us/azure/sentinel/investigate-incidents)

---
## 

📌 Source:

---
## 

📌 Source:

---
## 

📌 Source:

---

If you find this guide helpful and want to support my work, you can buy me a coffee ☕️!

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-Support%20My%20Work-orange)](https://buymeacoffee.com/404future)
