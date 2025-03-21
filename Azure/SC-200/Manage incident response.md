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

**Overview**
- **Automatic Attack Disruption**: A feature in Microsoft Defender XDR that automatically contains active attacks, limiting their impact and giving security teams time to respond.

**Key Concepts**
- **Incident Correlation**: Defender XDR aggregates signals from endpoints, identities, emails, and SaaS apps into high-confidence incidents for better threat assessment.
- **Automated Response Actions**:
  - **Device Containment**: Isolates compromised devices to block inbound and outbound communications.
  - **User Account Suspension**: Disables compromised accounts to prevent further malicious activity.

**Investigation and Remediation Steps**
1. **Verify Backups**: Ensure offline backups are available before remediation.
2. **Add Indicators**: Block known attacker communication channels in firewalls and endpoints.
3. **Reset Compromised Users**: Reset passwords for affected and privileged accounts.
4. **Isolate Control Points**: Disconnect known attacker infrastructure from the internet.
5. **Remove Malware**: Conduct antivirus scans on all suspected devices.
6. **Recover Files**: Use File History or System Protection to restore clean versions.

**Best Practices**
- **Comprehensive Deployment**: Ensure Defender is deployed across all relevant platforms.
- **Automation Levels**: Set device group policies to ‘Full - remediate threats automatically’ for seamless responses.
- **Device Discovery**: Enable 'Standard Discovery' to ensure full monitoring.
- **Audit Policies**: Configure auditing on domain controllers to log critical events.
- **Action Accounts**: Verify Defender for Identity has necessary permissions for remediation.

**Monitoring and Management**
- **Incident Queue**: Use the Microsoft Defender portal to view and manage incidents.
- **Action Center**: Track all remediation and response actions for oversight.
- **Attack Disruption Tags**: Identify incidents tagged with 'Attack Disruption' to prioritize containment.

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
- **Permissions**: Membership in the eDiscovery Manager role group within the Purview portal is required to access and utilize Content Search features.
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
## Create and configure automation rules

**Overview**
- Automation rules in Microsoft Sentinel streamline incident and alert management by automating responses based on defined triggers and conditions.

**Creating an Automation Rule**
1. **Navigate to Automation Page**:
   - In the Azure portal:
     - Go to **Microsoft Sentinel**.
     - Select **Configuration** > **Automation**.
   - In the Defender portal:
     - Go to **Microsoft Sentinel** > **Configuration** > **Automation**.
2. **Initiate Rule Creation**:
   - Click **Create** > **Automation rule**.
3. **Define Rule Settings**:
   - **Name**: Enter a unique name for the rule.
   - **Trigger**: Select when the rule should activate:
     - **When incident is created**
     - **When incident is updated**
     - **When alert is created**
   - **Conditions**: Set criteria for the rule to apply.
   - **Actions**: Specify automated responses, such as:
     - Creating incident tasks.
     - Running playbooks.
     - Assigning incidents to owners.
     - Changing incident severity.
     - Tagging incidents.
     - Closing incidents with specified comments.
4. **Review and Create**:
   - Verify all settings.
   - Click **Create** to establish the automation rule.

**Best Practices**
- **Design Considerations**:
  - Align automation rules with organizational workflows and incident response strategies.
  - Regularly review and update rules to adapt to evolving security requirements.
- **Management**:
  - Monitor the performance and effectiveness of automation rules.
  - Adjust conditions and actions as necessary based on incident trends and feedback.

📌 Source: [Create and use Microsoft Sentinel automation rules to manage response](https://learn.microsoft.com/en-us/azure/sentinel/create-manage-use-automation-rules?tabs=azure-portal%2Conboarded)

---
## Create and configure Microsoft Sentinel playbooks

**Overview**
- Playbooks in Microsoft Sentinel automate responses to incidents, alerts, or specific entities, enhancing security operations efficiency. They are built on Azure Logic Apps, offering customization and integration capabilities.

**Creating a Playbook**
1. **Access Automation**:
   - In the Azure portal or Defender portal, navigate to your Microsoft Sentinel workspace.
   - Select **Automation** under the Configuration section.
2. **Initiate Playbook Creation**:
   - Click **Create** and choose the appropriate playbook type based on your trigger preference:
     - **Playbook with incident trigger**
     - **Playbook with alert trigger**
     - **Playbook with entity trigger**
3. **Design Playbook Workflow**:
   - Utilize Azure Logic Apps designer to define the workflow, incorporating necessary triggers, actions, and conditions.
   - For playbooks requiring access to protected resources within an Azure virtual network, consider creating a Standard logic app workflow to leverage virtual network integration features. 

**Best Practices**
- **Role-Based Access Control (RBAC)**:
  - Assign appropriate roles to users managing playbooks:
    - **Logic App Contributor**:
      - Edit and manage logic apps.
    - **Logic App Operator**:
      - Read, enable, and disable logic apps.
    - **Standard Logic Apps Standard Contributor**:
      - Manage all aspects of a workflow.
    - **Standard Logic Apps Standard Developer**:
      - Create and edit workflows.
    - **Standard Logic Apps Standard Operator**:
      - Enable, resubmit, and disable workflows.
  - For detailed role descriptions, refer to Microsoft Sentinel roles documentation. 
- **Customization and Testing**:
  - Tailor playbooks to align with your organization's security protocols.
  - Thoroughly test playbooks to ensure they function as intended before deployment.
- **Monitoring and Maintenance**:
  - Regularly review playbook performance and update them to adapt to evolving security threats and operational requirements.

📌 Source: [Create and manage Microsoft Sentinel playbooks](https://learn.microsoft.com/en-us/azure/sentinel/automation/create-playbooks?tabs=azure-portal%2Cconsumption)

---
## Run playbooks on on-premises resources

**Overview**
- **Microsoft Sentinel Playbooks**: Automated workflows responding to incidents, alerts, or specific entities. Built using Azure Logic Apps.

**Key Concepts**
- **Azure Logic Apps**: Foundation for creating playbooks, enabling integration with various services, including on-premises systems.
- **Hybrid Runbook Worker**: Allows Azure Automation runbooks to interact with on-premises resources.

**Permissions and Roles**
- **Required Roles**:
  - Owner: Grants access to playbooks in the resource group.
  - Microsoft Sentinel Contributor: Attach playbooks to analytics or automation rules.
  - Microsoft Sentinel Responder: Access incidents to run playbooks manually.
  - Microsoft Sentinel Playbook Operator: Run playbooks manually.
  - Microsoft Sentinel Automation Contributor: Allow automation rules to run playbooks.
  - Logic App Contributor: Required on the resource group containing the playbooks.

**Implementing Playbooks for On-Premises Resources**
1. **Set Up Azure Automation Account**:
   - Create an Azure Automation Account.
   - Deploy a Hybrid Runbook Worker to communicate with on-premises systems.
   - Register the Hybrid Worker with Azure Automation.
2. **Create PowerShell Runbook**:
   - Develop a PowerShell script to perform desired actions on on-premises resources (e.g., disabling a compromised user account).
   - Ensure the script is tested and functions as intended.
3. **Integrate Runbook with Sentinel Playbook**:
   - In Microsoft Sentinel, create a playbook that triggers the Azure Automation runbook.
   - Configure the playbook to respond to specific alerts or incidents.
4. **Assign Necessary Permissions**:
   - Ensure the Microsoft Sentinel service account has the *Microsoft Sentinel Automation Contributor* role on the resource group containing the playbook.
   - Verify that the Hybrid Runbook Worker has appropriate permissions to execute tasks on on-premises resources.

**Best Practices**
- **Security**:
  - Limit permissions to the minimum necessary for both Azure and on-premises environments.
  - Regularly review and update access controls.
- **Testing**:
  - Thoroughly test playbooks in a controlled environment before deploying to production.
  - Monitor the execution of playbooks to ensure they perform as expected.
- **Documentation**:
  - Maintain clear documentation of playbook workflows and associated permissions.
  - Keep records of any changes made to playbooks or related configurations.

📌 Source: [Automate and run Microsoft Sentinel playbooks](https://learn.microsoft.com/en-us/azure/sentinel/automation/run-playbooks?tabs=before-onboarding%2Cincidents%2Cmicrosoft-defender%2Cincident-details-new)

---
# Implement and use Copilot for Security

## Create and use promptbooks

**Overview**
- **Promptbooks**: Sequences of prompts designed to automate specific security tasks in Microsoft Security Copilot. 

**Creating a Promptbook**
1. **Initiate from Existing Session**:
   - Identify a sequence of prompts frequently used together.
   - Access the promptbook builder in Security Copilot.
   - Select prompts from the existing session to include in the new promptbook.
   - Save and name the promptbook for future use. 
2. **Design Principles**:
   - Define clear objectives for the promptbook.
   - Ensure prompts are logically sequenced, with each building upon the previous.
   - Test the promptbook to verify it meets intended goals. 

**Using Prebuilt Promptbooks**
1. **Access Promptbook Library**:
   - Navigate to the Promptbook library in Security Copilot.
   - Browse available promptbooks relevant to your role or task.
2. **Execute a Promptbook**:
   - Select the desired promptbook.
   - Provide necessary inputs (e.g., user principal name, incident ID).
   - Submit and review the generated responses. 

**Best Practices**
- **Effective Prompting**:
   - Craft clear, specific prompts to elicit accurate responses.
   - Use natural language and provide necessary context. 
- **Feedback and Iteration**:
   - Regularly review promptbook performance.
   - Incorporate feedback to refine and improve prompt sequences.

📌 Source: [Using promptbooks in Microsoft Security Copilot](https://learn.microsoft.com/en-us/copilot/security/using-promptbooks)

---
## Manage sources for Copilot for Security, including plugins and files

**Overview**
- **Microsoft Security Copilot**: An AI-driven security analysis tool that can be extended using plugins and customized with uploaded files.

**Managing Plugins**

**Plugin Categories**
- **Microsoft Plugins**: Preinstalled plugins for Microsoft security services.
- **Non-Microsoft Plugins**: Support for third-party services and websites.
- **Custom Plugins**: User-created plugins for specialized tasks.

**Adding a Plugin**
1. **Access Plugin Management**:
   - Click the **Sources** icon in the prompt bar.
2. **Choose Plugin Type**:
   - Select **Security Copilot plugin** or **OpenAI plugin**.
3. **Upload Plugin**:
   - **For Security Copilot plugin**:
     - Upload a file or provide a link to a `.yaml` or `.json` file.
   - **For OpenAI plugin**:
     - Provide a link to the OpenAI plugin.
4. **Set Availability**:
   - Decide if the plugin is for personal use or organization-wide.
5. **Finalize**:
   - Complete any additional setup as prompted.

**Managing Plugin Settings**
- **Toggle Plugins**:
  - Enable or disable plugins via the **Sources** menu.
- **Personalize Settings**:
  - Configure specific settings for plugins like Microsoft Sentinel.

**Permissions**
- **Default**:
  - Only owners can add and manage custom plugins.
- **Extended**:
  - Owners can permit contributors to add/manage plugins.

**Uploading Files**

**Supported File Types**
- DOCX, MD, PDF, and TXT formats.

**File Size Limits**
- **Per File**: Up to 3 MB.
- **Total**: Up to 20 MB across all uploads.

**Upload Process**
1. **Initiate Upload**:
   - Click the **Sources** icon in the prompt bar.
2. **Select Files**:
   - Navigate to **Files** > **Upload file**.
3. **Activate Files**:
   - Toggle the switch beside each file to enable it as a source.

**Storage and Privacy**
- **Storage Location**:
  - Files are stored in the Security Copilot service within your tenant's home geo.
- **Access**:
  - Uploaded files are accessible only to the uploader.

**Deletion**
- **Remove File**:
  - Use the trash icon next to the file in the **Uploads** section.

**Permissions for File Uploads**
- **Default**:
  - Contributors and owners can upload files.
- **Restriction**:
  - Owners can limit file uploads to owners only.

📌 Source: 
- [Manage plugins in Microsoft Security Copilot](https://learn.microsoft.com/en-us/copilot/security/manage-plugins?tabs=securitycopilotplugin)
- [Add a source by uploading a file (Preview)](https://learn.microsoft.com/en-us/copilot/security/upload-file)

---
## Integrate Copilot for Security by implementing connectors

**Overview**
- **Connectors**: APIs that enable developers and users to interact with Microsoft Security Copilot for specialized tasks. 

**Available Connectors**

**Logic Apps Connector**
- **Functionality**: Allows integration of Security Copilot into Azure Logic Apps workflows.
- **Actions**:
  - *Submit a Security Copilot prompt*: Initiates a new Security Copilot investigation based on a natural language prompt.
  - *Submit a Security Copilot promptbook*: Executes a sequence of prompts (promptbook) and returns the output to the workflow.
- **Authentication**: Requires Microsoft Entra ID (formerly Azure Active Directory) user identity with appropriate permissions.
- **Prerequisites**:
  - Tenant admin must set up access to Microsoft Security Copilot.
  - Authenticated user should have access to relevant security data sources.
- **Implementation Steps**:
  1. Create and configure a new Logic Apps workflow in the Azure portal.
  2. Set up the initial trigger step.
  3. Search for and add the Security Copilot action (either "Submit a Security Copilot prompt" or "Submit a Security Copilot promptbook").
  4. Fill in the required parameters for the selected action.
  5. Save and run the workflow to integrate with Security Copilot.

📌 Source: [Connectors overview in Microsoft Security Copilot (Preview)](https://learn.microsoft.com/en-us/copilot/security/connectors-overview)

---
## Manage permissions and roles in Copilot for Security

**Overview**
- **Security Copilot Roles**: Define access to platform features; managed within Security Copilot.
- **Microsoft Entra Roles**: Control access to security data across Microsoft services; managed via Microsoft Entra ID.

**Security Copilot Roles**
- **Copilot Owner**:
  - Full access to all platform features, including configuration and permission assignments.
- **Copilot Contributor**:
  - Access to use platform features without administrative privileges.

**Microsoft Entra Roles**
- **Security Administrator**:
  - Manages security-related features across Microsoft services.
- **Global Administrator**:
  - Full access to all administrative features in Microsoft Entra ID.

*Note: Users with Security Administrator or Global Administrator roles automatically inherit Copilot Owner access.*

**Best Practices**
- **Assign Minimal Necessary Permissions**:
  - Use roles with the least privileges required for tasks to enhance security.
- **Utilize Recommended Security Roles**:
  - Assign the "Recommended Microsoft Security roles" group to streamline access management.

📌 Source: [Understand authentication in Microsoft Security Copilot](https://learn.microsoft.com/en-us/copilot/security/authentication)

---
## Monitor Copilot for Security capacity and cost

**Overview**
- Microsoft Security Copilot operates on a provisioned capacity model, utilizing Security Compute Units (SCUs) to handle workloads. Effective management of SCUs is crucial for monitoring capacity and controlling costs.

**Key Concepts**
- **Security Compute Units (SCUs)**
   - **Definition**: Units representing the compute capacity allocated for Security Copilot operations.
   - **Provisioning**: SCUs can be adjusted (increased or decreased) at any time to align with organizational needs.
- **Billing Structure**
   - **Hourly Billing**: SCUs are billed in hourly blocks. Any usage within an hour is charged as a full SCU, regardless of the exact duration.
   - **Example**: Provisioning an SCU at 9:05 AM and deprovisioning at 9:35 AM incurs a charge for the entire hour.

**Monitoring Usage**
- **Usage Monitoring Dashboard**
   - **Access**:
     1. Sign in to Security Copilot.
     2. Navigate to **Home > Owner settings**.
     3. Select **Usage monitoring**.
   - **Features**:
  - Displays SCU consumption over time.
  - Provides data on session initiators, plugins used, and session categories.
  - Allows filtering by various dimensions for detailed analysis.

**Data Dimensions in Dashboard**
- **Date**: When the session was initiated.
- **Units Used**: Number of SCUs consumed.
- **Initiated By**: User who started the session.
- **Session ID**: Unique identifier for each session.
- **Category**: Type of session (e.g., Prompt, Promptbook).
- **Type**: Method of initiation (Manual or Automated).
- **Copilot Experience**: Interface used (Standalone, Embedded, Azure Logic Apps).
- **Plugin Used**: Specific plugin utilized during the session.

**Best Practices**
- **Optimize SCU Provisioning**
   - **Timing**: Make provisioning changes at the start of an hour to maximize usage efficiency.
   - **Monitoring**: Regularly review the usage dashboard to identify trends and adjust SCU allocations accordingly.
- **Cost Management**
   - **In-Product Dashboard**: Utilize the built-in dashboard to track and manage costs effectively.
   - **Flexible Provisioning**: Adjust SCU levels based on organizational demands to optimize expenditure.

📌 Source: [Manage usage of security compute units in Security Copilot](https://learn.microsoft.com/en-us/copilot/security/manage-usage)

---
## Identify threats and risks by using Copilot for Security

**Overview**
- Microsoft Security Copilot is an AI-driven platform designed to enhance security operations by integrating advanced threat intelligence and providing actionable insights.

**Key Capabilities**
- **Incident Investigation**: Provides contextual information to quickly triage complex security alerts into actionable summaries, aiding in faster remediation. 
- **Threat Intelligence Integration**: Enriches alerts with relevant threat intelligence, connecting entities to known threat actors and informing severity assessments. 
- **KQL Query Assistance**: Assists in building KQL queries or analyzing suspicious scripts, eliminating the need for manual scripting and enabling team members to execute technical tasks efficiently. 

**Best Practices for Threat Identification**
1. **Leverage Enriched Threat Intelligence**:
   - Utilize Security Copilot to enrich incident data with threat intelligence, aiding in the identification of known threat actors and assessing incident severity. 
2. **Utilize AI-Assisted Guidance**:
   - Employ AI-driven insights to investigate access issues, identify and summarize data and user risks, and contextualize incidents swiftly.
3. **Integrate with Microsoft Entra**:
   - Use Security Copilot's integration with Microsoft Entra to investigate identity risks and troubleshoot identity tasks efficiently. 

📌 Source: [Use case: Triage incidents based on enrichment from threat intelligence](https://learn.microsoft.com/en-us/copilot/security/triage-alert-with-enriched-threat-intel)

---
## Investigate incidents by using Copilot for Security

**Overview**
- Microsoft Security Copilot leverages AI to assist security operations teams in efficiently investigating and responding to security incidents. 

**Key Steps in Incident Investigation**
1. **Access Incident Details**:
   - Navigate to the Microsoft Defender XDR incident queue to view incidents, which may correlate multiple alerts across various Microsoft security solutions. 
2. **Review Incident Summary**:
   - Utilize Security Copilot's automatically generated summaries to understand the incident's scope and attack phases. 
3. **Analyze Specific Alerts**:
   - Investigate individual alerts, such as suspected DCSync attacks or suspicious service creations, to determine malicious activity. 
4. **Consult Security Copilot for Clarifications**:
   - Use natural language prompts to gain insights into specific attack techniques or anomalies. 
5. **Implement Guided Responses**:
   - Follow the remediation steps provided by Security Copilot to contain and mitigate threats effectively. 

**Best Practices**
- **Leverage AI Capabilities**:
  - Use Security Copilot's AI and machine learning features to contextualize incidents and generate appropriate response actions. 
- **Summarize Incidents Efficiently**:
  - Utilize Security Copilot to create concise incident summaries, aiding in swift decision-making. 
- **Generate Incident Reports**:
  - Employ Security Copilot to assist in drafting detailed incident reports, ensuring comprehensive documentation.

📌 Source: [Use case: Incident response and remediation](https://learn.microsoft.com/en-us/copilot/security/use-case-incident-response-remediation)

---

If you find this guide helpful and want to support my work, you can buy me a coffee ☕️!

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-Support%20My%20Work-orange)](https://buymeacoffee.com/404future)
