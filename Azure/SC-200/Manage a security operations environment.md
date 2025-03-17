# Configure settings in Microsoft Defender XDR

## Configure alert and vulnerability notification rules

- **Access the Microsoft Defender Portal:**
  - Sign in with an account assigned the Security Administrator or Global Administrator role. 

- **Navigate to Email Notifications Settings:**
  - Go to `Settings` > `Endpoints` > `General` > `Email notifications`. 

- **Create a New Notification Rule:**
  - Click `Add item`.
  - Provide a `Rule name` and, optionally, a description.
  - Optionally, include:
    - Organization name in the email.
    - Tenant-specific portal link for direct access.
    - Device information in the email body.
  - Define the scope:
    - For alerts:
      - Select whether to notify for alerts on all devices (Global Administrator only) or specific device groups.
      - Choose the alert severity levels that trigger notifications.
    - For vulnerabilities:
      - Choose vulnerability events to trigger notifications:
        - New vulnerability found (with severity threshold).
        - Exploit verified.
        - New public exploit.
        - Exploit added to an exploit kit.

- **Add Notification Recipients:**
  - Enter the recipient's email address and click `Add recipient`. Repeat for multiple recipients.
  - Optionally, send a test email to verify delivery.

- **Finalize and Save the Rule:**
  - Review all settings.
  - Click `Save notification rule` to activate.

- **Edit or Delete Notification Rules:**
  - To edit:
    - Select the desired rule.
    - Modify settings as needed.
    - Click `Save notification rule`.
  - To delete:
    - Select the desired rule.
    - Click `Delete`.

**Best Practices:**

- **Use Least Privileged Roles:**
  - Assign roles with the minimum permissions necessary. Reserve Global Administrator roles for essential scenarios to enhance security. 

- **Verify Email Deliverability:**
  - Ensure notifications aren't filtered as junk or blocked by email security products. 

- **Regularly Review and Update Rules:**
  - Periodically assess notification rules to ensure they align with current security requirements and organizational changes.

📌 Source: 
- [Configure alert notifications](https://learn.microsoft.com/en-us/defender-xdr/configure-email-notifications)
- [Configure vulnerability email notifications in Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/configure-vulnerability-email-notifications)

--- 
## Configure Microsoft Defender for Endpoint advanced features

- **Access Advanced Features:**
  - Sign in to the Microsoft Defender portal.
  - Navigate to `Settings` > `Endpoints` > `Advanced features`. 

- **Enable or Disable Features:**
  - Toggle desired features On or Off.
  - Click `Save preferences` to apply changes. 

**Key Advanced Features:**

- **Restrict Correlation to Within Scoped Device Groups:**
  - Limits incident correlations to specific device groups.
  - Recommended to keep Off unless necessary. 

- **Enable EDR in Block Mode:**
  - Allows Endpoint Detection and Response to block malicious artifacts, even if Microsoft Defender Antivirus is in passive mode. 

- **Automatically Resolve Alerts:**
  - Auto-resolves alerts where no threats are found or threats are remediated.
  - Influences device risk level calculations. 

- **Allow or Block File:**
  - Requires Microsoft Defender Antivirus as the active antimalware solution with cloud-based protection enabled.
  - Allows blocking of potentially malicious files, preventing execution on devices. 

- **Hide Potential Duplicate Device Records:**
  - Identifies and hides duplicate device records based on hostname and last seen time.
  - Ensures accurate device information in the portal.

**Best Practices:**

- **Regularly Review Feature Settings:**
  - Periodically assess and adjust advanced features to align with organizational security requirements.

- **Understand Feature Dependencies:**
  - Some features, like 'Allow or Block File', require specific configurations (e.g., active Microsoft Defender Antivirus).

- **Monitor Impact on Security Operations:**
  - Features such as 'Automatically Resolve Alerts' can influence device risk levels and incident management workflows.

For detailed information on each feature and its configuration, refer to Microsoft's official documentation. 

📌  Source: [Configure advanced features in Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/advanced-features)

---  
## Configure endpoint rules settings

**1. Manage Alert Suppression Rules**

- **Purpose:**
  - Suppress alerts from known benign tools or processes to reduce noise.

- **Steps to Create a Suppression Rule:**
  1. **Sign in** to the Microsoft Defender portal with appropriate administrative privileges.
  2. **Navigate** to `Settings` > `Endpoints` > `Rules` > `Alert suppression`.
  3. **Select** an existing alert to base the suppression rule on.
  4. **Define** the conditions and scope for the rule.
  5. **Save** the rule to activate suppression.

- **Managing Suppression Rules:**
  - **View** all suppression rules under `Alert suppression`.
  - **Edit**, **disable**, or **delete** rules as necessary.

- **Best Practices:**
  - Regularly **review** suppression rules to ensure they align with current security policies.
  - Use **least privileged roles** when assigning administrative permissions.

**2. Configure Web Content Filtering**

- **Purpose:**
  - Monitor and control access to websites based on content categories to enhance security and compliance.

- **Prerequisites:**
  - Ensure devices are **onboarded** to Microsoft Defender for Endpoint.
  - Verify that **network protection** is enabled.

- **Steps to Set Up Web Content Filtering:**
  1. **Access** the Microsoft Defender portal.
  2. **Navigate** to `Settings` > `Endpoints` > `Rules` > `Web content filtering`.
  3. **Click** `+ Add policy`.
  4. **Name** the policy and provide a description.
  5. **Select** categories to block (avoid selecting "Uncategorized").
  6. **Assign** the policy to specific device groups.
  7. **Save** the policy to enforce it.

- **Monitoring and Reporting:**
  - **Review** web activity reports in the portal to assess policy effectiveness.

- **Best Practices:**
  - **Tailor** content categories to align with organizational policies.
  - **Regularly update** policies to adapt to emerging threats and changing requirements.

**3. Manage Indicators (Indicators of Compromise - IoCs)**

- **Purpose:**
  - Define detection, prevention, and exclusion rules for known malicious entities such as file hashes, IP addresses, and URLs.

- **Steps to Create an Indicator:**
  1. **Sign in** to the Microsoft Defender portal.
  2. **Navigate** to `Settings` > `Endpoints` > `Indicators`.
  3. **Select** the type of indicator to create (e.g., File hash, IP address, URL/domain).
  4. **Specify** the details of the indicator, including the action to take (e.g., Allow, Block) and the scope (device groups).
  5. **Set** the expiration date for the indicator, if applicable.
  6. **Save** the indicator to apply the rule.

- **Managing Indicators:**
  - **View** all configured indicators under the `Indicators` section.
  - **Edit**, **disable**, or **delete** indicators as necessary.

- **Best Practices:**
  - **Create** indicators for known malicious entities to enhance threat detection and prevention.
  - **Regularly review** and **update** indicators to maintain an effective security posture.
  - **Avoid** creating indicators for entities already covered by Microsoft's threat intelligence to prevent redundancy.

📌  Source:
- [Manage Microsoft Defender for Endpoint suppression rules](https://learn.microsoft.com/en-us/defender-endpoint/manage-suppression-rules)    
- [Set up and configure Microsoft Defender for Endpoint Plan 1](https://learn.microsoft.com/en-us/defender-endpoint/mde-p1-setup-configuration#configure-web-content-filtering)
- [Overview of indicators in Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/indicators-overview) 

---
## Manage automated investigation and response capabilities in Microsoft Defender XDR

**1. Overview of AIR in Microsoft Defender XDR**

- **Purpose:**
  - Automate threat investigations and responses to reduce alert volume and enhance security operations efficiency.

- **Functionality:**
  - Mimics actions of security analysts to investigate and remediate threats across devices, emails, and identities.

**2. Prerequisites for Configuring AIR**

- **Subscriptions:**
  - Microsoft 365 E5, A5, E3 with E5 Security add-on, or equivalent. 

- **Network Requirements:**
  - Enable Microsoft Defender for Identity and configure Microsoft Defender for Cloud Apps. 

- **Device Requirements:**
  - Windows 10 version 1709 or later, with Microsoft Defender for Endpoint and Microsoft Defender Antivirus configured. 

- **Permissions:**
  - Assign Global Administrator or Security Administrator roles in Microsoft Entra ID or the Microsoft 365 admin center. 

**3. Configuring Automation Levels for Device Groups**

- **Steps:**
  1. **Sign in** to the Microsoft Defender portal.
  2. **Navigate** to `Settings` > `Endpoints` > `Device groups` under `Permissions`.
  3. **Review** the `Remediation level` for each device group.
  4. **Set** the automation level to `Full - remediate threats automatically` for optimal automated response.

- **Recommendation:**
  - Use the `Full` automation level to allow automatic remediation of threats. 

**4. Reviewing Security and Alert Policies in Office 365**

- **Purpose:**
  - Ensure built-in alert policies are active to detect risks like malware activity and potential threats.

- **Steps:**
  1. **Access** the Microsoft 365 Defender portal.
  2. **Navigate** to `Settings` > `Email & collaboration` > `Policies & rules` > `Threat policies`.
  3. **Review** and **enable** relevant alert policies to support automated investigations.

**5. Managing Remediation Actions**

- **Action Center:**
  - Monitor and manage remediation actions identified during automated investigations.

- **Steps:**
  1. **Go to** the `Action center` in the Microsoft Defender portal.
  2. **Review** pending and completed actions.
  3. **Approve** or **reject** pending actions as necessary.

- **Recommendation:**
  - Regularly review the Action center to stay informed about remediation activities. 

**6. Best Practices**

- **Regular Reviews:**
  - Periodically assess automation levels and alert policies to ensure they align with organizational security requirements.

- **Role Assignment:**
  - Assign appropriate roles to personnel to balance security and operational efficiency.

- **Stay Updated:**
  - Keep abreast of updates to Microsoft Defender XDR features to leverage new AIR capabilities.

📌  Source: [Configure automated investigation and response capabilities in Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/m365d-configure-auto-investigation-response)

---
## Configure automatic attack disruption in Microsoft Defender XDR

**1. Overview**

- **Purpose:** Contain active attacks, limit impact, and provide security teams with more time to remediate threats. 

- **Scope:** Utilizes XDR signals across Defender products to act at the incident level, differing from single-indicator protection methods.

**2. Prerequisites**

- **Subscriptions:** Microsoft 365 E5/A5, Microsoft 365 E3 with E5 Security add-on, or equivalent. 

- **Deployment:**
  - Deploy Defender products (Endpoint, Identity, Cloud Apps, Office 365) for comprehensive coverage.
  - Set Microsoft Defender for Endpoint's device discovery to 'Standard Discovery'.

- **Permissions:** Global Administrator or Security Administrator roles required.

- **Device Requirements:** Microsoft Defender Antivirus in Active, Passive, or EDR Block Mode; minimum Sense Agent version v10.8470.

**3. Configuration Steps**

1. **Sign In:**
   - Access the Microsoft Defender portal.

2. **Set Automation Level:**
   - Navigate to `Settings` > `Endpoints` > `Device groups`.
   - Review the `Remediation level`; set to `Full - remediate threats automatically` for comprehensive automation. 

3. **Configure Device Discovery:**
   - Ensure device discovery is set to 'Standard Discovery' to enable automatic containment actions. 

**4. Managing Exclusions**

- **Exclude User Accounts from Automated Responses:**
  1. In the Defender portal, go to `Settings` > `Microsoft Defender XDR` > `Identities`.
  2. Under `Automated response exclusions`, select `Add user exclusion`.
  3. Choose user accounts to exclude and save changes. 

- **Exclude IP Addresses (Preview):**
  - Exclude specific IPs from automated containment actions by configuring exclusions in the Defender portal. 

**5. Reviewing and Managing Actions**

- **Incident Review:**
  - In the Defender portal, navigate to `Incidents`.
  - Select incidents tagged with 'Attack Disruption' to view the incident graph and assess impact.

- **Action Center:**
  - Go to `Actions & submissions` > `Action center` to view and manage remediation actions.

**6. Best Practices**

- **Regularly Review Settings:**
  - Ensure automation levels and exclusions align with organizational security policies.

- **Stay Informed:**
  - Keep abreast of new features and updates in Microsoft Defender XDR to enhance security measures.

📌  Source: [Configure automatic attack disruption in Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/configure-attack-disruption)

---
# Manage assets and environments

## Configure and manage device groups, permissions, and automation levels in Microsoft Defender for Endpoint

### Configure & Manage Device Groups
- Purpose: 
	- Group devices for role-based access control (RBAC), auto-remediation, and filtered investigations.
- Key Actions:
	- Create Device Group:
		- Go to Settings > Endpoints > Permissions > Device Groups.
		- Click Add device group, name it, and set automation level.
		- Define matching rules (device name, domain, OS, tags).
		- Assign Microsoft Entra user groups for access.
	- Manage Device Groups:
		- Rank priority (1 = highest).
		- Unmatched devices go to Ungrouped Devices (default).
		- Edit/Delete groups (note: deleting may affect notification rules).
	- Best Practices:
		- Use tagging for easier management.
		- Assign groups granularly to limit access.

📌 Source: [Create and manage device groups in Microsoft Defender for Endpoint - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/machine-groups)

### Role-Based Access Control (RBAC)
- Why Use RBAC? 
	- Limits user access to Defender data and actions.
- Create RBAC Roles:
	- Go to Settings > Endpoints > Roles.
	- Click Add Role, define permissions (Security Ops, Vulnerability Mgmt, Live Response).
	- Assign Microsoft Entra group to the role.
- Permissions Breakdown:
	- Security Ops: 
		- View data, respond to threats.
	- Defender Vulnerability Management: 
		- Handle remediation, exceptions.
	- Live Response:
		- Basic: Read-only commands, file download.
		- Advanced: Upload & execute scripts.
- Editing/Deleting Roles:
	- Edit via Settings > Endpoints > Roles.
	- Delete roles via the dropdown menu.
- Best Practice:
	- Use least privilege (avoid Global Administrator unless necessary).

📌 Source: [Create and manage roles for role-based access control - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/user-roles)
  
### Automation Levels in Defender for Endpoint
- Purpose: 
	- Controls automated threat remediation in AIR (Automated Investigation & Remediation).
- Levels of Automation:
	- Full Automation (Recommended):
		- Automatically remediates malicious artifacts.
		- Best for efficiency & security.
	- Semi-Automation:
		- Approval needed for remediation in certain locations.
		- Variants:
			- All folders: 
				- Requires approval for all files.
			- Core folders: 
				- Only system-critical locations need approval.
			- Non-temp folders: 
				- Excludes temporary locations.
	- No Automation:
		- No automated remediation or investigation (not recommended).
- Key Notes:
	- Full automation removes 40% more threats than semi-automation.
	- Defender for Business uses Full Automation by default.
	- View all remediation actions in Action Center.
	- Changes take effect instantly after updating settings.

📌 Source: [Automation levels in automated investigation and remediation - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/automation-levels)  

---
## Identify unmanaged devices in Microsoft Defender for Endpoint

### Overview
- Device discovery in Microsoft Defender for Endpoint (MDE) identifies unmanaged devices in the network.
- Helps secure endpoints, network devices, and IoT assets by onboarding them to Defender for Endpoint.

### Discovery Modes
- Basic Discovery (Passive)
	- Uses SenseNDR.exe to collect network traffic data.
	- Limited visibility—only detects devices seen in existing network traffic.
- Standard Discovery (Active) – Recommended
	- Uses multicast queries and active probing to find more devices.
	- Provides enriched device information.
	- Default mode since July 19, 2021.

### Device Inventory & Onboarding Status
- Onboarded: 
	- Device is managed by Defender for Endpoint.
- Can be onboarded: 
	- Detected and supported but not yet onboarded.
- Unsupported: 
	- Detected but not supported by Defender for Endpoint.
- Insufficient info: 
	- Requires standard discovery for more details.

### Network Device Discovery
- Uses authenticated remote scans (agentless) via Defender for Endpoint sensors.
- Discovers routers, switches, firewalls, WLAN controllers, VPN gateways.

### Advanced Hunting for Unmanaged Devices
- Find discovered devices

```
DeviceInfo
| summarize arg_max(Timestamp, *) by DeviceId  
| where isempty(MergedToDeviceId)  
| where OnboardingStatus != "Onboarded"
```
  
- Identify which onboarded device detected them

```
DeviceInfo
| where OnboardingStatus != "Onboarded"
| summarize arg_max(Timestamp, *) by DeviceId  
| where isempty(MergedToDeviceId)  
| limit 100  
| invoke SeenBy()  
| project DeviceId, DeviceName, DeviceType, SeenBy
```

- Analyze network connections from non-onboarded devices

```
DeviceNetworkEvents
| where ActionType == "ConnectionAcknowledged" or ActionType == "ConnectionAttempt"
| take 10
```

### Defender for IoT Integration
- Extends discovery to OT and Enterprise IoT devices (e.g., VoIP, printers, smart TVs).
- Works via Microsoft Defender for IoT in Defender portal.

### Security Recommendations & Vulnerability Management
- Found under Defender Vulnerability Management > Security Recommendations.
- Helps prioritize onboarding and securing high-risk unmanaged devices.
  
📌 Source: [Device discovery overview - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/device-discovery)

---  
## Discover unprotected resources by using Defender for Cloud

### Key Concepts:
- Unprotected Resources: 
	- Resources without appropriate security settings or protection.
- Defender for Cloud Recommendations: 
	- Suggestions to secure unprotected resources.
- Security Alerts: 
	- Notifications about unprotected or misconfigured resources.  

### Steps to Discover Unprotected Resources:
1. Enable Defender for Cloud: Activate in the Azure Portal for resource monitoring.
2. Review Security Alerts: Identify flagged resources with missing protections.
3. Review Security Recommendations: Implement actionable steps to secure resources.

### Best Practices:
- Regularly monitor Security Alerts for new vulnerabilities.
- Apply recommended policies to secure resources.
- Use tags for better resource classification.

### Important Tools:
- Azure Arc: 
	- Extends coverage to non-Azure resources.
- RBAC: 
	- Ensures proper permissions for resource management.

### Critical Functions:
- CSPM (Cloud Security Posture Management): 
	- Tracks multi-cloud security.
- Resource Inventory: 
	- Discovers and tracks unprotected resources.

### Actionable Steps:
- Enable Defender for Cloud to start discovery.
- Use Azure Arc for non-Azure resources.
- Review Secure Score to assess environment security.

📌 Source:
- [What is Azure Resource Manager? - Azure Resource Manager | Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/overview)
- [Azure Arc overview - Azure Arc | Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-arc/overview)
- [Microsoft Defender for Cloud Overview - Microsoft Defender for Cloud | Microsoft Learn](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction)

---
## Identify and remediate devices at risk by using Microsoft Defender Vulnerability Management

### High-Level Overview:
- Purpose: 
	- Identify, assess, and remediate vulnerabilities across critical assets to reduce cyber risk.
- Key Features: 
	- Asset visibility, intelligent risk prioritization, built-in remediation tools, cross-platform support (Windows, macOS, Linux, Android, iOS, network devices).
- Core Goals: 
	- Prioritize vulnerabilities, provide mitigation strategies, and track remediation efforts.

### Key Components:
- Asset Discovery & Monitoring:
	- Continuous scanning of devices, even offline.
	- Centralized view of software, certificates, hardware, firmware, and browser extensions.
	- Identify unmanaged devices through authenticated scans (e.g., for Windows).
- Vulnerability Assessment Tools:
	- Security Baselines: 
		- Measure compliance against benchmarks (CIS, STIG).
	- Software Inventory: 
		- Track software changes (installations, uninstalls, patches).
	- Network Shares: 
		- Assess internal network share configurations.
	- Event Timelines: 
		- Use timelines for vulnerability tracking and prioritization.
- Risk-based Prioritization:
	- Leverage Microsoft threat intelligence and breach likelihood.
	- Focus on high-risk, actively exploited vulnerabilities.
	- Pinpoint vulnerabilities tied to critical assets (e.g., business-critical applications).

### Remediation & Tracking:
- Built-in Workflows:
	- Create remediation tasks in Microsoft Intune.
	- Block vulnerable applications on specific devices.
	- Track remediation progress in real time.
- Remediation Strategies:
	- Actionable security recommendations (e.g., patches, configuration changes).
	- Alternative mitigations for vulnerabilities when direct patching isn't possible.

### Navigation & Reporting:
- Dashboard: 
	- View risk scores, recommendations, top vulnerabilities, and remediation activities.
- Recommendations: 
	- Lists of security issues, with links to remediation options.
- Inventories & Weaknesses: 
	- Access asset lists and common vulnerabilities (CVE tracking).
- APIs: 
	- Automate workflows with Defender for Endpoint APIs for vulnerabilities, recommendations, and machine data.

### Best Practices:
- Prioritize vulnerabilities based on exposure and criticality.
- Regularly assess devices, even when offline, to maintain up-to-date visibility.
- Use real-time monitoring to track and ensure successful remediation.
  
📌 Source: [Microsoft Defender Vulnerability Management - Microsoft Defender Vulnerability Management | Microsoft Learn](https://learn.microsoft.com/en-us/defender-vulnerability-management/defender-vulnerability-management)

---
## Mitigate risk by using Exposure Management in Microsoft Defender XDR

### High-Level Overview:
- Purpose: 
	- Provides a unified view of organizational security posture and attack surface to proactively manage and mitigate exposure risks.
- Core Functions: 
	- Asset discovery, attack surface management, exposure insights, risk mitigation, and attack path simulation.  

### Key Features:
- Unified View: 
	- Continuously discovers assets and workloads, creating an up-to-date inventory and attack surface.
- Attack Surface Management:
	- Visualize and analyze attack surfaces across on-premises, hybrid, and multicloud environments.
	- Use the enterprise exposure graph to query and assess risk.
	- Attack surface map for visualizing security posture.
- Critical Asset Management:
	- Mark assets as critical for focused security efforts.
	- Prioritize and safeguard critical assets for business continuity.
- Exposure Insights:
	- Aggregate security posture data for actionable insights.
	- Includes security events, recommendations, and metrics.
	- Insights help prioritize security efforts and investments.

### Risk Mitigation:
- Attack Path Simulation:
	- Generate attack paths based on asset and workload data.
	- Simulate attack scenarios and identify exploitable weaknesses.
	- Focus on choke points that may amplify threats.
- Actionable Recommendations:
	- Use insights and recommendations to mitigate attack paths.
	- Focus on actionable steps to reduce exposure risks.  

### Data Integration:
- Data Connectors:
	- Integrate data from multiple sources into a unified view.
	- Gain deeper security insights by consolidating data from various environments.

### Best Practices:
- Continuously monitor and update asset inventory to keep exposure data current.
- Leverage the enterprise exposure graph for comprehensive risk analysis.
- Prioritize remediation based on attack paths and critical asset visibility.  

📌 Source: [What is Microsoft Security Exposure Management? - Microsoft Security Exposure Management | Microsoft Learn](https://learn.microsoft.com/en-us/security-exposure-management/microsoft-security-exposure-management)

---
# Design and configure a Microsoft Sentinel workspace

## Plan a Microsoft Sentinel workspace

### Plan & Prepare
- Prerequisites: Ensure Azure tenant readiness.
- Workspace Architecture:
	- Choose single vs. multiple tenants based on compliance, data control, and access.
	- Review workspace design guides and multiple workspace setups.
- Data Connectors:
	- Identify key data sources & estimate ingestion size.
	- Prioritize based on security needs & SIEM evaluation.
- Roles & Permissions:
	- Use Azure RBAC to assign fine-grained access.
	- Apply roles at workspace, resource group, or subscription level.
- Cost Planning:
	- Budget for Log Analytics ingestion, playbooks, automation.

### Deployment
- Enable Microsoft Sentinel: Activate health & audit, content solutions.
- Configure Security Content:
	- Data connectors, analytics rules, automation rules, playbooks, workbooks, watchlists.
- Multi-Workspace Setup: Extend Sentinel across workspaces/tenants if needed.
- Enable UEBA: Use User & Entity Behavior Analytics for anomaly detection.
- Data Retention: Configure short-term & long-term storage.

### Fine-Tuning & Review
- Incident & Process Review: Validate incident accuracy, SOC workflow.
- Analytics Rules: Tune rules, mitigate false positives.
- Automation & Playbooks: Ensure correct response to alerts/incidents.
- Watchlists: Keep updated with new users, use cases.
- Commitment Tiers: Adjust to match data ingestion.
- Cost Tracking: Use Sentinel Cost & Usage Reports.
- Data Collection Rules (DCRs): Optimize ingestion & transformation.
- MITRE ATT&CK Mapping: Validate coverage using Sentinel’s MITRE view.
- Threat Hunting: Establish proactive detection processes.

📌 Source: [Deployment guide for Microsoft Sentinel | Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/deploy-overview)

---
## Configure Microsoft Sentinel roles

### Role-Based Access Control (RBAC) in Microsoft Sentinel  
- Microsoft Sentinel uses Azure RBAC to manage permissions.  
- Assign roles at resource group level for full Sentinel resource access or at workspace level (requires additional assignments).  

### Built-in Microsoft Sentinel Roles  
| Role                          | Key Permissions                                      |
|--------------------------------|------------------------------------------------------|
| Sentinel Reader            | View data, incidents, workbooks.                    |
| Sentinel Responder         | Manage incidents (assign, dismiss, etc.).           |
| Sentinel Contributor       | Install/update content, create/edit workbooks, analytics rules. |
| Sentinel Playbook Operator | Run playbooks manually.                             |
| Sentinel Automation Contributor | Allows Sentinel to run playbooks in automation rules. |

### Other Related Roles  
| Role                  | Purpose                                      |
|-----------------------|----------------------------------------------|
| Logic Apps Contributor  | Create, edit, and run playbooks.         |
| Workbook Contributor    | Create and delete workbooks.             |
| Azure Contributor       | Grants broad permissions across Azure, including Sentinel. |

### Role Assignment Best Practices  
- Assign roles at the resource group level to cover all Sentinel-related resources.  
- Use custom roles when built-in roles don’t meet specific needs.  
- To grant playbook execution permissions, Sentinel needs the Automation Contributor role at the playbook’s resource group level.  
- Guest users need Directory Reader + Sentinel Responder to assign incidents.  

### Resource-Specific RBAC (Granular Access)  
- Table-Level RBAC:
	- Restrict access to specific data types.  
- Resource-Context RBAC:
	- Assign permissions based on the data users need, without full Sentinel access.  

📌 Source: [Roles and permissions in Microsoft Sentinel | Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/roles)

---
## Specify Azure RBAC roles for Microsoft Sentinel configuration

### Custom Roles & Advanced RBAC  
- Custom Roles:
	- Create Azure custom roles for Sentinel & Log Analytics permissions.  
- Log Analytics RBAC:
	- Use table-level RBAC and resource-context RBAC to restrict access to specific data without full Sentinel access.  

### Role Assignment Best Practices  
| User Type             | Role | Resource Group | Permissions |
|----------------------|------------------------------|-----------------------------|-------------------------------------------|
| Security Analysts | Sentinel Responder | Sentinel RG | View & manage incidents. |
|                      | Playbook Operator | Sentinel RG or Playbook RG | Attach & run playbooks. |
| Security Engineers | Sentinel Contributor | Sentinel RG | Manage incidents, create/edit workbooks & analytics rules. |
|                      | Logic Apps Contributor | Sentinel RG or Playbook RG | Modify & run playbooks. |
| Service Principal | Sentinel Contributor | Sentinel RG | Automate Sentinel management tasks. |

### Resource-Based Access Control  
- Use resource-context RBAC for users needing access to specific data (e.g., Windows event logs).  
- Instead of granting full Sentinel access, restrict access to only necessary resources.

📌 Source: [Roles and permissions in Microsoft Sentinel | Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/roles#custom-roles-and-advanced-azure-rbac)

---
## Design and configure Microsoft Sentinel data storage, including log types and log retention 

### Log Retention Overview  
- Interactive Retention (default: 30 days, extendable to 730 days for Analytics tables).  
- Long-term Retention (low-cost storage, up to 12 years, searchable via search jobs).  
- Default Retention:  
	- Most tables → 30 days interactive retention.  
	- Log tables (e.g., Usage, AzureActivity) → 90 days free retention.  

### Managing Data Retention  
- Workspace-Level Retention (affects all Analytics tables unless overridden):  
	- Modify via Portal → Usage & estimated costs → Data Retention → Adjust slider.  
	- API: Set retention & enable `immediatePurgeDataOn30Days` for strict 30-day compliance.  

- Table-Level Retention (custom per-table settings):  
	- Portal: Log Analytics workspaces → Tables → Manage table.  
	- Interactive: Set 4 - 730 days (Analytics tables).  
	- Total: Up to 12 years (CLI/PowerShell currently supports only 7 years).  

### Retention Modifications & Impact  
- Shortening retention:
	- 30-day grace period before deletion.  
- Increasing retention:
	- Applies immediately to existing & new data.  
- Long-term retention activation:
	- Interactive data transitions automatically.  

### Log Deletion & Special Table Handling  
- Azure Tables:
	- Cannot be deleted; stop data ingestion instead.  
- Custom Log Tables (`_CL`):
	- Soft-deleted until retention period expires.  
- Search Results Tables (`_SRCH`):
	- Deleted immediately when removed.  
- Restored Tables (`_RST`):
	- Cache removed, source data remains.  

### Permissions for Managing Retention  
| Action | Required Permission | Built-in Role |  
|-----------|----------------------|------------------|  
| Configure default retention | `Microsoft.OperationalInsights/workspaces/write` | Log Analytics Contributor |  
| Get table retention settings | `Microsoft.OperationalInsights/workspaces/tables/read` | Log Analytics Reader |  

### Pricing Considerations  
- Retention costs depend on data volume (GB) × retention period (days).  
- Log data with `_IsBillable == false` is not charged (e.g., some system logs).  

📌 Source: [Roles and permissions in Microsoft Sentinel | Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-retention-configure?toc=%2Fazure%2Fsentinel%2FTOC.json&bc=%2Fazure%2Fsentinel%2Fbreadcrumb%2Ftoc.json&tabs=portal-3%2Cportal-1%2Cportal-2)

--- 
# Ingest data sources in Microsoft Sentinel

## Identify data sources to be ingested for Microsoft Sentinel

### Data Ingestion Overview  
- Microsoft Sentinel uses data connectors to ingest security data from various sources.  
- Types of connectors:  
	- Built-in (Microsoft Services): Defender XDR (includes Office 365, Entra ID, Defender for Identity, Defender for Cloud Apps).  
	- Third-Party & Custom: Syslog, CEF, REST API, Log Ingestion API, Azure Monitor Agent (AMA).  

### Microsoft Sentinel Solutions & Connectors  
- Solutions:
	- Pre-packaged security content (connectors, workbooks, analytics rules, playbooks).  
- Installed connectors:
	- View in Microsoft Sentinel > Data Connectors page.  
- To add new connectors:
	- Install solutions from the Content Hub.  

### Custom Data Connectors  
- Use when no built-in solution exists.  
- Methods:  
	- Codeless Connector Platform (for APIs).  
	- Log Ingestion API (via Azure Function/Logic App).  
	- Azure Monitor Agent (AMA) or Logstash.  

### Agent-Based Integration  
- Syslog & CEF (Linux-based sources):  
	- Install Azure Monitor Agent (AMA) on a log forwarder or directly on the source.  
	- Syslog events → Syslog table, CEF events → CommonSecurityLog table.  
- Custom Logs: Log Analytics custom log agent for Windows/Linux file-based ingestion.  

### Service-to-Service Integrations  
- Native integration for Microsoft services (Azure, Windows, Defender) & AWS.  
- Configuration:
	- Follow setup instructions on each Microsoft Sentinel data connector page.  

### Support Types for Data Connectors  
| Type | Description | Support Provided By |  
|---------|---------------|--------------------|  
| Microsoft-Supported | Microsoft-authored connectors for first-party & some third-party sources. | Microsoft Azure Support Plans |  
| Partner-Supported | Third-party vendor connectors. | Vendor/MSSP/SI support |  
| Community-Supported | Open-source/community-created connectors. | Microsoft Sentinel GitHub Community |  

📌 Source: [Microsoft Sentinel data connectors | Microsoft  Learn](https://learn.microsoft.com/en-us/azure/sentinel/connect-data-sources?tabs=azure-portal)

---
## Implement and use Content hub solutions

### Overview
- Centralized platform to discover, install, and manage built-in security solutions.
- Includes prepackaged solutions and standalone content (rules, playbooks, workbooks, queries).
- Requires Microsoft Sentinel Contributor role at the resource group level.

### Discover Content
- Navigate to Content hub via:
	- Azure portal: Content management > Content hub
	- Defender portal: Microsoft Sentinel > Content management > Content hub
- Use filters: status, content type, support, provider, category.
- Search supports fuzzy matching & AI-driven queries.

### Install & Update Solutions
- Install content individually or in bulk.
- Steps:
  1. Locate solution in Content hub.
  2. Select View details > Create/Update.
  3. Provide Subscription, Resource Group, Workspace.
  4. Complete configuration steps per content type.
  5. Review + Create and validate before deployment.
  6. If dependencies exist, select Install with dependencies.
  7. Post-installation, configure additional content if required.

### Bulk Install & Updates
- Switch to List View.
- Select multiple solutions/content items.
- Click Install/Update.
- Standalone content updates automatically.

### Enable & Manage Installed Content
- Data Connectors
	- Navigate to the Connector page.
	- Complete setup; status changes from Disconnected → Connected.
- Analytics Rules
	- View in Analytics template gallery.
	- Select Create rule (if not yet created) or Edit existing rule.
	- Active rules are listed under Content created.
- Hunting Queries
	- Select Run query for immediate results.
	- Clone and modify query via Hunting gallery.
- Workbooks
	- Select View template > Save to create an instance.
	- View saved workbooks under Created content.
- Parsers
	- Installed as workspace functions.
	- Open Log Analytics > Load function code > Use in editor.
- Playbooks
	- Select playbook template > Create playbook.
	- Manage active playbooks under Created content.

### Support Model
- Located in the Support box on the solution's detail pane.
- Additional details (Publisher, Provider, Plan ID) under Usage information & support.

📌 Source: [Discover and deploy Microsoft Sentinel out-of-the-box content from Content hub | Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-deploy?tabs=azure-portal)

---
## Configure and use Microsoft connectors for Azure resources, including Azure Policy and diagnostic settings

### Overview
- Objective: Integrate Azure services with Microsoft Sentinel using diagnostic settings and Azure Policy.

### Key Concepts
- Diagnostic Settings: Configure Azure resources to send logs and metrics to destinations like Log Analytics, Event Hubs, or Storage Accounts.
- Azure Policy: Automate the application of diagnostic settings across multiple resources for consistent monitoring.

### Configuring Diagnostic Settings for Individual Resources
1. Navigate to Resource:
   - Go to the Azure portal.
   - Select the resource (e.g., Azure Activity) you want to monitor.
2. Access Diagnostic Settings:
   - In the resource's menu, click on 'Diagnostic settings'.
3. Add Diagnostic Setting:
   - Click '+ Add diagnostic setting'.
   - Provide a name for the setting.
4. Select Logs and Metrics:
   - Choose the log categories and metrics to collect.
5. Choose Destination:
   - Select 'Send to Log Analytics workspace'.
   - Specify the target Log Analytics workspace.
6. Save Configuration:
   - Click 'Save' to apply the settings.

### Automating Diagnostic Settings with Azure Policy
1. Access Data Connectors:
   - In Microsoft Sentinel, go to 'Data connectors'.
2. Select Resource Type:
   - Choose the resource type (e.g., Azure Activity) from the gallery.
3. Launch Azure Policy Assignment Wizard:
   - Click 'Launch Azure Policy Assignment wizard'.
4. Define Scope:
   - In the 'Basics' tab, set the scope by selecting the subscription and, optionally, a resource group.
5. Configure Parameters:
   - In the 'Parameters' tab:
     - Ensure 'Only show parameters that require input' is unchecked.
     - Select the appropriate Log Analytics workspace.
     - Set desired log categories to 'True'.
6. Review and Create:
   - Review the configuration and click 'Create' to assign the policy.

### Best Practices
- Consistent Monitoring: Use Azure Policy to enforce uniform diagnostic settings across resources.
- Selective Logging: Enable only necessary log categories to optimize data ingestion and costs.
- Regular Reviews: Periodically audit diagnostic settings to ensure compliance and effectiveness.

📌 Source: [Connect Microsoft Sentinel to Azure, Windows, and Microsoft services | Microsoft Learn](
https://learn.microsoft.com/en-us/azure/sentinel/connect-azure-windows-microsoft-services)

---
## Plan and configure Syslog and Common Event Format (CEF) event collections

### Overview
- Objective: Integrate Syslog and CEF messages into Microsoft Sentinel using the Azure Monitor Agent (AMA).

### Key Concepts
- Syslog: Standard protocol for transmitting log messages across network devices.
- Common Event Format (CEF): Vendor-neutral log format designed for security information and event management (SIEM) systems.
- Azure Monitor Agent (AMA): Collects and forwards Syslog and CEF messages to Microsoft Sentinel.
- Data Collection Rule (DCR): Defines the log sources and types of messages to collect.

### Setup Process
1. Install the Appropriate Solution:
   - From the Microsoft Sentinel Content hub, install the Syslog or Common Event Format solution. 
2. Create a Data Collection Rule (DCR):
   - Navigate to Microsoft Sentinel > Configuration > Data connectors.
   - Select 'Syslog via AMA' or 'Common Event Format (CEF) via AMA' connector.
   - Click '+Create data collection rule'.
   - Provide a name, select subscription, and resource group.
   - Define log sources and specify log levels.
3. Install Azure Monitor Agent (AMA):
   - AMA is automatically installed on selected Linux machines during DCR creation.
4. Configure Syslog Daemon on Log Forwarder:
   - Set up 'rsyslog' or 'syslog-ng' to listen on TCP/UDP port 514 (or preferred port).
   - Ensure configuration matches the application's log transmission settings.
5. Configure Security Devices or Appliances:
   - Set devices to send logs in CEF or Syslog format to the log forwarder's IP and designated port.

### Best Practices
- Avoid Data Duplication:
   - Use separate facilities for Syslog and CEF messages.
   - Adjust Syslog configuration on source devices to prevent overlapping log facilities. 
- Secure Log Transmission:
   - For devices sending logs over TLS, configure the Syslog daemon to support TLS communication.
- Monitor and Maintain:
   - Regularly review DCRs and AMA configurations to ensure continuous log collection.

📌 Source: [Syslog and CEF AMA connectors - Microsoft Sentinel | Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/cef-syslog-ama-overview?tabs=forwarder)

---
## Plan and configure collection of Windows Security events by using data collection rules, including Windows Event Forwarding (WEF)

### Overview

- **Objective**: Collect Windows Security events in Microsoft Sentinel using Azure Monitor Agent (AMA), Data Collection Rules (DCRs), and Windows Event Forwarding (WEF).

### Key Concepts

- **Azure Monitor Agent (AMA)**: The agent responsible for collecting monitoring data from Windows machines.
- **Data Collection Rules (DCRs)**: Define the data to collect and specify the destination for that data.
- **Windows Event Forwarding (WEF)**: Aggregates event logs from multiple Windows devices to a central server for streamlined monitoring.


### 1. Configure Windows Event Forwarding (WEF)

- **Set Up a Collector**:
  - Designate a Windows Server as the event collector.
  - Configure the server to collect events from source computers using Group Policy or local settings.

- **Configure Source Computers**:
  - Ensure source computers are configured to forward events to the collector.
  - Use Group Policy to define which events to forward.

*Reference*: :contentReference[oaicite:0]{index=0}

### 2. Install Azure Monitor Agent (AMA) on the Collector

- **Installation**:
  - Install the AMA on the event collector server.
  - Ensure the agent is properly connected to your Azure environment.

*Reference*: :contentReference[oaicite:1]{index=1}

### 3. Create Data Collection Rules (DCRs)

- **Define Data Collection**:
  - In the Azure portal, navigate to Microsoft Sentinel > Configuration > Data connectors.
  - Select 'Windows Security Events via AMA' connector.
  - Click '+Create data collection rule'.
  - Specify the event logs to collect (e.g., Security) and define severity levels.

- **Assign DCR to Machines**:
  - Assign the DCR to the event collector machine to ensure the specified events are collected.

*Reference*: :contentReference[oaicite:2]{index=2}

### Best Practices

- **Centralized Collection**:
  - Use WEF to centralize event logs from multiple sources, simplifying monitoring and management.

- **Monitor Data Ingestion**:
  - Regularly verify that events are being ingested into Microsoft Sentinel as expected.

- **Security Considerations**:
  - Ensure secure communication between source computers and the event collector.
  - Implement appropriate access controls to protect collected event data.

📌 Source:

---

