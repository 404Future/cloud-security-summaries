# Configure settings in Microsoft Defender XDR

## Configure alert and vulnerability notification rules

Alert Notification Rules (Defender XDR)
- Purpose:
  - Sends email alerts for new security threats based on severity.
- Permissions Required: 
  - ‘Manage security settings’ or Security Administrator/Global Administrator.
- Device Groups: 
  - Supported in Defender for Endpoint Plan 1 & 2 (not in Defender for Business).
- RBAC Considerations: 
	- Recipients only receive alerts for assigned device groups.
- Best Practice: 
	- Use minimal permissions; Global Administrator only for emergencies.

Configuration Steps
1. Sign in to the Defender portal as Security/Global Admin. 
2. Navigate to `Settings > Endpoints > General > Email notifications`.   
3. Add notification rule → Define:
	- Rule Name 
	- Organization Name (optional)
	- Tenant-specific portal link (optional)
	- Device Groups (All devices or selected groups)
	- Alert Severity (Define severity levels)
4. Enter recipient emails → Add multiple if needed.
5. Send test email (optional) → Save rule.

Modify/Delete Rules
- Edit: 
  - Select the rule → Update details → Save.
- Delete: 
  - Select the rule → Delete.

Troubleshooting
- Ensure emails aren’t blocked (Junk folder, security filters, mail rules).

📌 Source: [Configure alert notifications - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/configure-email-notifications)

Vulnerability Notification Rules (Defender for Endpoint)
- Purpose: 
	- Sends email alerts for new vulnerability events.
- Permissions Required: 
	- ‘Manage security settings’ or Security Administrator.
- Device Groups: 
	- Supported in Defender for Endpoint Plan 1 & 2 (not in Defender for Business).
- RBAC Considerations: 
	- Notifications are limited to assigned device groups.
- Best Practice: 
	- Limit high-privilege roles to improve security. 

Configuration Steps
1. Sign in to the Defender portal as Security Admin.
2. Navigate to `Settings > Endpoints > General > Email notifications > Vulnerabilities`.
3. Add notification rule → Define:
	- Rule Name & Description
	- Activate notification rule
	- Device Groups (If applicable)
	- Vulnerability Events:
		- New vulnerability found
		- Exploit verified
		- New public exploit
		- Exploit added to exploit kit
	- Include organization name (optional)
4. Enter recipient emails → Add multiple if needed.
5. Review settings → Create rule.

Modify/Delete Rules
- Edit: 
	- Select rule → Click Edit rule → Update details.
- Delete: 
	- Select rule → Click Delete.

Troubleshooting
- Check email filters (Junk folder, security software, mail rules).

📌  Source: [Configure vulnerability email notifications in Microsoft Defender for Endpoint - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/configure-vulnerability-email-notifications)

--- 
## Configure Microsoft Defender for Endpoint advanced features

Enabling Advanced Features
- Access Settings: 
  - Navigate to Defender Portal > `Settings > Endpoints > Advanced Feature`
- Toggle features ON/OFF and Save Preferences

Key Advanced Features & Configurations

| Feature                                                | Purpose                                                                                                           |
| ------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| **Restrict Incident Correlation by Device Groups**     | Limits alert correlation within defined device groups. (Recommended: Leave OFF unless local SOC needs isolation)  |
| **Enable EDR in Block Mode**                           | Blocks malicious artifacts even when Defender AV is in passive mode                                               |
| **Automatically Resolve Alerts**                       | Auto-closes alerts if no threats are found or are remediated. Does not override manually resolved alerts.         |
| **Allow or Block Files**                               | Requires Defender AV as active AV + Cloud Protection enabled. Toggle `Settings > Endpoints > Allow or Block File` |
| **Tamper Protection**                                  | Prevents unauthorized changes to security settings                                                                |
| **Custom Network Indicators**                          | Create allow/block lists for IPs, domains, URLs                                                                   |
| **Web Content Filtering**                              | Blocks unwanted content + tracks web activity. equires Network Protection in block mode.                          |
| Hide Duplicate Device Records                          | Identifies & hides duplicate records (default ON)                                                                 |
| Show User Details                                      | Displays Microsoft Entra ID info (user photo, title, department)                                                  |
| Skype for Business Integration                         | Allows direct communication with users during incident response                                                   |
| Microsoft Defender for Cloud Apps                      | Forwards Defender signals to Defender for Cloud Apps for cloud visibility                                         |
| Unified Audit Log                                      | Enables Microsoft Purview search for security event logs                                                          |
| Device Discovery                                       | Identifies unmanaged devices using onboarded endpoints                                                            |
| Download Quarantined Files                             | Enables file download from quarantine (default ON)                                                                |
| Streamlined Connectivity for Onboarding                | Sets default onboarding package for applicable OS                                                                 |
| Live Response Features                                 | Start live response sessions on devices & servers. Option to run unsigned scripts during sessions.                |
| Deception Capabilities                                 | Deploy lures & decoys to detect attackers. Managed via `Rules > Deception Rules`                                  |
| Share Endpoint Alerts with Microsoft Compliance Center | Integrates with Microsoft Purview for insider risk detection                                                      |
| Microsoft Intune Connection                            | Enables device risk-based Conditional Access                                                                      |
| Authenticated Telemetry                                | Prevents spoofed security telemetry data                                                                          |
| Preview Features                                       | Grants early access to new Defender for Endpoint features                                                         |
| Endpoint Attack Notifications                          | Provides proactive threat hunting from Microsoft experts                                                          |
  
📌  Source: [Configure advanced features in Microsoft Defender for Endpoint - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/advanced-features)

---  
## Configure endpoint rules settings

Managing Alert Suppression Rules
- Purpose: 
	- Suppress known false-positive alerts.
- Access: 
	- Microsoft Defender portal → `Settings → Endpoints → Rules → Alert suppression`.
- Actions:
	- View, create, edit, enable/disable, or delete suppression rules.
	- Option to release previously suppressed alerts.
- Permissions: 
	- Requires Security Administrator or Global Administrator role.

📌  Source: [Manage Microsoft Defender for Endpoint suppression rules - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/manage-suppression-rules)    

Indicators of Compromise (IoCs) Management
- Purpose: 
	- Define detection, prevention, and exclusion policies for threats.
- Supported IoC Types:
	- Files (Hashes) – Block execution, remediation, audit, warn, allow.
	- IP Addresses, URLs/Domains – Same as files.
	- Certificates – Allow or block & remediate only.
- Key Considerations:
	- 15,000 indicator limit per tenant.
	- Blocking via file hashes not recommended for apps (use WDAC or AppLocker).
	- Network protection blocks access after TCP handshake completes.
	- IoC enforcement depends on Defender settings & configured actions.

📌  Source: [Overview of indicators in Microsoft Defender for Endpoint - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/indicators-overview) 

Configuring Web Content Filtering
- Purpose: 
	- Restrict access to specific web content categories.
- Steps to Configure:
	1. Microsoft Defender portal → `Settings → Endpoints → Rules → Web content filtering`.
	2. Add new policy → Name policy.
	3. Select blocked categories.
	4. Assign to device groups.
	5. Review and save policy.

📌  Source: [Set up and configure Microsoft Defender for Endpoint Plan 1 - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/mde-p1-setup-configuration#configure-web-content-filtering)

Enforcement & Detection Engines
- Cloud Detection Engine: 
	- Scans data for IoC matches, enforcing defined actions.
- Endpoint Prevention Engine: 
	- Applies Defender AV policies for alerts & blocks.
- Automated Investigation & Remediation: 
	- Overrides verdicts based on IoC settings.

Best Practices & Limitations
- Use least privilege roles (avoid Global Administrator unless necessary).
- Prefer IP/URL indicators over file hashes for web access control.
- Microsoft Store apps cannot be blocked via Defender.
- Defender for Cloud Apps can override Defender portal IoC settings.
- Some alert types (e.g., block indicators) generate informational alerts only.

---
## Manage automated investigation and response capabilities in Microsoft Defender XDR

Prerequisites
- Permissions: 
	- Global Administrator or Security Administrator in Microsoft Entra ID/Microsoft 365 Admin Center.

Configure Automation Level for Device Groups
- Access Portal: 
	- Defender Portal → `Settings > Endpoints > Device Groups`
- Review & Edit Automation Level:
	- Full (Recommended): Auto-remediates threats.
	- Semi: Approves some actions.
	- Minimal: Only collects evidence.
	- None: No automated response.

Security & Alert Policies in Office 365
- Defender for Office 365 Alert Policies: 
	- Identifies Exchange admin abuse, malware, insider threats.
- Preset Security Policies:
	- Use Standard/Strict to protect emails & content.
	- Custom Policies? 
		- Use Configuration Analyzer for comparison.
- Review Alerts:
	- Path: 
		- Defender Portal → `Policies & Rules > Alert Policy`
	- Some alerts trigger automated investigations.
- Remediation Approval:
	- Email-related remediation requires manual approval in Action Center.

Modifying Automated Investigation Settings
- Change Device Automation Level:
	- Defender Portal → `Permissions > Endpoints roles & groups > Device groups`
	- Select group → Adjust Automation Level (Full recommended).

📌  Source: [Configure automated investigation and response capabilities in Microsoft Defender XDR - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/m365d-configure-auto-investigation-response)

---
## Configure automatic attack disruption in Microsoft Defender XDR

Prerequisites
- Roles Required: 
	- Global Administrator or Security Administrator (Microsoft Entra ID/Microsoft 365 Admin Center).
- Permissions Needed: 
	- Review, approve, or reject automated containment actions in Action Center.

Microsoft Defender for Endpoint Requirements
- Automation Level Settings:
	- Path: 
		- Defender Portal → `System > Settings > Endpoints > Device Groups`.
	- Recommended Setting: 
		- Full - remediate threats automatically.
	- Semi-Automation: 
		- Allows attack disruption without manual approval.
	- No Automated Response: 
		- Excludes specific devices (not recommended).

Device Discovery Configuration
- Minimum Setting: 
	- Standard Discovery (Configure via Set up device discovery).
- Works Regardless of Defender AV Mode: 
	- Active, Passive, or EDR Block Mode.

Microsoft Defender for Identity Requirements
- Audit Policies on Domain Controllers: 
	- Configure Windows event logs for required audit events.
- Validate Action Accounts:
	- Defender for Identity impersonates LocalSystem by default.
	- Ensure required permissions are set if using a different account.
- Automation Conflict Check: 
	- Prevent external automation from reactivating disrupted accounts.
- Sensor Deployment: 
	- Must be installed on the domain controller managing the affected AD account.

Microsoft Defender for Cloud Apps Requirements
- Microsoft 365 Connector: 
	- Defender for Cloud Apps must be connected to Microsoft 365.
- App Governance: 
	- Must be enabled (refer to app governance documentation). 

Microsoft Defender for Office 365 Requirements
- Mailboxes: 
	- Must be hosted in Exchange Online.
- Mailbox Audit Logging: 
	- Must track at least:
		- MailItemsAccessed, UpdateInboxRules, MoveToDeletedItems, SoftDelete, HardDelete.
		- (See Manage mailbox auditing for details).
- Safe Links Policy: 
	- Must be configured.    

📌  Source: [Configure automatic attack disruption in Microsoft Defender XDR - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/configure-attack-disruption)

---
# Manage assets and environments

## Configure and manage device groups, permissions, and automation levels in Microsoft Defender for Endpoint

Configure & Manage Device Groups
- Purpose: 
	- Group devices for role-based access control (RBAC), auto-remediation, and filtered investigations.
- Key Actions:
	- Create Device Group:
		- Go to `Settings > Endpoints > Permissions > Device Groups`.
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

Role-Based Access Control (RBAC)
- Why Use RBAC? 
	- Limits user access to Defender data and actions.
- Create RBAC Roles:
	- Go to `Settings > Endpoints > Roles`.
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
	- Edit via `Settings > Endpoints > Roles`.
	- Delete roles via the dropdown menu.
- Best Practice:
	- Use least privilege (avoid Global Administrator unless necessary).

📌 Source: [Create and manage roles for role-based access control - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/user-roles)
  
Automation Levels in Defender for Endpoint
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

Overview
- Device discovery in Microsoft Defender for Endpoint (MDE) identifies unmanaged devices in the network.
- Helps secure endpoints, network devices, and IoT assets by onboarding them to Defender for Endpoint.

Discovery Modes
- Basic Discovery (Passive)
	- Uses SenseNDR.exe to collect network traffic data.
	- Limited visibility—only detects devices seen in existing network traffic.
- Standard Discovery (Active) – Recommended
	- Uses multicast queries and active probing to find more devices.
	- Provides enriched device information.
	- Default mode since July 19, 2021.

Device Inventory & Onboarding Status
- Onboarded: 
	- Device is managed by Defender for Endpoint.
- Can be onboarded: 
	- Detected and supported but not yet onboarded.
- Unsupported: 
	- Detected but not supported by Defender for Endpoint.
- Insufficient info: 
	- Requires standard discovery for more details.

Network Device Discovery
- Uses authenticated remote scans (agentless) via Defender for Endpoint sensors.
- Discovers routers, switches, firewalls, WLAN controllers, VPN gateways.

Advanced Hunting for Unmanaged Devices
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

Defender for IoT Integration
- Extends discovery to OT and Enterprise IoT devices (e.g., VoIP, printers, smart TVs).
- Works via Microsoft Defender for IoT in Defender portal.

Security Recommendations & Vulnerability Management
- Found under Defender Vulnerability Management > Security Recommendations.
- Helps prioritize onboarding and securing high-risk unmanaged devices.
  
📌 Source: [Device discovery overview - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/device-discovery)

---  
## Discover unprotected resources by using Defender for Cloud

Key Concepts:
- Unprotected Resources: 
	- Resources without appropriate security settings or protection.
- Defender for Cloud Recommendations: 
	- Suggestions to secure unprotected resources.
- Security Alerts: 
	- Notifications about unprotected or misconfigured resources.  

Steps to Discover Unprotected Resources:
1. Enable Defender for Cloud: Activate in the Azure Portal for resource monitoring.
2. Review Security Alerts: Identify flagged resources with missing protections.
3. Review Security Recommendations: Implement actionable steps to secure resources.

Best Practices:
- Regularly monitor Security Alerts for new vulnerabilities.
- Apply recommended policies to secure resources.
- Use tags for better resource classification.

Important Tools:
- Azure Arc: 
	- Extends coverage to non-Azure resources.
- RBAC: 
	- Ensures proper permissions for resource management.

Critical Functions:
- CSPM (Cloud Security Posture Management): 
	- Tracks multi-cloud security.
- Resource Inventory: 
	- Discovers and tracks unprotected resources.

Actionable Steps:
- Enable Defender for Cloud to start discovery.
- Use Azure Arc for non-Azure resources.
- Review Secure Score to assess environment security.

📌 Source:
- [What is Azure Resource Manager? - Azure Resource Manager | Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/overview)
- [Azure Arc overview - Azure Arc | Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-arc/overview)
- [Microsoft Defender for Cloud Overview - Microsoft Defender for Cloud | Microsoft Learn](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction)

---
## Identify and remediate devices at risk by using Microsoft Defender Vulnerability Management

High-Level Overview:
- Purpose: 
	- Identify, assess, and remediate vulnerabilities across critical assets to reduce cyber risk.
- Key Features: 
	- Asset visibility, intelligent risk prioritization, built-in remediation tools, cross-platform support (Windows, macOS, Linux, Android, iOS, network devices).
- Core Goals: 
	- Prioritize vulnerabilities, provide mitigation strategies, and track remediation efforts.

Key Components:
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

Remediation & Tracking:
- Built-in Workflows:
	- Create remediation tasks in Microsoft Intune.
	- Block vulnerable applications on specific devices.
	- Track remediation progress in real time.
- Remediation Strategies:
	- Actionable security recommendations (e.g., patches, configuration changes).
	- Alternative mitigations for vulnerabilities when direct patching isn't possible.

Navigation & Reporting:
- Dashboard: 
	- View risk scores, recommendations, top vulnerabilities, and remediation activities.
- Recommendations: 
	- Lists of security issues, with links to remediation options.
- Inventories & Weaknesses: 
	- Access asset lists and common vulnerabilities (CVE tracking).
- APIs: 
	- Automate workflows with Defender for Endpoint APIs for vulnerabilities, recommendations, and machine data.

Best Practices:
- Prioritize vulnerabilities based on exposure and criticality.
- Regularly assess devices, even when offline, to maintain up-to-date visibility.
- Use real-time monitoring to track and ensure successful remediation.
  
📌 Source: [Microsoft Defender Vulnerability Management - Microsoft Defender Vulnerability Management | Microsoft Learn](https://learn.microsoft.com/en-us/defender-vulnerability-management/defender-vulnerability-management)

---
## Mitigate risk by using Exposure Management in Microsoft Defender XDR

High-Level Overview:
- Purpose: 
	- Provides a unified view of organizational security posture and attack surface to proactively manage and mitigate exposure risks.
- Core Functions: 
	- Asset discovery, attack surface management, exposure insights, risk mitigation, and attack path simulation.  

Key Features:
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

Risk Mitigation:
- Attack Path Simulation:
	- Generate attack paths based on asset and workload data.
	- Simulate attack scenarios and identify exploitable weaknesses.
	- Focus on choke points that may amplify threats.
- Actionable Recommendations:
	- Use insights and recommendations to mitigate attack paths.
	- Focus on actionable steps to reduce exposure risks.  

Data Integration:
- Data Connectors:
	- Integrate data from multiple sources into a unified view.
	- Gain deeper security insights by consolidating data from various environments.

Best Practices:
- Continuously monitor and update asset inventory to keep exposure data current.
- Leverage the enterprise exposure graph for comprehensive risk analysis.
- Prioritize remediation based on attack paths and critical asset visibility.  

📌 Source: [What is Microsoft Security Exposure Management? - Microsoft Security Exposure Management | Microsoft Learn](https://learn.microsoft.com/en-us/security-exposure-management/microsoft-security-exposure-management)

---
