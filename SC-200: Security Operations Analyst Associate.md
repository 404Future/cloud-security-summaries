# SC-200: Security Operations Analyst Associate (Skills measured as of October 21, 2024) Study Guide  

## Foreword  

When I first started studying for the SC-200 exam, I relied on Microsoft's official learning path and study guide. However, I quickly realized that the material wasn’t always structured in a way that made it easy to see how each topic mapped to the exam objectives. Some key concepts felt buried in long explanations, while others seemed disconnected from the technical documentation.

To make studying more effective, I took a different approach. I used Microsoft Learn as my foundation but supplemented it with the official technical documentation, linking relevant articles directly to the exam objectives. This helped me focus on what actually mattered for the test while deepening my practical understanding of Defender XDR, Sentinel, and other security solutions.

This study guide is the result of that process. It’s a structured summary of what I learned, with direct references to Microsoft’s documentation where needed. My goal is to make it easier for others to navigate the material, just like I wish I had when I started.

If you find this preview helpful, I offer full versions of my study guides on Patreon, where I go even deeper into the topics. But whether you use this guide alone or as a supplement, I hope it helps you prepare more efficiently and confidently for the exam.
  
---  

# Manage a Security Operations Environment (20-25%)  

## Configure Settings in Microsoft Defender XDR  

### Configure Alert and Vulnerability Notification Rules  

#### 1. Alert Notification Rules (Defender XDR)  

**Purpose:** Sends email alerts for new security threats based on severity.  
**Permissions Required:** ‘Manage security settings’ or Security Administrator/Global Administrator.  
**Device Groups:** Supported in Defender for Endpoint Plan 1 & 2 (not in Defender for Business).  
**RBAC Considerations:** Recipients only receive alerts for assigned device groups.  
**Best Practice:** Use minimal permissions; Global Administrator only for emergencies.  

##### Configuration Steps  

1. Sign in to the Defender portal as Security/Global Admin.  
2. Navigate to **Settings > Endpoints > General > Email notifications**.  
3. Add notification rule → Define:  
   - Rule Name  
   - Organization Name (optional)  
   - Tenant-specific portal link (optional)  
   - Device Groups (All devices or selected groups)  
   - Alert Severity (Define severity levels)  
4. Enter recipient emails → Add multiple if needed.  
5. Send test email (optional) → Save rule.  

##### Modify/Delete Rules  

- **Edit:** Select the rule → Update details → Save.  
- **Delete:** Select the rule → Delete.  

##### Troubleshooting  

- Ensure emails aren’t blocked (Junk folder, security filters, mail rules).  

📌 **Source:** [Configure alert notifications - Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/microsoft-365/security/defender-xdr/configure-alert-notifications)  

---

#### 2. Vulnerability Notification Rules (Defender for Endpoint)  

**Purpose:** Sends email alerts for new vulnerability events.  
**Permissions Required:** ‘Manage security settings’ or Security Administrator.  
**Device Groups:** Supported in Defender for Endpoint Plan 1 & 2 (not in Defender for Business).  
**RBAC Considerations:** Notifications are limited to assigned device groups.  
**Best Practice:** Limit high-privilege roles to improve security.  

##### Configuration Steps  

1. Sign in to the Defender portal as Security Admin.  
2. Navigate to **Settings > Endpoints > General > Email notifications > Vulnerabilities**.  
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
   - Enter recipient emails → Add multiple if needed.  
4. Review settings → Create rule.  

##### Modify/Delete Rules  

- **Edit:** Select rule → Click Edit rule → Update details.  
- **Delete:** Select rule → Click Delete.  

##### Troubleshooting  

- Check email filters (Junk folder, security software, mail rules).  

📌 **Source:** [Configure vulnerability email notifications in Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-vulnerability-email-notifications)  

---

## Configure Microsoft Defender for Endpoint Advanced Features  

### Enabling Advanced Features  

**Access Settings:**  
- **Defender Portal > Settings > Endpoints > Advanced Features**  
- Toggle features **ON/OFF** and Save Preferences  

#### Key Advanced Features & Configurations  

| Feature | Purpose |
|---------|---------|
| **Restrict Incident Correlation by Device Groups** | Limits alert correlation within defined device groups |
| **Enable EDR in Block Mode** | Blocks malicious artifacts even when Defender AV is in passive mode |
| **Automatically Resolve Alerts** | Auto-closes alerts if no threats are found or are remediated |
| **Allow or Block Files** | Requires Defender AV as active AV + Cloud Protection enabled |
| **Tamper Protection** | Prevents unauthorized changes to security settings |
| **Custom Network Indicators** | Create allow/block lists for IPs, domains, URLs |
| **Web Content Filtering** | Blocks unwanted content + tracks web activity |

📌 **Source:** [Configure advanced features in Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-advanced-features)  

---

## Configure Endpoint Rules Settings  

### 1. Managing Alert Suppression Rules  

**Purpose:** Suppress known false-positive alerts.  
**Access:** **Microsoft Defender portal → Settings → Endpoints → Rules → Alert suppression**.  
**Actions:**  
- View, create, edit, enable/disable, or delete suppression rules.  
- Option to release previously suppressed alerts.  
**Permissions:** Requires Security Administrator or Global Administrator role.  

📌 **Source:** [Manage Microsoft Defender for Endpoint suppression rules | Microsoft Learn](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/manage-alert-suppression)  

---

## Manage Automated Investigation and Response Capabilities in Microsoft Defender XDR  

### 1. Prerequisites  

- **Permissions:** Global Administrator or Security Administrator in Microsoft Entra ID/Microsoft 365 Admin Center.  

### 2. Configure Automation Level for Device Groups  

1. **Access Portal:** Defender Portal → Settings > Endpoints > Device Groups  
2. **Review & Edit Automation Level:**  
   - **Full (Recommended):** Auto-remediates threats.  
   - **Semi:** Approves some actions.  
   - **Minimal:** Only collects evidence.  
   - **None:** No automated response.  

### 3. Security & Alert Policies in Office 365  

- **Defender for Office 365 Alert Policies:** Identifies Exchange admin abuse, malware, insider threats.  
- **Preset Security Policies:** Use **Standard/Strict** to protect emails & content.  
- **Review Alerts:** Path → **Defender Portal → Policies & Rules > Alert Policy**.  
- **Remediation Approval:** Email-related remediation requires manual approval in **Action Center**.  

📌 **Source:** [Configure automated investigation and response capabilities in Microsoft Defender XDR | Microsoft Learn](https://learn.microsoft.com/en-us/microsoft-365/security/defender-xdr/configure-air)  

# Manage assets and environments

## 1. Configure & Manage Device Groups
**Purpose:** Group devices for role-based access control (RBAC), auto-remediation, and filtered investigations.

### Key Actions:
#### Create Device Group:
- Go to `Settings > Endpoints > Permissions > Device Groups`.
- Click **Add device group**, name it, and set automation level.
- Define matching rules (device name, domain, OS, tags).
- Assign Microsoft Entra user groups for access.

#### Manage Device Groups:
- Rank priority (1 = highest).
- Unmatched devices go to **Ungrouped Devices** (default).
- Edit/Delete groups (note: deleting may affect notification rules).

#### Best Practices:
- Use tagging for easier management.
- Assign groups granularly to limit access.

📌 **Source:** [Create and manage device groups in Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/microsoft-defender-endpoint/create-device-groups)

---

## 2. Role-Based Access Control (RBAC)
**Why Use RBAC?** Limits user access to Defender data and actions.

### Create RBAC Roles:
- Go to `Settings > Endpoints > Roles`.
- Click **Add Role**, define permissions (Security Ops, Vulnerability Mgmt, Live Response).
- Assign Microsoft Entra group to the role.

### Permissions Breakdown:
- **Security Ops:** View data, respond to threats.
- **Defender Vulnerability Mgmt:** Handle remediation, exceptions.
- **Live Response:**
  - Basic: Read-only commands, file download.
  - Advanced: Upload & execute scripts.

#### Editing/Deleting Roles:
- Edit via `Settings > Endpoints > Roles`.
- Delete roles via the dropdown menu.

#### Best Practice:
- Use least privilege (avoid Global Administrator unless necessary).

📌 **Source:** [Create and manage roles for role-based access control](https://learn.microsoft.com/en-us/microsoft-defender-endpoint/create-roles)

---

## 3. Automation Levels in Defender for Endpoint
**Purpose:** Controls automated threat remediation in AIR (Automated Investigation & Remediation).

### Levels of Automation:
- **Full Automation (Recommended):** Automatically remediates malicious artifacts. Best for efficiency & security.
- **Semi-Automation:** Approval needed for remediation in certain locations.
  - Variants:
    - All folders: Requires approval for all files.
    - Core folders: Only system-critical locations need approval.
    - Non-temp folders: Excludes temporary locations.
- **No Automation:** No automated remediation or investigation (not recommended).

#### Key Notes:
- Full automation removes 40% more threats than semi-automation.
- Defender for Business uses Full Automation by default.
- View all remediation actions in Action Center.
- Changes take effect instantly after updating settings.

📌 **Source:** [Automation levels in automated investigation and remediation](https://learn.microsoft.com/en-us/microsoft-defender-endpoint/automation-levels)

---

# Identify unmanaged devices in Microsoft Defender for Endpoint

## 1. Overview
Device discovery in Microsoft Defender for Endpoint (MDE) identifies unmanaged devices in the network. Helps secure endpoints, network devices, and IoT assets by onboarding them to Defender for Endpoint.

## 2. Discovery Modes
- **Basic Discovery (Passive):** Uses SenseNDR.exe to collect network traffic data. Limited visibility—only detects devices seen in existing network traffic.
- **Standard Discovery (Active) – Recommended:** Uses multicast queries and active probing to find more devices. Provides enriched device information. Default mode since July 19, 2021.

## 3. Device Inventory & Onboarding Status
- **Onboarded:** Device is managed by Defender for Endpoint.
- **Can be onboarded:** Detected and supported but not yet onboarded.
- **Unsupported:** Detected but not supported by Defender for Endpoint.
- **Insufficient info:** Requires standard discovery for more details.

## 4. Network Device Discovery
Uses authenticated remote scans (agentless) via Defender for Endpoint sensors. Discovers routers, switches, firewalls, WLAN controllers, VPN gateways.

## 5. Advanced Hunting for Unmanaged Devices
- Find discovered devices 

    DeviceInfo
    | summarize arg_max(Timestamp, *) by DeviceId  
    | where isempty(MergedToDeviceId)  
    | where OnboardingStatus != "Onboarded"

- Identify which onboarded device detected them 

    DeviceInfo
    | where OnboardingStatus != "Onboarded"
    | summarize arg_max(Timestamp, *) by DeviceId  
    | where isempty(MergedToDeviceId)  
    | limit 100  
    | invoke SeenBy()  
    | project DeviceId, DeviceName, DeviceType, SeenBy

- Analyze network connections from non-onboarded devices 

    DeviceNetworkEvents
    | where ActionType == "ConnectionAcknowledged" or ActionType == "ConnectionAttempt"
    | take 10

## 6. Defender for IoT Integration
Extends discovery to OT and Enterprise IoT devices (e.g., VoIP, printers, smart TVs). Works via Microsoft Defender for IoT in Defender portal.

## 7. Security Recommendations & Vulnerability Management
Found under **Defender Vulnerability Management > Security Recommendations**. Helps prioritize onboarding and securing high-risk unmanaged devices.

📌 **Source:** [Device discovery overview - Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/microsoft-defender-endpoint/device-discovery)

---

# Discover unprotected resources by using Defender for Cloud

### Key Concepts:
- **Unprotected Resources:** Resources without appropriate security settings or protection.
- **Defender for Cloud Recommendations:** Suggestions to secure unprotected resources.
- **Security Alerts:** Notifications about unprotected or misconfigured resources.

### Steps to Discover Unprotected Resources:
1. Enable Defender for Cloud: Activate in the Azure Portal for resource monitoring.
2. Review Security Alerts: Identify flagged resources with missing protections.
3. Review Security Recommendations: Implement actionable steps to secure resources.

### Best Practices:
- Regularly monitor Security Alerts for new vulnerabilities.
- Apply recommended policies to secure resources.
- Use tags for better resource classification.

### Important Tools:
- **Azure Arc:** Extends coverage to non-Azure resources.
- **RBAC:** Ensures proper permissions for resource management.

### Critical Functions:
- **CSPM (Cloud Security Posture Management):** Tracks multi-cloud security.
- **Resource Inventory:** Discovers and tracks unprotected resources.

### Actionable Steps:
- Enable Defender for Cloud to start discovery.
- Use Azure Arc for non-Azure resources.
- Review Secure Score to assess environment security.

📌 **Source:**
- [What is Azure Resource Manager? - Azure Resource Manager](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/overview)
- [Azure Arc overview - Azure Arc](https://learn.microsoft.com/en-us/azure/azure-arc/overview)
- [Microsoft Defender for Cloud Overview](https://learn.microsoft.com/en-us/microsoft-defender-cloud/overview)

---

# Identify and remediate devices at risk by using Microsoft Defender Vulnerability Management

### High-Level Overview:
**Purpose:** Identify, assess, and remediate vulnerabilities across critical assets to reduce cyber risk.  
**Key Features:** Asset visibility, intelligent risk prioritization, built-in remediation tools, cross-platform support (Windows, macOS, Linux, Android, iOS, network devices).  
**Core Goals:** Prioritize vulnerabilities, provide mitigation strategies, and track remediation efforts.

### Key Components:
- **Asset Discovery & Monitoring:** Continuous scanning of devices, even offline. Centralized view of software, certificates, hardware, firmware, and browser extensions.
- **Vulnerability Assessment Tools:** Security Baselines, Software Inventory, Network Shares, Event Timelines for vulnerability tracking and prioritization.
- **Risk-based Prioritization:** Leverage Microsoft threat intelligence and breach likelihood. Focus on high-risk, actively exploited vulnerabilities.

### Remediation & Tracking:
- **Built-in Workflows:** Create remediation tasks in Microsoft Intune. Block vulnerable applications on specific devices. Track remediation progress in real time.
- **Remediation Strategies:** Actionable security recommendations (e.g., patches, configuration changes). Alternative mitigations for vulnerabilities when direct patching isn't possible.

### Navigation & Reporting:
- **Dashboard:** View risk scores, recommendations, top vulnerabilities, and remediation activities.
- **Recommendations:** Lists of security issues, with links to remediation options.
- **Inventories & Weaknesses:** Access asset lists and common vulnerabilities (CVE tracking).
- **APIs:** Automate workflows with Defender for Endpoint APIs for vulnerabilities, recommendations, and machine data.

### Best Practices:
- Prioritize vulnerabilities based on exposure and criticality.
- Regularly assess devices, even when offline, to maintain up-to-date visibility.
- Use real-time monitoring to track and ensure successful remediation.

📌 **Source:** [Microsoft Defender Vulnerability Management](https://learn.microsoft.com/en-us/microsoft-defender-vulnerability-management)

---

# Mitigate risk by using Exposure Management in Microsoft Defender XDR

### High-Level Overview:
**Purpose:** Provides a unified view of organizational security posture and attack surface to proactively manage and mitigate exposure risks.  
**Core Functions:** Asset discovery, attack surface management, exposure insights, risk mitigation, and attack path simulation.

### Key Features:
- **Unified View:** Continuously discovers assets and workloads, creating an up-to-date inventory and attack surface.
- **Attack Surface Management:** Visualize and analyze attack surfaces across on-premises, hybrid, and multicloud environments. Use the enterprise exposure graph to query and assess risk.
- **Critical Asset Management:** Mark assets as critical for focused security efforts. Prioritize and safeguard critical assets for business continuity.
- **Exposure Insights:** Aggregate security posture data for actionable insights, including security events, recommendations, and metrics.

### Risk Mitigation:
- **Attack Path Simulation:** Generate attack paths based on asset and workload data. Simulate attack scenarios and identify exploitable weaknesses.
- **Actionable Recommendations:** Use insights and recommendations to mitigate attack paths.

### Data Integration:
- **Data Connectors:** Integrate data from multiple sources into a unified view for deeper security insights.

### Best Practices:
- Continuously monitor and update asset inventory to keep exposure data current.
- Leverage the enterprise exposure graph for comprehensive risk analysis.
- Prioritize remediation based on attack paths and critical asset visibility.

📌 **Source:** [What is Microsoft Security Exposure Management?](https://learn.microsoft.com/en-us/microsoft-defender-exposure-management)

