# SC-200 Study Guide  

## Foreword  

When preparing for the **SC-200: Microsoft Security Operations Analyst** exam, I initially followed the **Microsoft Learn learning path** and the **official study guide**. However, I quickly realized that the content was not structured in a study-friendly way—it wasn’t always clear which topics mapped to which exam objectives.  

To create a more effective learning experience, I turned to **Microsoft's technical documentation**. I reviewed the **exam objectives**, identified the relevant technical articles, and built my summary based on those resources. This approach ensured that each exam domain was covered with accurate and up-to-date information.  

In this study guide, I have linked the relevant **Microsoft Learn** documentation to each topic, making it easier to dive deeper into key concepts when needed. My goal is to provide a structured and efficient way to study for SC-200, focusing on the most relevant technical details.  

Hope this helps with your preparation!  

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
