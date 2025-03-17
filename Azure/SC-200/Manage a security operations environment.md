# Configure settings in Microsoft Defender XDR

## Configure alert and vulnerability notification rules

**Access the Microsoft Defender Portal:**
  - Sign in with an account assigned the Security Administrator or Global Administrator role. 

**Navigate to Email Notifications Settings:**
  - Go to **Settings** > **Endpoints** > **General** > **Email notifications**. 

**Create a New Notification Rule:**
  - Click **Add item**.
  - Provide a **Rule name** and, optionally, a description.
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

**Add Notification Recipients:**
  - Enter the recipient's email address and click **Add recipient**. Repeat for multiple recipients.
  - Optionally, send a test email to verify delivery.

**Finalize and Save the Rule:**
  - Review all settings.
  - Click **Save notification rule** to activate.

**Edit or Delete Notification Rules:**
  - To edit:
    - Select the desired rule.
    - Modify settings as needed.
    - Click **Save notification rule**.
  - To delete:
    - Select the desired rule.
    - Click **Delete**.

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

**Access Advanced Features:**
  - Sign in to the Microsoft Defender portal.
  - Navigate to **Settings** > **Endpoints** > **Advanced features**. 

**Enable or Disable Features:**
  - Toggle desired features On or Off.
  - Click **Save preferences** to apply changes. 

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

📌  Source: [Configure advanced features in Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/advanced-features)

---  
## Configure endpoint rules settings

**1. Manage Alert Suppression Rules**
- **Purpose:**
  - Suppress alerts from known benign tools or processes to reduce noise.
- **Steps to Create a Suppression Rule:**
  1. **Sign in** to the Microsoft Defender portal with appropriate administrative privileges.
  2. **Navigate** to **Settings** > **Endpoints** > **Rules** > **Alert suppression**.
  3. **Select** an existing alert to base the suppression rule on.
  4. **Define** the conditions and scope for the rule.
  5. **Save** the rule to activate suppression.
- **Managing Suppression Rules:**
  - **View** all suppression rules under **Alert suppression**.
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
  2. **Navigate** to **Settings** > **Endpoints** > **Rules** > **Web content filtering**.
  3. **Click** **+ Add policy**.
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
  2. **Navigate** to **Settings** > **Endpoints** > **Indicators**.
  3. **Select** the type of indicator to create (e.g., File hash, IP address, URL/domain).
  4. **Specify** the details of the indicator, including the action to take (e.g., Allow, Block) and the scope (device groups).
  5. **Set** the expiration date for the indicator, if applicable.
  6. **Save** the indicator to apply the rule.
- **Managing Indicators:**
  - **View** all configured indicators under the **Indicators** section.
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
  2. **Navigate** to **Settings** > **Endpoints** > **Device groups** under **Permissions**.
  3. **Review** the **Remediation level** for each device group.
  4. **Set** the automation level to **Full - remediate threats automatically** for optimal automated response.
- **Recommendation:**
  - Use the **Full** automation level to allow automatic remediation of threats. 

**4. Reviewing Security and Alert Policies in Office 365**
- **Purpose:**
  - Ensure built-in alert policies are active to detect risks like malware activity and potential threats.
- **Steps:**
  1. **Access** the Microsoft 365 Defender portal.
  2. **Navigate** to **Settings** > **Email & collaboration** > **Policies & rules** > **Threat policies**.
  3. **Review** and **enable** relevant alert policies to support automated investigations.

**5. Managing Remediation Actions**
- **Action Center:**
  - Monitor and manage remediation actions identified during automated investigations.
- **Steps:**
  1. **Go to** the **Action center** in the Microsoft Defender portal.
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
   - Navigate to **Settings** > **Endpoints** > **Device groups**.
   - Review the **Remediation level**; set to **Full - remediate threats automatically** for comprehensive automation. 
3. **Configure Device Discovery:**
   - Ensure device discovery is set to 'Standard Discovery' to enable automatic containment actions. 

**4. Managing Exclusions**
- **Exclude User Accounts from Automated Responses:**
  1. In the Defender portal, go to **Settings** > **Microsoft Defender XDR** > **Identities**.
  2. Under **Automated response exclusions**, select **Add user exclusion**.
  3. Choose user accounts to exclude and save changes. 
- **Exclude IP Addresses (Preview):**
  - Exclude specific IPs from automated containment actions by configuring exclusions in the Defender portal. 

**5. Reviewing and Managing Actions**
- **Incident Review:**
  - In the Defender portal, navigate to **Incidents**.
  - Select incidents tagged with 'Attack Disruption' to view the incident graph and assess impact.
- **Action Center:**
  - Go to **Actions & submissions** > **Action center** to view and manage remediation actions.

**6. Best Practices**
- **Regularly Review Settings:**
  - Ensure automation levels and exclusions align with organizational security policies.
- **Stay Informed:**
  - Keep abreast of new features and updates in Microsoft Defender XDR to enhance security measures.

📌  Source: [Configure automatic attack disruption in Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/configure-attack-disruption)

---
# Manage assets and environments

## Configure and manage device groups, permissions, and automation levels in Microsoft Defender for Endpoint

**1. Device Groups**
- **Purpose:** Group devices by logical categories for targeted policies and actions.
- **Steps to Create a Device Group:**
  - Navigate to **Settings** > **Endpoints** > **Device Groups**.
  - Click **Add** to create a new group, assign a name, and define membership rules.
  - Assign group members based on criteria (e.g., device OS, tags, etc.).
- **Best Practices:**
  - Use groups to apply specific policies (e.g., antivirus settings, detection rules).
  - Regularly review group memberships to ensure relevance.

**2. User Roles**
- **Purpose:** Manage access control to Defender for Endpoint features.
- **Key Roles:**
  - **Global Administrator:** Full access to all configurations and data.
  - **Security Administrator:** Access to security-related settings and policies.
  - **Security Reader:** View-only access to alerts, incidents, and reports.
- **Assigning Roles:**
  - Navigate to **Settings** > **Permissions** > **Roles**.
  - Select a role and assign users or groups.
- **Best Practices:**
  - Follow the principle of least privilege to minimize exposure.
  - Use predefined roles instead of creating custom roles unless absolutely necessary.

**3. Automation Levels**
- **Purpose:** Control the extent of automated actions Defender for Endpoint can take on detected threats.
- **Automation Levels:**
  - **None:** No automatic actions; manual remediation required.
  - **Limited:** Automatic actions for certain cases (e.g., quarantining files).
  - **Full:** Automated actions, including blocking threats and remediating issues.
- **Steps to Configure Automation Levels:**
  - Navigate to **Settings** > **Endpoints** > **Automated Investigation & Response**.
  - Choose the automation level: None, Limited, or Full.
  - Define which actions (quarantine, block, etc.) are allowed based on the level.
- **Best Practices:**
  - Set automation levels based on organization needs and risk tolerance.
  - Regularly review and adjust automation settings to balance security and operational impact.

📌 Source: 
- [Create and manage device groups in Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/machine-groups)
- [Create and manage roles for role-based access control](https://learn.microsoft.com/en-us/defender-endpoint/user-roles)
- [Automation levels in automated investigation and remediation](https://learn.microsoft.com/en-us/defender-endpoint/automation-levels)  

---
## Identify unmanaged devices in Microsoft Defender for Endpoint

**Purpose:** Detect devices connected to your network that are not protected by Defender for Endpoint.

**Discovery Methods:**
  - **Basic Discovery:**
    - Endpoints passively collect network events to extract device information without initiating network traffic.
    - Provides limited visibility of unmanaged devices.
  - **Standard Discovery (Recommended):**
    - Endpoints actively probe the network using multicast queries to enrich device data.
    - Offers a comprehensive and reliable device inventory.

**Device Inventory:**
  - Discovered devices are categorized based on their onboarding status:
    - **Onboarded:** Devices currently protected by Defender for Endpoint.
    - **Can be onboarded:** Devices identified as suitable for onboarding but not yet protected.
    - **Unsupported:** Devices not compatible with Defender for Endpoint.

**Recommended Actions:**
  - Onboard devices listed under "Can be onboarded" to enhance network security.
  - Regularly review and update device discovery settings to maintain an accurate inventory.
  
📌 Source: [Device discovery overview - Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/device-discovery)

---  
## Discover unprotected resources by using Defender for Cloud

**Purpose:** Identify and secure resources lacking adequate protection within your Azure environment.

**Key Components:**
  - **Azure Resource Manager (ARM):** Centralized management layer for deploying, managing, and organizing Azure resources.
  - **Azure Arc:** Extends Azure management capabilities to on-premises and multicloud environments, allowing consistent management of resources outside Azure.
  - **Microsoft Defender for Cloud:** Provides security posture management and threat protection across Azure, on-premises, and multicloud environments.

**Steps to Discover Unprotected Resources:**
  1. **Enable Defender for Cloud:**
     - Navigate to the Azure portal.
     - Go to **Microsoft Defender for Cloud** and enable it for your subscriptions.
  2. **Review Security Recommendations:**
     - In Defender for Cloud, access the **Recommendations** section.
     - Identify resources marked with security vulnerabilities or lacking protection.
  3. **Assess Secure Score:**
     - Monitor the **Secure Score** to evaluate your current security posture.
     - A higher score indicates better security practices; prioritize improving areas with lower scores.
  4. **Implement Remediation Steps:**
     - For each recommendation, select **Take action** and follow the guided remediation steps.
     - Apply security controls as advised to protect unprotected resources.

**Best Practices:**
  - **Regular Monitoring:** Consistently review Defender for Cloud dashboards to stay informed about security status.
  - **Automation:** Utilize automated workflows to remediate common security issues promptly.
  - **Integration:** Incorporate Defender for Cloud with Azure Arc to manage and secure resources across hybrid and multicloud environments.

📌 Source:
- [What is Azure Resource Manager? - Azure Resource Manager](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/overview)
- [Azure Arc overview - Azure Arc](https://learn.microsoft.com/en-us/azure/azure-arc/overview)
- [Microsoft Defender for Cloud Overview - Microsoft Defender for Cloud](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction)

---
## Identify and remediate devices at risk by using Microsoft Defender Vulnerability Management

**Purpose:** Detect, assess, and mitigate vulnerabilities across various devices to enhance organizational security.

**Key Features:**
  - **Continuous Asset Discovery and Monitoring:**
    - Utilizes built-in and agentless scanners for real-time monitoring, even for devices not connected to the corporate network.
    - Provides consolidated inventories of software applications, digital certificates, hardware, firmware, and browser extensions.
  - **Advanced Vulnerability and Configuration Assessment:**
    - Offers security baselines assessment against benchmarks like CIS and STIG.
    - Assesses software inventories, network share configurations, browser extensions, digital certificates, and hardware/firmware vulnerabilities.
  - **Risk-Based Intelligent Prioritization:**
    - Leverages Microsoft's threat intelligence and breach likelihood predictions to prioritize vulnerabilities.
    - Provides a unified view of prioritized recommendations with details such as related CVEs and affected devices.

**Remediation Process:**
  1. **Access Security Recommendations:**
     - Navigate to the Microsoft 365 Defender portal.
     - Select 'Vulnerabilities' under 'Threat & Vulnerability Management'.
  2. **Review and Prioritize:**
     - Examine the list of security recommendations.
     - Focus on high-risk vulnerabilities affecting critical assets.
  3. **Initiate Remediation:**
     - For each recommendation, choose 'Open ticket' to create a remediation task.
     - Assign tasks to the appropriate IT personnel or teams.
  4. **Monitor Progress:**
     - Track remediation activities and verify the implementation of security measures.

**Integration with Microsoft Intune:**
  - Integrate with Microsoft Intune to manage remediation tasks directly.
  - Security tasks from Defender are visible in the Intune admin center for action.
  - After remediation, update the task status to reflect completion.
  
📌 Source: [Microsoft Defender Vulnerability Management - Microsoft Defender Vulnerability Management](https://learn.microsoft.com/en-us/defender-vulnerability-management/defender-vulnerability-management)

---
## Mitigate risk by using Exposure Management in Microsoft Defender XDR

**Purpose:**  
  - Proactively identify and reduce security exposure by assessing risks and attack surfaces.

**Key Features:**  
  - **Attack Surface Visibility:** Provides real-time insight into exploitable attack vectors.  
  - **Risk-Based Prioritization:** Uses threat intelligence to rank risks based on exploitability and impact.  
  - **Proactive Security Planning:** Aligns security efforts with evolving attack techniques.  

**Core Components:**  
  1. **Continuous Exposure Assessment:**  
     - Identifies misconfigurations, vulnerable software, and potential attack paths.  
  2. **Threat Intelligence Integration:**  
     - Maps real-world attack data to internal security posture.  
  3. **Security Score and Insights:**  
     - Provides exposure scores to measure security posture improvements.  

**Mitigation Process:**  
  1. **Access Security Exposure Management:**  
     - Go to Microsoft 365 Defender > **Exposure Management** Dashboard.  
  2. **Analyze Exposure Score & Security Recommendations:**  
     - Review attack surface insights and recommended actions.  
  3. **Prioritize and Implement Fixes:**  
     - Apply security controls to high-risk areas first.  
  4. **Monitor and Improve Security Posture:**  
     - Continuously assess exposure levels and adapt defenses.  

**Benefits:**  
  - Reduces attack surface and enhances organizational resilience.  
  - Enables proactive security rather than reactive response.  

📌 Source: [What is Microsoft Security Exposure Management? - Microsoft Security Exposure Management](https://learn.microsoft.com/en-us/security-exposure-management/microsoft-security-exposure-management)

---
# Design and configure a Microsoft Sentinel workspace

## Plan a Microsoft Sentinel workspace

**Purpose:**  
  - Microsoft Sentinel is a cloud-native SIEM/SOAR solution for threat detection, investigation, and response.

**Key Planning Considerations:**  
  - **Log Analytics Workspace:** Sentinel requires an Azure Log Analytics workspace to store data.  
  - **Data Ingestion:** Connectors for Azure, Microsoft 365, and third-party sources.  
  - **Geolocation:** Choose a region for compliance, performance, and cost optimization.  
  - **Access Control:** Use Azure RBAC roles like **Reader**, **Responder**, and **Contributor**.  
  - **Retention & Costs:** Adjust data retention settings to balance cost and compliance.  

**Deployment Steps:**  
  1. **Create a Log Analytics Workspace:**  
     - In Azure Portal, go to **Log Analytics workspaces** > **Create workspace**.  
  2. **Enable Microsoft Sentinel:**  
     - In Azure Portal, search for **Microsoft Sentinel**, select workspace, and enable it.  
  3. **Connect Data Sources:**  
     - Add **Connectors** for logs (Azure, Office 365, Firewalls, Threat Intelligence, etc.).  
  4. **Configure Analytics Rules:**  
     - Define rules to detect threats using scheduled queries and machine learning.  
  5. **Set Up Automation & Response:**  
     - Use **Playbooks** (Azure Logic Apps) for automated incident response.  

**Best Practices:**  
  - Centralize Sentinel in a dedicated subscription for better management.  
  - Use multiple workspaces for multi-region or multi-tenant deployments.  
  - Optimize query performance and cost by fine-tuning log retention.  

📌 Source: [Deployment guide for Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/deploy-overview)

---
## Configure Microsoft Sentinel roles

**Purpose:**  
  - Microsoft Sentinel uses **Azure Role-Based Access Control (RBAC)** for access management.

**Built-in Roles:**  
  1. **Microsoft Sentinel Reader** – View incidents, logs, and rules but no modifications.  
  2. **Microsoft Sentinel Responder** – Investigate and update incidents but cannot modify analytics rules.  
  3. **Microsoft Sentinel Contributor** – Full access to manage Sentinel except workspace settings.  
  4. **Log Analytics Contributor** – Manage log analytics settings (needed for Sentinel configurations).  
  5. **Azure Owner, Contributor, and Reader** – Control workspace and resource permissions.  

**Role Assignment Steps:**  
  1. In **Azure Portal**, go to **Microsoft Sentinel**.  
  2. Select **Settings** > **Access control (IAM)**.  
  3. Click **Add role assignment**.  
  4. Choose a **role** (e.g., Sentinel Contributor).  
  5. Assign to **users, groups, or service principals**.  
  6. Click **Save**.  

**Best Practices:**  
  - **Principle of Least Privilege** – Assign only the necessary role for the task.  
  - **Use Azure AD Groups** – Simplifies role management.  
  - **Audit Role Changes** – Monitor role assignments via **Azure Monitor Logs**.  

📌 Source: [Roles and permissions in Microsoft Sentinel | Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/roles)

---
## Specify Azure RBAC roles for Microsoft Sentinel configuration

**Custom Roles & Advanced RBAC:**  
  - Microsoft Sentinel supports **custom roles** via Azure RBAC for granular access control.
  - Use **JSON role definitions** to specify permissions.

**Key Built-in Roles & Their Scope:**  
  1. **Microsoft Sentinel Contributor** – Full Sentinel management except workspace settings.  
  2. **Microsoft Sentinel Reader** – View-only access.  
  3. **Microsoft Sentinel Responder** – Manage incidents but cannot edit analytics rules.  

**Assigning a Custom Role:**
  1. Navigate to **Azure Portal** > **Microsoft Sentinel**.
  2. Open **Access Control (IAM)** > **Add Custom Role**.
  3. Upload the **JSON definition** or create manually.
  4. Assign to **users**, **groups**, or **service principals**.

**Best Practices:**
  - Follow **least privilege** principles.
  - Use **Azure AD groups** for role assignments.
  - Regularly **audit permissions** via **Azure Monitor Logs**.

📌 Source: [Roles and permissions in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/roles#custom-roles-and-advanced-azure-rbac)

---
## Design and configure Microsoft Sentinel data storage, including log types and log retention 

**Log Types in Microsoft Sentinel**
- **Azure Monitor Logs**: Centralized log collection in Log Analytics workspace.
- **Table Types**:
  - **Analytics Logs**: Security events, alerts, and audit logs.
  - **Basic Logs**: High-volume logs with limited query capabilities (cost-effective).
  - **Archive Logs**: Retained for long-term storage, accessed via search.

**Configuring Log Retention**
- **Retention Period**: Default **90 days**, configurable up to **730 days**.
- **Archive Retention**: Retain logs beyond retention period for **7 years max**.
- **Data Access**:
  - Analytics Logs → Fully queryable.
  - Archived Logs → Require **Search Jobs** to restore.

**Retention Configuration (Portal)**
1. Go to **Azure Monitor** > **Log Analytics workspaces**.
2. Select your **workspace**.
3. Navigate to **Usage and estimated costs** > **Data retention**.
4. Configure **default retention** or **per-table retention**.

**Best Practices**
- **Use Tiered Storage**:
  - **Short-term**: Analytics Logs.
  - **Mid-term**: Archive Logs for compliance.
  - **Long-term**: External storage (e.g., Azure Blob Storage).
- **Monitor Costs**: Adjust retention based on query frequency and compliance.
- **Security Considerations**:
  - Implement **role-based access control (RBAC)**.
  - Enable **Immutable Storage** for compliance.

📌 Source: [Roles and permissions in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-retention-configure?toc=%2Fazure%2Fsentinel%2FTOC.json&bc=%2Fazure%2Fsentinel%2Fbreadcrumb%2Ftoc.json&tabs=portal-3%2Cportal-1%2Cportal-2)

--- 
# Ingest data sources in Microsoft Sentinel

## Identify data sources to be ingested for Microsoft Sentinel

**Built-in Data Connectors**
- **Microsoft Services**: Real-time integration with services like Office 365, Microsoft Entra ID, Microsoft Defender for Identity, and Microsoft Defender for Cloud Apps. 
- **Third-Party Products**: Connect using Syslog, Common Event Format (CEF), or REST APIs. 

**Agent-Based Integration**
- **Azure Monitor Agent (AMA)**: Collects data from any source capable of real-time log streaming, especially on-premises data sources. 
- **Syslog and CEF**: Stream events from Linux-based, Syslog-supporting devices using AMA. 

**Custom Data Connectors**
- **Codeless Connector Platform**: Configure data source APIs without coding. 
- **Log Ingestion API**: Use with Azure Functions or Logic Apps for custom integrations. 
- **Logstash**: Utilize the Logstash output plugin for Microsoft Sentinel to create custom connectors. 

**Free Data Sources**
- **Azure Activity Logs**: No ingestion charges. 
- **Office 365 Audit Logs**: Includes SharePoint activity, Exchange admin activity, and Teams. 
- **Security Alerts**: From services like Microsoft Defender for Cloud, Microsoft 365 Defender, and Microsoft Defender for Endpoint. 

**Best Practices**
- **Assess Data Sources**: Identify relevant sources to monitor security events effectively.
- **Utilize Built-in Connectors**: Leverage existing connectors for seamless integration.
- **Implement Custom Connectors**: Develop custom integrations when necessary.
- **Monitor Ingestion Costs**: Be aware of which data sources are free and which incur charges. 

📌 Source: [Microsoft Sentinel data connectors](https://learn.microsoft.com/en-us/azure/sentinel/connect-data-sources?tabs=azure-portal)

---
## Implement and use Content hub solutions

**Overview:**
- The Microsoft Sentinel Content Hub is a centralized platform to discover, deploy, and manage out-of-the-box (OOTB) security content, including solutions tailored for specific products, domains, or industries. 

**Key Concepts:**
- **Solutions:** Packaged integrations delivering end-to-end value, encompassing data connectors, workbooks, analytics rules, playbooks, and more.
- **Standalone Content:** Individual components like analytics rules or workbooks that can be deployed separately.

**Best Practices:**
- **Discovery:** Utilize the Content Hub's filtering and search capabilities to find relevant solutions or content items.
- **Installation:** Ensure you have the Microsoft Sentinel Contributor role at the resource group level to install or update content.
- **Management:** Regularly check for updates to installed solutions and apply them to maintain optimal functionality.
- **Customization:** Tailor deployed content to align with your organization's specific security requirements.

**Steps to Implement a Solution:**
1. **Access Content Hub:**
   - Navigate to Microsoft Sentinel in the Azure portal.
   - Select 'Content Management' > 'Content Hub'.
2. **Discover Solutions:**
   - Use filters or search to locate desired solutions.
3. **Install Solution:**
   - Select the solution and click 'Install/Update'.
   - Follow on-screen prompts to complete the installation.
4. **Configure Data Connectors:**
   - Post-installation, set up associated data connectors to start data ingestion.
5. **Monitor and Update:**
   - Regularly monitor the Content Hub for updates to installed solutions and apply them as needed.

📌 Source: [Discover and deploy Microsoft Sentinel out-of-the-box content from Content hub](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-deploy?tabs=azure-portal)

---
## Configure and use Microsoft connectors for Azure resources, including Azure Policy and diagnostic settings

**Overview:**
- **Microsoft Sentinel** integrates with Azure resources through connectors to collect and analyze data.

**Key Connector Types:**
1. **Diagnostic Settings-Based Connectors:**
   - **Standalone Connections:**
     - **Purpose:** Collect logs and metrics from Azure resources.
     - **Configuration Steps:**
       1. Navigate to the desired Azure resource.
       2. Select **Diagnostic settings**.
       3. Add a new diagnostic setting, specifying Microsoft Sentinel as the destination.
   - **Policy-Managed Connections:**
     - **Purpose:** Apply diagnostic settings across multiple resources using Azure Policy.
     - **Configuration Steps:**
       1. Create a custom policy definition to enable diagnostic settings for specific resource types.
       2. Assign the policy to the appropriate scope (e.g., subscription, resource group).
       3. Monitor compliance and ensure logs are sent to Microsoft Sentinel.

**Best Practices:**
- **Role-Based Access Control (RBAC):** Assign appropriate roles to users managing connectors to ensure proper permissions.
- **Regular Audits:** Periodically review connector configurations and data flow to maintain security and compliance.
- **Documentation:** Keep detailed records of connector setups for troubleshooting and auditing purposes.

📌 Source: [Connect Microsoft Sentinel to Azure, Windows, and Microsoft services](
https://learn.microsoft.com/en-us/azure/sentinel/connect-azure-windows-microsoft-services)

---
## Plan and configure Syslog and Common Event Format (CEF) event collections

**Overview:**
- **Syslog** and **CEF** are two event formats used to collect logs from devices and applications for monitoring and analysis in Microsoft Sentinel.
- **Syslog** is a standard for transmitting log messages over a network.
- **CEF** is a log format used by many security devices to provide structured event data.

**Steps for Configuration:**
1. **Syslog Configuration:**
   - **Set up Syslog Forwarding:**
     - Configure Syslog servers to forward logs to Microsoft Sentinel.
     - Enable **Syslog collection** in Microsoft Sentinel's data connectors.
     - Use the **Linux agent** to forward Syslog messages to Sentinel.
   - **Ensure Firewall Access:** 
     - Open necessary ports (UDP 514 by default) for communication between devices and Microsoft Sentinel.
   
2. **CEF Configuration:**
   - **Set up CEF Forwarding:**
     - Configure CEF-compliant devices to forward logs to a collector (e.g., using the **CEF agent** or **Syslog agent**).
     - Enable **CEF connector** in Microsoft Sentinel to receive logs from CEF devices.
   
**Best Practices:**
- **Log Retention:** 
   - Define retention policies to ensure logs are stored according to compliance requirements.
- **Time Synchronization:** 
   - Ensure **time sync** across devices for accurate log timestamps.
- **Secure Communication:** 
   - Use encryption (e.g., TLS) to protect log data in transit.
- **Regular Monitoring:** 
   - Continuously monitor logs for critical events and incidents.

**Additional Information:**
- **AMA Agent**: The **Azure Monitor Agent (AMA)** collects both Syslog and CEF data.
- **Data Connectors:** Set up the relevant connectors in Microsoft Sentinel to ingest Syslog and CEF logs.
- **Use Case**: CEF is ideal for security devices (e.g., firewalls, intrusion detection systems), while Syslog is often used by network devices and Linux-based systems.

📌 Source: [Syslog and CEF AMA connectors - Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/cef-syslog-ama-overview?tabs=forwarder)

---
## Plan and configure collection of Windows Security events by using data collection rules, including Windows Event Forwarding (WEF)

**Overview:**
- **Windows Security Events** can be collected using **Azure Monitor Agent (AMA)** and **Windows Event Forwarding (WEF)** to enhance security monitoring in Microsoft Sentinel.
- **Data Collection Rules (DCRs)** help manage and configure log data collection for Sentinel.

**Steps for Configuration:**
1. **Data Collection Rules (DCRs):**
   - Create **DCRs** to define which logs to collect (e.g., Windows Security events).
   - Use the **Azure Monitor Agent** to deploy DCRs for Windows machines.
   - Configure DCRs for event filtering, routing, and data transformation.
   
2. **Windows Event Forwarding (WEF):**
   - Configure **Windows Event Forwarding** on Windows servers to forward event logs to a collector server.
   - Set up **Event Collector** to aggregate events from multiple Windows machines.
   - Use **Event Subscription** to define which events to forward from target devices.
   
**Key Concepts:**
- **Windows Security Events** (Event ID 4624, 4634, etc.) provide critical information about user logins, privilege usage, and other security-related events.
- **AMA Agent** is used for collecting logs in a more efficient and scalable way compared to legacy agents like the **OMS Agent**.
- **Forwarded Events Log** stores events forwarded via WEF to the collector.

**Best Practices:**
- **Log Retention:** Define retention policies for event logs according to compliance and security requirements.
- **Secure Forwarding:** Use encrypted communication channels to forward logs securely.
- **Minimal Event Collection:** Filter and forward only necessary security events to optimize storage and analysis.
- **Monitoring and Alerts:** Set up monitoring and alerts for key event types (e.g., logon failures, privilege escalations).

**Additional Information:**
- Ensure **time synchronization** across Windows devices for accurate event timestamps.
- Use **DCRs** to ensure only relevant data is collected, avoiding unnecessary data overhead.

📌 Source: [Windows Security Events via AMA connector for Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors/windows-security-events-via-ama)

---
## Create custom log tables in the workspace to store ingested data

**Overview:**
- **Custom Log Tables** in Sentinel allow you to store data from non-standard or custom data sources.
- Use **Custom Data Connectors** to ingest data from specific log sources, then configure custom tables to store the data.

**Steps for Creating Custom Log Tables:**
1. **Define Log Format:**
   - Identify the log format and structure (e.g., Syslog, CEF, or custom formats).
2. **Ingest Data:**
   - Use **Custom Data Connectors** (e.g., via **rsyslog** or **syslog-ng**) to forward data into Sentinel.
   - Ensure the data is structured for the custom table format (fields, types, etc.).
3. **Create Custom Log Table:**
   - In **Kusto Query Language (KQL)**, define the **custom log table schema**. For example:
     ******kusto
     .create table CustomLogs (timestamp: datetime, event_id: string, log_message: string)
     ******
   - Specify columns, types, and data structure.
4. **Map Ingested Data to Table:**
   - Use **ingestion-time transformation** to map fields from the ingested data into the custom table schema.
5. **Validate and Test:**
   - After ingestion, validate data is correctly populated into the custom table.
   - Use **KQL queries** to ensure the integrity and structure of the logs.

**Best Practices:**
- **Log Schema Design:** Design log tables with well-defined schemas that align with the data structure.
- **Field Mapping:** Make sure the ingestion process correctly maps fields to the custom table columns.
- **Data Retention:** Define retention policies for custom logs to manage storage costs and compliance.
- **Performance Optimization:** Consider partitioning large tables to optimize query performance.

**Tools:**
- **KQL** for querying custom logs.
- **Log Analytics Workspace** to manage custom tables and connectors.

📌 Source: [Custom Logs via AMA data connector - Configure data ingestion to Microsoft Sentinel from specific applications](https://learn.microsoft.com/en-us/azure/sentinel/unified-connector-custom-device?tabs=rsyslog)

---
## Monitor and optimize data ingestion

**Overview:**
- Data ingestion in Microsoft Sentinel can be monitored and optimized using transformation rules and monitoring tools.
- **Optimization** involves improving data flow, ensuring efficiency, and managing costs.

**Steps for Monitoring Data Ingestion:**
1. **Monitor Ingestion Status:**
   - Use **Log Analytics workspace** to check data ingestion status.
   - Review data connector **health**, and ensure logs are flowing correctly.
2. **Use Data Ingestion Logs:**
   - Ingest **Data Connector logs** to monitor and verify the ingestion process.
   - Track logs related to data collection failures or issues.
3. **Set Up Alerts:**
   - Create **alerts** for data ingestion anomalies (e.g., high error rates).
   - Use built-in **Health Check queries** to identify data ingestion issues.

**Optimization Techniques:**
1. **Optimize Data Transformation:**
   - Use **data transformation rules** to clean, enrich, and map data before ingestion.
   - Apply **custom parsing** for non-standard formats like Syslog or CEF.
2. **Limit Ingestion Volume:**
   - Filter and transform data at the source to prevent ingesting unnecessary logs.
   - Use **ingestion time transformation** to reduce data volume.
3. **Partitioning Large Tables:**
   - Implement **table partitioning** for large datasets to enhance query performance.
4. **Data Retention Policies:**
   - Set **retention rules** to manage how long data stays in Sentinel.
   - Regularly assess data retention to balance between cost and data access.

**Best Practices:**
- Monitor **ingestion throughput** and resource usage to avoid bottlenecks.
- Use **ingestion-time transformations** to clean data before it reaches the workspace.
- Regularly check **data connector status** to ensure no issues with data ingestion.

📌 Source: [Custom data ingestion and transformation in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/data-transformation)

---

If you find this guide helpful and want to support my work, you can buy me a coffee ☕️!

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-Support%20My%20Work-orange)](https://buymeacoffee.com/404future)
