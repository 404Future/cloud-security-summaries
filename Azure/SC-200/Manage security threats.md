# Hunt for threats by using Microsoft Defender XDR

## Identify threats by using Kusto Query Language (KQL)

**Overview**
- Kusto Query Language (KQL) is a powerful tool developed by Microsoft for querying large datasets, particularly in security contexts. It's extensively used in platforms like Microsoft Sentinel to analyze logs and detect potential threats. 

**Key Concepts**
- **Kusto Query**: A read-only request to process data and return results, expressed in plain text using a data-flow model. 
- **Data Organization**: Data is structured hierarchically into databases, tables, and columns, similar to SQL. 

**Essential KQL Commands for Threat Detection**
- **`where`**: Filters records based on specified conditions.
- **`project`**: Selects specific columns to include in the output.
- **`summarize`**: Aggregates data (e.g., counts, averages) over specified columns.
- **`join`**: Combines records from two tables based on a related column.
- **`extend`**: Adds calculated columns to each record.

**Best Practices for Threat Identification**
1. **Understand Your Data Sources**:
   - Familiarize yourself with the schema and types of logs available in your environment.
2. **Develop Baseline Queries**:
   - Create standard queries to establish normal behavior patterns.
3. **Identify Anomalies**:
   - Use KQL functions to detect deviations from established baselines.
4. **Leverage Community Resources**:
   - Utilize existing KQL queries and detection rules from reputable sources to enhance your threat-hunting capabilities. 
5. **Continuous Learning**:
   - Engage with advanced KQL training and resources to refine your threat detection skills. 

📌 Source: [Kusto Query Language overview](https://learn.microsoft.com/en-us/kusto/query/?view=microsoft-fabric)

---
## Interpret threat analytics in the Microsoft Defender portal

**Overview**
- Threat analytics in Microsoft Defender XDR provides in-product threat intelligence from Microsoft's security researchers, aiding security teams in identifying and responding to emerging threats. 

**Accessing Threat Analytics**
- **Navigation**:
  - Access via the upper left-hand side of the Microsoft Defender portal's navigation bar or through a dedicated dashboard card displaying top organizational threats. 

**Key Components of Threat Analytics**
- **Dashboard Sections**:
  - **Latest Threats**: Displays recently published or updated threat reports with active and resolved alert counts.
  - **High-Impact Threats**: Lists threats with the highest impact based on active and resolved alerts.
  - **Highest Exposure Threats**: Identifies threats to which the organization has the highest exposure, considering vulnerability severity and the number of exploitable devices. 
- **Individual Threat Reports**:
  - **Analyst Report**: Provides analysis of the threat, including attack techniques and actor profiles.
  - **Incidents and Alerts**: Details related incidents and alerts within the organization.
  - **Impacted Assets**: Lists devices and users affected by the threat.
  - **Exposures and Mitigations**: Highlights vulnerabilities and recommended actions to mitigate the threat. 

**Best Practices for Interpreting Threat Analytics**
- **Regular Monitoring**:
  - Consistently review the threat analytics dashboard to stay informed about emerging threats and organizational exposure.
- **Prioritize High-Impact Threats**:
  - Focus on threats listed under 'High-Impact Threats' to address the most pressing issues promptly.
- **Implement Recommended Actions**:
  - Follow the mitigation steps provided in the 'Exposures and Mitigations' section to enhance security posture.
- **Collaborate Across Teams**:
  - Share insights from threat analytics with relevant teams to ensure a unified and effective response.

📌 Source: [Threat analytics in Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/threat-analytics)

---
## Create custom hunting queries by using KQL

**Overview**
- Custom hunting queries in Microsoft Defender XDR enable proactive threat detection by leveraging Kusto Query Language (KQL) to analyze extensive datasets.

**Key Concepts**
- **Kusto Query Language (KQL)**: A powerful language used for querying large datasets, enabling pattern discovery, anomaly detection, and statistical modeling. 
- **Advanced Hunting**: A feature that allows exploration of up to 30 days of raw data to identify potential threats using KQL. 

**Creating Custom Hunting Queries**
1. **Access Advanced Hunting**:
   - Navigate to the Microsoft Defender portal.
   - Select **Advanced hunting** from the navigation pane.
2. **Develop Your Query**:
   - Use KQL to construct queries targeting specific threat indicators.
   - Utilize operators and functions to refine search results. 
   - Test queries to validate accuracy and efficiency.
3. **Optimize Performance**:
   - Be mindful of CPU resource quotas to ensure efficient query execution. 
   - Aim for queries that return relevant results without excessive resource consumption.
4. **Save and Reuse Queries**:
   - Save frequently used queries for consistent threat monitoring.
   - Consider creating custom functions for reusable query logic. 

**Best Practices**
- **Understand Data Schema**: Familiarize yourself with the data tables and their relationships within Microsoft Defender XDR to write effective queries.
- **Use the Query Builder**: For those less familiar with KQL, the guided query builder assists in crafting queries without deep knowledge of the language. 
- **Regularly Review and Refine Queries**: Continuously assess and adjust queries to adapt to evolving threat landscapes and organizational changes.

📌 Source: [Create and manage custom detections rules](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules)

---
# Hunt for threats by using Microsoft Sentinel

## Analyze attack vector coverage by using the MITRE ATT&CK matrix

**Overview**
- The MITRE ATT&CK framework provides a comprehensive model of adversary tactics and techniques, aiding organizations in assessing and enhancing their security posture. Microsoft Sentinel integrates this framework to visualize and analyze detection coverage across various attack vectors.

**Key Concepts**
- **MITRE ATT&CK Framework**: A knowledge base detailing adversary behaviors based on real-world observations, structured into tactics (goals) and techniques (methods).
- **Microsoft Sentinel**: A cloud-native SIEM solution that provides intelligent security analytics and threat intelligence across enterprise environments.

**Analyzing Coverage in Microsoft Sentinel**
1. **Access MITRE Coverage Matrix**:
   - In the Azure portal, navigate to **Microsoft Sentinel**.
   - Under **Threat management**, select **MITRE ATT&CK (Preview)**. 
2. **Review Active Detections**:
   - The matrix displays active scheduled query and near real-time (NRT) rules.
   - Use the legend to interpret the number of active detections per technique.
3. **Assess Simulated Coverage**:
   - Simulated coverage indicates detections available but not yet configured.
   - Toggle the **View MITRE by threat scenario** option to simulate coverage based on different scenarios. 
4. **Drill Down into Techniques**:
   - Select a technique in the matrix to view details, including:
     - **Description**: Overview of the technique.
     - **Active Items**: Links to associated analytics rules, hunting queries, and incidents.
   - Utilize these links to manage and configure detections effectively. 

**Best Practices**
- **Regularly Update Detections**: Ensure that analytics rules and NRT rules align with the latest MITRE techniques to maintain comprehensive coverage.
- **Prioritize Coverage Gaps**: Identify techniques with limited or no coverage and prioritize implementing relevant detections.
- **Utilize Threat Scenarios**: Use simulated coverage to evaluate potential security posture under various threat scenarios.

📌 Source: [Understand security coverage by the MITRE ATT&CK® framework](https://learn.microsoft.com/en-us/azure/sentinel/mitre-coverage?tabs=azure-portal)

---
## Manage and use threat indicators

**Overview**
- Microsoft Sentinel enables the integration, management, and utilization of threat intelligence to enhance security operations.

**Key Concepts**
- **Threat Indicators**: Data points such as IP addresses, domain names, URLs, or file hashes that signify potential security threats.
- **STIX Objects**: Structured Threat Information Expression (STIX) is a standardized language for describing cyber threat information.

**Managing Threat Indicators**
1. **Access Threat Intelligence Management**:
   - In the **Defender portal**: Navigate to **Threat intelligence > Intel management**.
   - In the **Azure portal**: Go to **Threat management > Threat intelligence**.
2. **Create a New STIX Object**:
   - Select **Add new > TI object**.
   - Choose the object type (e.g., Indicator, Malware).
   - Fill in required fields (marked with a red asterisk).
   - Define relationships to other objects if applicable.
   - Click **Add** to create the object.
3. **Manage Threat Intelligence**:
   - Use ingestion rules to filter and modify incoming threat intelligence.
   - Utilize the relationship builder to define connections between objects.
   - Search, filter, and sort indicators; add tags for better organization.

**Utilizing Threat Indicators**
- **In Analytics Rules**:
  - Incorporate threat indicators into analytics rules to generate alerts based on integrated threat intelligence.
- **In Advanced Hunting**:
  - Use Kusto Query Language (KQL) to query the `ThreatIntelligenceIndicator` table for custom threat intelligence analysis.

**Best Practices**
- **Regularly Update Indicators**: Ensure threat indicators are current to maintain effective detection capabilities.
- **Curate Intelligence**: Use tagging and relationships to organize and contextualize threat data.
- **Integrate with Other Tools**: Connect Microsoft Sentinel with Threat Intelligence Platforms (TIPs) to enrich threat data.

📌 Source: [Work with Microsoft Sentinel threat intelligence](https://learn.microsoft.com/en-us/azure/sentinel/work-with-threat-indicators?tabs=defender-portal)

---
## Create and manage hunts

**Overview**
- Microsoft Sentinel's hunting capabilities allow security analysts to proactively search for and investigate potential threats across organizational data sources.

**Creating a New Hunt**
1. **Access Hunting Queries**:
   - Navigate to **Hunting > Queries** in Microsoft Sentinel.
2. **Run Existing Queries**:
   - Select **Run All queries** to execute all available hunting queries.
   - Use filters to refine results based on specific criteria.
3. **Create a Custom Hunting Query**:
   - In the **Queries** tab, click **New query**.
   - Enter your Kusto Query Language (KQL) query in the editor.
   - Optionally, provide a description and set relevant entity mappings.
   - Click **Create** to save the query.

**Managing Hunts**
- **Edit an Existing Query**:
  - In the **Queries** tab, select the desired query.
  - Click the ellipsis (...) and choose **Edit**.
  - Modify the query as needed and click **Save**.
- **Clone a Query**:
  - Select the query to duplicate.
  - Click the ellipsis (...) and select **Clone**.
  - Adjust the cloned query's details and click **Create**.

**Utilizing Hunts**
- **Livestream Sessions**:
  - Create a livestream session from a query to monitor real-time data.
  - In the **Queries** tab, right-click a query and select **Add to livestream**.
  - Alternatively, in the **Livestream** tab, click **+ New livestream** to start a new session.

**Best Practices**
- **Define Clear Hypotheses**: Base hunts on specific hypotheses, such as suspicious behaviors or new threat campaigns, to focus investigations effectively.
- **Use Bookmarks**: During hunts, use bookmarks to mark significant findings for further analysis or follow-up.
- **Collaborate and Document**: Utilize comments within hunts to document observations and collaborate with team members.
- **Act on Findings**: Translate hunting results into actionable items like creating new analytics rules, incidents, or threat intelligence indicators.

📌 Source: [Conduct end-to-end proactive threat hunting in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/hunts)

---
## Create and monitor hunting queries

**Overview**
- Microsoft Sentinel enables proactive threat hunting through customizable queries, allowing analysts to identify and investigate potential security threats within their environment.

**Creating Hunting Queries**
1. **Access Hunting Queries**:
   - Navigate to **Hunting > Queries** in Microsoft Sentinel.
2. **Create a New Query**:
   - Click **New query**.
   - Enter your Kusto Query Language (KQL) query in the editor.
   - Optionally, provide a description and set relevant entity mappings.
   - Click **Create** to save the query.

**Monitoring Hunting Queries**
- **Run Queries**:
  - In the **Queries** tab, select queries and click **Run** to execute them.
- **Analyze Results**:
  - Review query results to identify potential threats.
  - Use filters and sorting options to refine results based on criteria such as data source, MITRE ATT&CK tactic, or technique.
- **Livestream Sessions**:
  - Create interactive sessions to monitor query results in real-time.
  - In the **Queries** tab, right-click a query and select **Add to livestream**.
  - Alternatively, in the **Livestream** tab, click **+ New livestream** to start a new session.
  - Select **Play** to begin the session and **Save** to preserve it for future reference.

**Best Practices**
- **Define Clear Hypotheses**: Base hunts on specific hypotheses to focus investigations effectively.
- **Use Bookmarks**: During hunts, use bookmarks to mark significant findings for further analysis.
- **Collaborate and Document**: Utilize comments within hunts to document observations and collaborate with team members.
- **Act on Findings**: Translate hunting results into actionable items like creating new analytics rules or incidents.

📌 Source: [Detect threats by using hunting livestream in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/livestream)

---
## Use hunting bookmarks for data investigations

**Overview**
- Hunting bookmarks in Microsoft Sentinel allow analysts to preserve relevant queries and results, annotate findings, and collaborate effectively.

**Creating Bookmarks**
1. **Navigate to Hunting**:
   - In the Azure portal: Go to **Threat management > Hunting**.
   - In the Defender portal: Select **Microsoft Sentinel > Threat management > Hunting**.
2. **Select and Run a Query**:
   - Choose a hunt and select a hunting query.
   - Click **Run Query**, then **View query results** to open the Logs pane.
3. **Add a Bookmark**:
   - In the query results, select desired rows using checkboxes.
   - Click **Add bookmark**.
   - In the **Add bookmark** pane:
     - Optionally, update the bookmark name, add tags, and notes.
     - Map MITRE ATT&CK tactics and techniques if applicable.
     - Map entities by selecting types and identifiers.
   - Click **Save** to create the bookmark.

**Managing and Investigating Bookmarks**
- **View and Update Bookmarks**:
  - In the **Bookmarks** tab, search or filter to find specific bookmarks.
  - Select a bookmark to view or edit details in the right-hand pane.
- **Investigate Bookmarks**:
  - Select bookmarks and click **Investigate** to launch the investigation graph.
  - Ensure at least one entity is mapped to utilize the investigation graph effectively.
- **Add Bookmarks to Incidents**:
  - Select bookmarks and click **Incident actions**.
  - Choose **Create new incident** or **Add to existing incident**.
  - Fill in incident details and click **Create** or **Add**.
  - View bookmarks within incidents via the **Bookmarks** section.

**Best Practices**
- **Collaborative Analysis**: Share bookmarks with team members to enhance collaborative investigations.
- **Organize Findings**: Use tags and notes to categorize and document observations effectively.
- **Utilize Investigation Graph**: Visualize relationships between entities to deepen analysis.

📌 Source: [Keep track of data during hunting with Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/bookmarks)

---
## Retrieve and manage archived log data

**Overview**
- Microsoft Sentinel allows restoration of archived log data for high-performance queries using Kusto Query Language (KQL).

**Restoring Archived Log Data**
1. **Access Search**:
   - In Microsoft Sentinel, select **Search**.
2. **Restore Data**:
   - **Option A**: Click **Restore** at the top. In the Restoration pane, select the table and time range, then click **Restore**.
   - **Option B**: Go to **Saved searches**, find desired search results, click **Restore**. For multiple tables, select one, then click **Actions > Restore**.
3. **Monitor Restoration**:
   - Check the **Restoration** tab for job status.

**Viewing and Managing Restored Data**
- **View Data**:
  - After restoration, access data in the Logs query page (Azure portal) or Advanced hunting page (Defender portal).
- **Delete Restored Tables**:
  - In the **Restoration** tab, identify the table, click **Delete** to remove it.

**Best Practices**
- **Data Retention Planning**: Configure interactive and long-term data retention to balance performance and storage costs.
- **Regular Monitoring**: Consistently monitor the status of restoration jobs to ensure timely access to data.

📌 Source: [Restore archived logs from search](https://learn.microsoft.com/en-us/azure/sentinel/restore)

---
## Create and manage search jobs

**Overview**
- Search jobs in Microsoft Sentinel enable efficient searches across extensive datasets over extended periods, facilitating in-depth investigations without impacting system performance.

**Creating a Search Job**
1. **Access Search**:
   - In the Azure portal: Navigate to **Microsoft Sentinel > General > Search**.
   - In the Defender portal: Go to **Microsoft Sentinel > Search**.
2. **Select Data Table**:
   - Click the **Table** menu and choose the appropriate table for your search.
3. **Define Search Criteria**:
   - Enter your search term in the **Search** box.
   - Click **Start** to open the Kusto Query Language (KQL) editor and preview results.
4. **Refine and Run Search**:
   - Modify the KQL query as needed.
   - Click **Run** to update the preview.
5. **Initiate Search Job**:
   - Once satisfied, click the ellipsis (**...**) and toggle **Search job mode** on.
   - Set the desired time range.
   - Click **Search job**.
   - Provide a new table name for storing results.
   - Click **Run a search job**.

**Managing Search Jobs**
- **Monitor Status**:
  - Navigate to the **Saved Searches** tab to view search job statuses.
- **View Results**:
  - Click **View search results** on the desired search card.
  - Use **Add filter** to refine results.
- **Bookmark Entries**:
  - Select rows and click **Add bookmark** or use the bookmark icon.
  - Bookmarks allow tagging, note-taking, and associating events with incidents.
- **Customize View**:
  - Click **Columns** to select additional columns for display.
  - Apply the **Bookmarked** filter to view only bookmarked entries.
  - Select **View all bookmarks** to manage bookmarks on the Hunting page.

**Best Practices**
- **Efficient Search Planning**: Define precise time ranges and search criteria to optimize performance.
- **Regular Monitoring**: Check the status of search jobs to ensure timely completion.
- **Effective Bookmarking**: Utilize bookmarks to document findings and facilitate collaboration.

📌 Source: [Search across long time spans in large datasets](https://learn.microsoft.com/en-us/azure/sentinel/search-jobs?tabs=azure-portal)

---
# Create and configure Microsoft Sentinel workbooks

## Activate and customize workbook templates

**Creating and Customizing Workbook Templates**
- **Access Templates**: In Microsoft Sentinel > Threat Management > Workbooks > Templates.
- **Save Template**: Select "Save" in template details and choose storage location.
- **Edit Workbook**: Click "Edit" in workbook toolbar to modify elements like time ranges or add new sections.
- **Clone Workbook**: Use "Save as" to create a duplicate under the same subscription/resource group.
- **Save Changes**: Save modifications to the workbook after editing.
- **Workbooks Usage**: Customize based on persona (e.g., network admin) or frequency of use.

📌 Source: [Visualize and monitor your data by using workbooks in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/monitor-your-data?tabs=azure-portal#create-a-workbook-from-a-template)

---
## Create custom workbooks that include KQL

**Create Custom Workbooks with KQL in Microsoft Sentinel**
- **Add Workbook**: Navigate to Sentinel > Workbooks > Add Workbook.
- **Data Source**: Set to 'Logs' and use Log Analytics workspace.
- **Query Customization**: Use KQL queries to pull data (e.g., `SecurityEvent | where TimeGenerated > ago(7d)`).
- **Parameters**: Add filters for interactivity (e.g., time range).
- **Save Workbook**: Choose 'My Reports' for personal use, or 'Shared Reports' for organizational use.
- **Visualize Data**: Use tiles to display query results in a customizable format.

📌 Source: [Visualize and monitor your data by using workbooks in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/monitor-your-data?tabs=azure-portal#create-new-workbook)

---
## Configure visualizations

**Overview**
  - Microsoft Sentinel utilizes workbooks to visualize and monitor data from connected sources. Workbooks, based on Azure Monitor workbooks, allow for the creation of custom dashboards and reports. 

**Prerequisites**
  - Ensure you have at least Workbook Reader or Workbook Contributor permissions on the resource group containing the Microsoft Sentinel workspace.

**Creating a Workbook from a Template**
  1. Navigate to **Workbooks** under the **Threat management** section in Microsoft Sentinel.
  2. Select the **Templates** tab to view available workbook templates.
  3. Choose a template relevant to your data sources.
  4. Click **Save** to create an Azure resource based on the template.
  5. Select **View saved workbook** to open and customize the workbook as needed.

**Creating a New Workbook**
  1. In Microsoft Sentinel, go to **Workbooks** under **Threat management**.
  2. Click **Add workbook** to start a new workbook.
  3. Select **Edit** to add text, queries, and parameters.
  4. For queries:
     - Set **Data source** to **Logs**.
     - Set **Resource type** to **Log Analytics**.
     - Choose the appropriate workspaces.
  5. After customization, click **Save** to store the workbook. 

**Best Practices**
  - Regularly review and update workbooks to reflect changes in data sources and organizational needs.
  - Utilize role-based access control (RBAC) to manage permissions and ensure appropriate access to workbooks. 

📌 Source: [Visualize and monitor your data by using workbooks in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/monitor-your-data?tabs=azure-portal)

---

If you find this guide helpful and want to support my work, you can buy me a coffee ☕️!

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-Support%20My%20Work-orange)](https://buymeacoffee.com/404future)
