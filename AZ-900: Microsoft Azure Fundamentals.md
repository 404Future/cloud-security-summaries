# Cloud Computing Concepts

## Describe Cloud Computing
### Define Cloud Computing
Cloud computing is the delivery of computing services over the internet. These services include virtual machines, storage, databases, and networking. Cloud computing also supports emerging technologies such as:
- Internet of Things (IoT)
- Machine Learning (ML)
- Artificial Intelligence (AI)

## Describe the Shared Responsibility Model
In the shared responsibility model, responsibilities are divided between the cloud provider and the customer.
- The cloud provider manages physical infrastructure, networking, and hardware.
- The customer is responsible for data, identities, and application-level security.
The level of responsibility varies depending on the cloud service type (SaaS, PaaS, IaaS).

![Shared Resp  model](https://github.com/user-attachments/assets/ab974150-3e58-4c13-8818-1f459bef7f68)

## Define Cloud Models and Identify Appropriate Use Cases for Each Cloud Model
### Public Cloud:
- No capital expenditures (CapEx) required to scale up.
- Applications can be quickly provisioned and deprovisioned.
- Organizations pay only for what they use.
- Less control over security and infrastructure.
**Best for**: Startups, web apps, testing environments.

### Private Cloud:
- Organizations have complete control over their resources and security.
- Data is isolated from other organizations.
- Requires hardware investment for setup and maintenance.
- Organizations are responsible for hardware maintenance and updates.
**Best for**: Financial institutions, government agencies, industries with strict compliance requirements.

### Hybrid Cloud:
- Combines public and private clouds for greater flexibility.
- Organizations decide where to run applications.
- Provides better control over security, compliance, and regulations.
**Best for**: Businesses needing both scalability and security, enterprises with sensitive workloads.

### Multi-cloud:
- Uses multiple cloud providers to avoid vendor lock-in.
- Enhances resilience and performance.
- **Azure Arc**: Helps manage hybrid and multi-cloud environments.
- **Azure VMware Solution**: Enables VMware workloads to run in Azure with seamless integration.

## Describe the Consumption-Based Model
### Two Types of IT Expenses:
- **Capital Expenditure (CapEx)**: One-time, upfront investment (e.g., purchasing hardware, building a data center).
- **Operational Expenditure (OpEx)**: Spending money on services or products over time.
Cloud computing operates on an OpEx model using a consumption-based pricing approach.

### Benefits of OpEx in Cloud Computing:
- No upfront costs.
- No need to purchase and manage physical infrastructure.
- Pay only for the resources you use.
- Scale resources up or down as needed.

## Compare Cloud Pricing Models
Cloud computing follows a pay-as-you-go pricing model. Billing is based on actual usage, rather than fixed infrastructure costs.

## Describe Serverless
Serverless computing allows developers to run code without managing servers. The cloud provider automatically handles scaling, maintenance, and availability.

**Example**: Azure Functions executes code in response to events, without requiring dedicated infrastructure.  
**Best for**: Event-driven applications, microservices, automation tasks.

## Describe the Benefits of Using Cloud Services
### High Availability and Scalability
- **High Availability**: Ensures that cloud services remain accessible despite failures, disruptions, or maintenance. Uptime guarantees are defined in Service Level Agreements (SLAs).
- **Scalability**: Enables resources to dynamically adjust based on demand, following a pay-as-you-go model.
    - **Vertical Scaling**: Expanding or reducing the power of existing resources (e.g., adding/removing CPUs or RAM in a virtual machine).
    - **Horizontal Scaling**: Adding or removing multiple resources (e.g., scaling virtual machines or containers up/down).

### Reliability and Predictability
- **Reliability**: Ensures systems can recover from failures while continuing to function. Cloud platforms offer redundancy and automated failover mechanisms.
- **Predictability**:
    - **Performance Predictability**: Optimizes resource allocation to maintain performance (e.g., autoscaling, load balancing, high availability).
    - **Cost Predictability**: Allows organizations to track and forecast cloud spending using real-time analytics and usage monitoring.

### Security and Governance
- **Security**: Cloud security is tailored to needs. IaaS provides maximum control, while PaaS automates patching and maintenance. Robust networks help mitigate cyber threats, including Distributed Denial of Service (DDoS) attacks.
- **Governance**: Cloud platforms ensure compliance with corporate and regulatory standards through predefined security templates, automated auditing, and policy enforcement.

### Manageability
- **Cloud Resource Management**: Cloud platforms support automated scaling, monitoring, and self-healing of resources, ensuring optimal performance and reliability. Cloud services can send real-time alerts for potential issues based on preconfigured metrics.
- **Cloud Environment Management**: Users can manage cloud resources through multiple interfaces, including:
    - Web Portals (GUI-based management).
    - Command-Line Interfaces (CLI).
    - APIs & PowerShell for automation and scripting.

## Cloud Service Types
### Infrastructure as a Service (IaaS)
Provides the most flexibility and control, placing the largest share of responsibility on the user. Users manage virtual machines, storage, and networking while the cloud provider handles the infrastructure.

### Platform as a Service (PaaS)
Serves as a middle ground, splitting responsibility between the user and the cloud provider. Simplifies application development by managing the underlying infrastructure, operating systems, and runtime environments.

### Software as a Service (SaaS)
The most complete and user-friendly cloud model, offering fully managed applications. Requires the least technical expertise, making it easy to deploy and use.  
**Trade-off**: Less flexibility compared to IaaS and PaaS.

## Identify Appropriate Use Cases for Each Cloud Service Type (IaaS, PaaS, and SaaS)
### IaaS:
- Ideal for lift-and-shift migrations, enabling businesses to move workloads without major modifications.
- Commonly used for testing and development environments that require quick resource provisioning.

### PaaS:
- Used in application development frameworks to reduce coding effort.
- Supports analytics and business intelligence by providing scalable computing environments.

### SaaS:
- Typically used for email, messaging, and business productivity applications.
- Common in finance and expense tracking solutions, eliminating the need for local installations.

## Get Full Access

This was a preview of the first section of the study guide. For the full version, visit my [Patreon](https://www.patreon.com/yourpatreonlink](https://www.patreon.com/0xFutureLearning/shop/az-900-microsoft-azure-fundamentals-1121439?utm_medium=clipboard_copy&utm_source=copyLink&utm_campaign=productshare_creator&utm_content=join_link)) to purchase and download the complete PDF.

