# SOC-Automation-Project

## Objective
In this lab, we will explore the practical aspects of setting up a Security Operations Center (SOC) home lab. Our focus will be on understanding and implementing Security Orchestration, Automation, and Response (SOAR) solutions.  We will gain hands-on experience with real-world scenarios, enhancing our skills as SOC analysts.

# Building a Home Lab for SOC Analyst Learning: A Journey into SOAR Solutions 🚀

I'm thrilled to share my latest project—an experimental learning endeavor focused on **SOC (Security Operations Center)** analysis. In this project, we'll explore the architecture and components of a home lab designed for hands-on experience with security event management, orchestration, and automated threat response.

## Lab Structure

1. **Windows 10 Agents/Users**:
   - These agents run **Wazuh** to generate security events.
   - Their role is crucial in simulating real-world scenarios.

2. **Wazuh Manager Server**:
   - The central hub for collecting and managing security events from Windows 10 agents.
   - It acts as the nerve center of our SOC setup.

3. **Shuffle Integration**:
   - Orchestrates the flow of data—from event collection to response actions.
   - Shuffle streamlines the entire process, ensuring efficient incident handling.

4. **The Hive**:
   - A powerful tool for centralizing alerts and managing incident response.
   - Integrates seamlessly with Shuffle, allowing automated OSINT (Open Source Intelligence) gathering.

5. **SOC Analyst Station**:
   - My workspace for monitoring and responding to alerts.
   - As an analyst, I play a critical role in assessing and mitigating security incidents.

## Data Flow

1. **Windows 10 → Wazuh Manager**:
   - Security events originate on Windows 10 machines.
   - Wazuh agents forward these events to the Wazuh Manager.

2. **Wazuh Manager → Shuffle**:
   - The Wazuh Manager sends events to Shuffle for orchestration.
   - Shuffle coordinates the incident response workflow.

3. **Shuffle → The Hive**:
   - Automated OSINT tools within The Hive gather additional context.
   - Alerts are centralized, providing a comprehensive view of incidents.

4. **Shuffle → SOC Analyst**:
   - When an alert triggers, an email notifies me—the SOC analyst.
   - I promptly assess the situation and take necessary actions.

5. **SOC Analyst → Shuffle**:
   - I respond to the alert, performing investigations or mitigation steps.
   - Shuffle records my actions for future reference.

6. **Shuffle → Wazuh Manager**:
   - Response actions are communicated back to the Wazuh Manager.
   - These actions may include blocking an IP address, quarantining a host, or other protective measures.

7. **Wazuh Manager → Windows 10**:
   - The Wazuh Manager executes response actions on the Windows 10 endpoints.
   - This completes the incident lifecycle.

## Lab Components in the Cloud

Our lab environment consists of:

- **Two Cloud Servers**:
  - One hosts the Wazuh Manager.
  - The other hosts Shuffle.
- **Virtual Machine with Windows 10**:
  - Simulates the Windows 10 environment.
- **SOC Analyst Station**:
  - My workspace for active monitoring and incident handling.

Feel free to explore this setup, adapt it to your needs, and embark on your own SOC learning journey! 🌟


