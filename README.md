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

## View the SOC Automation Network diagram:<br/>
<img src="https://i.imgur.com/oyaRw4J.png" height="80%" width="80%" alt="SOC Automation Network Diagram"/>
<br />


# Installation Commands for Wazuh and TheHive 

## Specifications

- **RAM:** 8GB+
- **HDD:** 50GB+
- **OS:** Ubuntu 22.04 LTS

---

### Wazuh Installation

1. **SSH into Wazuh Server:**
   ```bash
   ssh root@<Public IP of Wazuh>
   ```

2. **Update and Upgrade:**
   ```bash
   apt-get update && apt-get upgrade
   ```

3. **Install Wazuh 4.7:**
   ```bash
   curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
   ```

4. **Extract Wazuh Credentials:**
   ```bash
   sudo tar -xvf wazuh-install-files.tar
   ```

5. **Wazuh Dashboard Credentials:**
   - **User:** admin
   - **Password:** ***************

6. **Access Wazuh Dashboard:**
   - Open your browser and go to: `https://<Public IP of Wazuh>`

---

### TheHive Installation

1. **SSH into TheHive Server:**
   ```bash
   ssh root@<Public IP of TheHive>
   ```

2. **Update and Upgrade:**
   ```bash
   apt-get update && apt-get upgrade
   ```

3. **Install Dependencies:**
   ```bash
   apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl  software-properties-common python3-pip lsb-release
   ```

4. **Install Java:**
   ```bash
   wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor  -o /usr/share/keyrings/corretto.gpg
   echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" |  sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
   sudo apt update
   sudo apt install java-common java-11-amazon-corretto-jdk
   echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment 
   export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
   ```

5. **Install Cassandra:**
   ```bash
   wget -qO -  https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor  -o /usr/share/keyrings/cassandra-archive.gpg
   echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" |  sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
   sudo apt update
   sudo apt install cassandra
   ```

6. **Install ElasticSearch:**
   ```bash
   wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch |  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
   sudo apt-get install apt-transport-https
   echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" |  sudo tee /etc/apt/sources.list.d/elastic-7.x.list
   sudo apt update
   sudo apt install elasticsearch
   ```

7. **Install TheHive:**
   ```bash
   wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
   echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list
   sudo apt-get update
   sudo apt-get install -y thehive
   ```

8. **Default Credentials for TheHive:**
   - **Port:** 9000
   - **Credentials:** 'admin@thehive.local' with a password of 'secret'

## Configuration for TheHive

### Configure Cassandra

1. **Edit Cassandra Config File:**
   ```bash
   nano /etc/cassandra/cassandra.yaml
   ```

2. **Change Cluster Name:**
   ```yaml
   cluster_name: 'jashan'
   ```

3. **Update Listen Address:**
   ```yaml
   listen_address: <public IP of TheHive>
   ```

4. **Update RPC Address:**
   ```yaml
   rpc_address: <public IP of TheHive>
   ```

5. **Update Seed Provider:**
   ```yaml
   - seeds: "<Public IP Of the TheHive>:7000"
   ```

6. **Stop Cassandra Service:**
   ```bash
   systemctl stop cassandra.service
   ```

7. **Remove Old Files:**
   ```bash
   rm -rf /var/lib/cassandra/*
   ```

8. **Restart Cassandra Service:**
   ```bash
   systemctl start cassandra.service
   ```

### Configure ElasticSearch

1. **Edit ElasticSearch Config File:**
   ```bash
   nano /etc/elasticsearch/elasticsearch.yml
   ```

2. **Update Cluster Name and Host:**
   ```yaml
   cluster.name: thehive
   node.name: node-1
   network.host: <Public IP of your TheHive instance>
   http.port: 9200
   ```

3. **Start ElasticSearch Service:**
   ```bash
   systemctl start elasticsearch
   systemctl enable elasticsearch
   systemctl status elasticsearch
   ```

## Configure TheHive

1. **Ensure Proper Ownership:**
   ```bash
   ls -la /opt/thp
   chown -R thehive:thehive /opt/thp
   ```

2. **Edit TheHive Configuration File:**
   ```bash
   nano /etc/thehive/application.conf
   ```

3. **Update Database and Index Configuration:**
   ```conf
   db.janusgraph {
     storage {
       backend = cql
       hostname = ["<Public IP of TheHive>"]
       cql {
         cluster-name = jashan
         keyspace = thehive
       }
     }
   }

   index.search {
     backend = elasticsearch
     hostname = ["<Public IP of TheHive>"]
     index-name = thehive
   }

   application.baseUrl = "http://<Public IP of TheHive>:9000"
   ```

4. **Start TheHive Services:**
   ```bash
   systemctl start thehive
   systemctl enable thehive
   systemctl status thehive
   ```

## Configuration on Wazuh

### Retrieve Wazuh Credentials

1. **Access Wazuh Console and Extract Credentials:**
   ```bash
   tar -xvf wazuh-install-files.tar
   cd wazuh-install-files/
   cat wazuh-passwords.txt
   ```

2. **Add Windows 10 Agent to Wazuh:**
   - Click on "Add Agent" and select "Windows" as package.
   - Enter Wazuh Public IP as server address.
   - Assign an agent name.
   - Copy the provided command and run it on the Windows 10 machine.
   - Start Wazuh agent service:
     ```bash
     net start wazuhsvc
     ```

3. **Verify Agent Activation:**
   - After a few minutes, the Windows 10 agent should appear as active in the Wazuh Dashboard.

---

Congratulations! TheHive and Wazuh are now configured and operational as expected. 🎉

## Configuration on Windows 10

### Modify ossec.conf File

1. **Navigate to ossec.conf File:**
   ```
   This PC > Local Disk(C:) > Program Files(x86) > ossec-agent
   ```

2. **Backup ossec.conf File:**
   - Right-click on ossec.conf file and select "Copy", then right-click again and select "Paste" to create a backup named ossec-backup.conf.

3. **Edit ossec.conf File:**
   - Open ossec.conf with Notepad as Administrator.

4. **Add Sysmon Rule:**
   ```xml
   <!-- Log analysis -->
   <localfile>
     <location>Microsoft-Windows-Sysmon/Operational</location>
     <log_format>eventchannel</log_format>
   </localfile>
   ```

5. **Restart Wazuh Service:**
   - Open services.msc and restart the Wazuh service.

### Download and Execute Mimikatz

1. **Exclude Downloads Folder from Windows Defender:**
   - Open Windows Security > Virus & threat protection > Virus & threat protection settings > Manage settings > Add or remove exclusion > Exclude downloads folder.

2. **Download and Extract Mimikatz:**
   - Download Mimikatz from [here](https://github.com/gentilkiwi/mimikatz/releases/tag/2.2.0-20220919).
   - Extract the downloaded file in the excluded downloads folder.

3. **Execute Mimikatz:**
   - Open an Administrator PowerShell session.
   - Navigate to the folder containing Mimikatz.
   - Run Mimikatz: `.\mimikatz.exe`.

### Modify ossec.conf for Logging

1. **Edit ossec.conf:**
   ```bash
   nano /var/ossec/etc/ossec.conf
   ```

2. **Set Logging Options:**
   ```xml
   <logall>yes</logall>
   <logall_json>yes</logall_json>
   ```

3. **Restart Wazuh:**
   ```bash
   systemctl restart wazuh-manager.service
   ```

### Create New Index on Wazuh

1. **Access Wazuh Stack Management:**
   - Click on the hamburger icon > Stack Management > Index Patterns.

2. **Create New Index for Archives:**
   - Click "Create index" and type `wazuh-archives-**`.
   - Select timestamp and create the index pattern.

### Create Custom Alerts on Wazuh

1. **Navigate to Rules Management:**
   - Home > Management > Rules > Manage rule files.

2. **Copy Sysmon Rule:**
   - Find the desired rule (e.g., 0800-sysmon_id_1.xml) and copy its content.

3. **Edit Local Rules:**
   - Click on "Custom rules" and edit the local_rules.xml file.

4. **Paste and Customize Custom Rule:**
   - Paste the copied rule and modify it as needed (e.g., set custom rule id to 100002, change description).
   
5. **Restart Wazuh:**
   - Confirm the server restart.

### Verify Alert

1. **Run Mimikatz:**
   - Execute Mimikatz on your Windows 10 machine.

2. **Check for Alerts:**
   - Verify if the alert appears in Wazuh.


## Shuffler Configuration (SOAR Platform)

### Set up Webhook on Shuffler

1. **Access Shuffler Website:**
   - Go to [Shuffler website](https://shuffler.io/workflows).

2. **Add Webhook Trigger:**
   - Navigate to Triggers and drag and drop the Webhook trigger.
   - Click on the Webhook app and copy the Webhook URI.

3. **Integrate with OSSEC:**
   - Open the ossec.conf file on the Wazuh manager: `nano /var/ossec/etc/ossec.conf`.
   - Add the integration tag under the first global rule, replacing the hook URL with the copied URL from Shuffler Webhook.
   - Paste the following under the first global rule, replacing the hook URL with the copied URL from Shuffle Webhook:
 ```bash
<integration>
  <name>shuffle</name>
  <hook_url>https://shuffler.io/api/v1/hooks/webhook_1a37e289-23db-4098-9337-35c2b157488f </hook_url>
  <rule_id>100002</rule_id>
  <alert_format>json</alert_format>
</integration>
```
  - Note: Your webhook URL will be different so paste that in the integration tag.

4. **Restart Wazuh Manager Service:**
   ```bash
   systemctl restart wazuh-manager.service
   ```

### Telemetry Generation and Workflow Execution

1. **Regenerate Telemetry:**
   - Run Mimikatz on the Windows 10 machine.

2. **Execute Workflow on Shuffler:**
   - Start the Webhook execution on the Shuffler instance.

3. **Check Executions on Shuffler:**
   - Go to the Person tab to view the executions.

4. **Create Workflow in Shuffler:**
   - Define the workflow steps:
     1. Mimikatz alert sent to Shuffler.
     2. Shuffle Receives Mimikatz alert and extracts SHA256 Hash.
     3. Check Reputation score using VirusTotal.
     4. Send details to TheHive to create Alert.
     5. Send Email to SOC Analyst to Begin Investigation.

5. **Configure Regex Capture Group:**
   - Set Find Actions to Regex capture group and define the SHA256 Regex.

6. **Utilize VirusTotal API:**
   - Create an account on VirusTotal and obtain the API key.
   - Add the VirusTotal app to the workflow and set Find Actions to "Get hash report" using the API key.

### Send Alerts to TheHive

1. **Create User and Organization in TheHive:**
   - Add users and organization in TheHive.

2. **Generate API Key:**
   - Generate API key for the user in TheHive.

3. **Configure Workflow in Shuffle:**
   - Set up the workflow to create an alert in TheHive using the obtained API key and URL.

4. **Run Workflow:**
   - Rerun the workflow on Shuffler.

### Email Notification to SOC Analyst

1. **Add Email App to Workflow:**
   - Drag and drop the email app and connect it to the VirusTotal app.

### Configuration for SMTP Email:

#### Find Action: Send email SMTP

- **SMTP Host:** smtp.office365.com
- **Port:** 587

- **Username:** \<Your outlook email\>@outlook.com
- **Password:** \<App password - You can get this through this link - [App Password Link](https://account.live.com/proofs/Manage/additional)\>

- **Recipient:** \<Any email address where you want to send this alert email\>

- **Subject:** Mimikatz Usage Detected!!!

**Body:**
- Time: $exec.text.win.eventdata.utcTime
- Title: $exec.title
- Host: $exec.text.win.system.computer

- **Ssl verify:** True


### Configure Responsive Action in Shuffle

1. **Block Source IPs Attempting to Connect to Ubuntu Machine via SSH:**
   - Allow all TCP connections to the Ubuntu machine in the cloud FW.
   - Add an HTTP application to the Shuffle workflow.

2. **Workflow:**
   - **Name:** Get-API
   - **Find Actions:** Curl
   - Ensure a firewall rule exists to allow all inbound traffic to Wazuh for port 55000.
   - Use the Wazuh API to authenticate and obtain a JWT token.
   
     ```bash
     # GET-API (Wazuh for token)
     curl -u user:PASSWORD -k -X GET "https://<Wazuh-IP>:55000/security/user/authenticate?raw=true"
     ```
   
3. **Drag and Drop Wazuh Application to the Workflow:**
   - **Find Actions:** Run command
   - **API Key:** Get-API node
   - **URL:** https://(Wazuh-IP):55000
   - **Agent List:** <agent ID>
   - **Wait for Complete:** True
   - **Command:** firewall-drop0
   - **Alert:** `{"data":{"srcip":"$exec.all_fields.data.srcip"}}`

4. **Configure Active Response on Wazuh Console:**
   - Edit the ossec.conf file:
     ```bash
     nano /var/ossec/etc/ossec.conf
     ```
   - Add the following at the end of active response commands:
     ```xml
     <active-response>
       <command>firewall-drop</command>
       <location>local</location>
       <level>15</level>
       <timeout>no</timeout>
     </active-response>
     ```
   - Save the file and restart the Wazuh manager:
     ```bash
     systemctl restart wazuh-manager
     ```

5. **View Available Active Responses:**
   - ```bash
     cd /var/ossec/bin
     ls
     ./agent_control -L
     ```
   - Obtain the agent list from the Wazuh dashboard.

6. **Test Active Response:**
   - Run the following command:
     ```bash
     ./agent_control -b 8.8.8.8 -f firewall-drop0 -u 002
     ```
   - Start a ping to 8.8.8.8 on the Ubuntu machine before running this command.
   - Verify if 8.8.8.8 is blocked by active response from Wazuh:
     ```bash
     iptables --list
     ```
   - Flush iptables if needed:
     ```bash
     iptables --flush
     ```
   - Check Active Response logs on the Ubuntu machine:
     ```bash
     cd /var/ossec/logs/
     ls
     cat active-responses.log
     ```

7. **Setup User Input:**
   - Go to Trigger and select User Input.
   - **Email:** Analyst email
   - **Information:** Would you like to block the source IP: <src IP>


### Workflow:

Wazuh-Alert ---> Get-API ---> VirusTotal --> User Input ---> Wazuh ---> TheHive 
                                 
                                
## Conclusion

Congratulations on completing the SOC automation project! 🎉

By implementing Shuffler, integrating with OSSEC/Wazuh, and orchestrating workflows, you've taken significant steps towards enhancing security operations and incident response capabilities. 

As you continue to refine and expand upon this automation framework, remember the importance of continuous improvement and adaptation to evolving threats. 

Thank you for your dedication and effort in advancing our security posture. Together, we're better equipped to safeguard our systems and data against cyber threats.

Cheers to a safer and more efficient SOC environment! 🚀🔒
