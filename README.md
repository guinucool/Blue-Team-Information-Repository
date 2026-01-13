# Blue Team Tool Repository

## Hardening

## Intrusion Detection

Intrusion detection refers to the systematic deployment and configuration of security mechanisms designed to monitor network or host activity in order to identify malicious behavior, policy violations, or anomalous patterns indicative of compromise. These mechanisms analyze traffic, system events, and logs to detect both known attack signatures and deviations from established baselines.

Intrusion Detection Systems (IDS) play a critical role in Blue Team operations by providing visibility into potential threats, enabling timely investigation, and supporting incident response and forensic analysis. IDS solutions are commonly categorized as network-based or host-based, depending on the data sources they monitor.

This section covers the following tools:

- [Suricata (Network IDS)](#suricata)

### Suricata

Suricata is an open-source, high-performance Network Intrusion Detection and Prevention System (NIDS/NIPS) designed to monitor network traffic in real time. It supports signature-based detection, protocol analysis, and anomaly detection, enabling the identification of malicious activity, policy violations, and suspicious network behavior.

Suricata is capable of deep packet inspection across a wide range of protocols and is optimized for multi-threaded environments, allowing it to operate efficiently on high-throughput networks. In addition to intrusion detection, Suricata can generate detailed logs and metadata, which are valuable for threat hunting, forensic analysis, and integration with Security Information and Event Management (SIEM) platforms.

```
https://suricata.io/
```

#### Installation & Configuration

Suricata must be installed on the system responsible for monitoring network traffic. This system should have access to the network interface through which the traffic of interest flows.

The following commands install the stable version of Suricata from the official Open Information Security Foundation (OISF) repository on Debian-based systems:

```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install suricata -y
```

After installation, Suricata must be configured to reflect the operational network environment. This includes defining the protected network range and specifying the network interface to be monitored. Accurate configuration of these parameters is essential to ensure effective alerting and optimal performance.

The HOME_NET variable should be set to the IP address or network range of the monitored system or internal network. In the following example, the monitored host has the IP address 10.10.10.2, and Suricata is configured to capture traffic from the enp0s8 interface.

```bash
# Configuration at /etc/suricata/suricata.yaml

...

##
## Step 1: Inform Suricata about your network
##

vars:
    # more specific is better for alert accuracy and performance
    address-groups:
        HOME_NET: "[10.10.10.2]"

...

# Linux high speed capture support
af-packet:
    - interface: enp0s8

...
```

Suricata requires a dedicated directory to store detection rules. If the directory does not already exist, it must be created and assigned appropriate ownership and permissions to ensure secure access.

```
sudo mkdir -p /etc/suricata/rules
sudo chown root:suricata /etc/suricata/rules
sudo chmod 750 /etc/suricata/rules
```

After modifying configuration files or adding new rules, Suricata must be restarted to apply the changes. Restarting the service ensures that updated rulesets and configuration settings are loaded and actively monitored.

```bash
sudo systemctl restart suricata
```

#### Custom Rules

Suricata detection rules define the conditions under which network traffic is considered suspicious or malicious. These rules are evaluated against captured packets and can generate alerts, log events, or trigger preventive actions when specific criteria are met. Custom rules allow security teams to tailor detection logic to the specific threats, services, and network characteristics of the monitored environment.

```bash
###############################################################################
#                         SURICATA RULE TEMPLATE                               #
###############################################################################

<action> <protocol> <source_ip> <source_port> <direction> <destination_ip> <destination_port> (
    msg:"<descriptive alert message>";
    flow:<flow options>;
    content:"<pattern to match>";
    nocase;
    <additional detection keywords>;
    classtype:<classification>;
    sid:<unique signature id>;
    rev:<revision number>;
)

###############################################################################
#                         EXAMPLE SURICATA RULES                               #
###############################################################################

# 1. Detect ICMP echo requests (ping) to internal hosts
alert icmp any any -> $HOME_NET any (
    msg:"ICMP Echo Request detected";
    itype:8;
    classtype:network-scan;
    sid:1000001;
    rev:1;
)

# 2. Detect inbound TCP connections to a commonly abused backdoor port
alert tcp any any -> $HOME_NET 4444 (
    msg:"Suspicious TCP connection to port 4444";
    flow:to_server;
    classtype:trojan-activity;
    sid:1000002;
    rev:1;
)

# 3. Detect HTTP GET requests
alert http any any -> $HOME_NET any (
    msg:"HTTP GET request detected";
    http.method;
    content:"GET";
    classtype:web-application-activity;
    sid:1000003;
    rev:1;
)

# 4. Detect access to a suspicious domain via HTTP Host header
alert http any any -> $HOME_NET any (
    msg:"HTTP request to suspicious domain";
    http.host;
    content:"malicious.example";
    nocase;
    classtype:trojan-activity;
    sid:1000004;
    rev:1;
)

# 5. Detect a basic SQL injection pattern
alert http any any -> $HOME_NET any (
    msg:"Possible SQL injection attempt";
    content:"' OR 1=1";
    nocase;
    classtype:web-application-attack;
    sid:1000005;
    rev:1;
)

# 6. Detect cleartext password parameters in HTTP traffic
alert http any any -> $HOME_NET any (
    msg:"Cleartext password parameter detected";
    content:"password=";
    nocase;
    classtype:policy-violation;
    sid:1000006;
    rev:1;
)

# 7. Detect SSH connection attempts to internal hosts
alert tcp any any -> $HOME_NET 22 (
    msg:"SSH connection attempt detected";
    flow:to_server,established;
    classtype:attempted-recon;
    sid:1000007;
    rev:1;
)

# 8. Detect DNS queries for known malicious domains
alert dns any any -> $HOME_NET any (
    msg:"DNS query for suspicious domain";
    dns.query;
    content:"bad-domain.example";
    nocase;
    classtype:trojan-activity;
    sid:1000008;
    rev:1;
)

# 9. Detect potential TCP SYN port scanning activity
alert tcp any any -> $HOME_NET any (
    msg:"Potential TCP SYN scan detected";
    flags:S;
    threshold:type both, track by_src, count 20, seconds 10;
    classtype:network-scan;
    sid:1000009;
    rev:1;
)

# 10. Detect Windows executable downloads over HTTP
alert http any any -> $HOME_NET any (
    msg:"Executable file download detected over HTTP";
    http.response_body;
    content:".exe";
    classtype:policy-violation;
    sid:1000010;
    rev:1;
)
```

Each rule includes a unique Signature ID (SID) and a revision number, which are essential for rule management and lifecycle tracking. When creating custom rules, it is recommended to use SIDs above 1000000 to avoid conflicts with official rule sets.

#### Third-Party Rulesets

Third-party rulesets extend Suricata’s detection capabilities by providing pre-defined signatures maintained by external security research organizations. These rulesets typically cover a wide range of known threats, including malware activity, exploit attempts, command-and-control communication, and emerging attack techniques. Integrating external rulesets enables faster threat coverage without requiring manual rule development.

To add a third-party ruleset, the rules must be downloaded, extracted, and placed in Suricata’s rules directory with appropriate ownership and permissions. The following example demonstrates a generic installation workflow.

```bash
# Download the third-party ruleset archive
sudo wget https://example.ruleset.com/ruleset/example.tar.gz

# Extract the ruleset
sudo tar -xvzf example.tar.gz

# Set secure ownership and permissions for the rule files
sudo chown root:suricata rules/*.rules
sudo chmod 640 rules/*.rules

# Move the rules into the Suricata rules directory
sudo mv rules/*.rules /etc/suricata/rules
```

After installing new rules, the Suricata configuration file (/etc/suricata/suricata.yaml) should be reviewed to ensure that the rules directory is included. Suricata must then be restarted or reloaded for the new signatures to take effect.

The following repositories are commonly used within Blue Team environments:

- [Emerging Threats](https://rules.emergingthreats.net/open/suricata/)

## Security Information and Event Management

Security Information and Event Management (SIEM) systems are centralized platforms designed to collect, correlate, and analyze security-related data from across an organization's IT infrastructure. They aggregate logs and events from endpoints, servers, network devices, applications, and security controls to provide real-time monitoring, threat detection, and incident response capabilities.

SIEM platforms are essential for Blue Team operations because they enable the identification of anomalous behavior, support forensic investigations, and facilitate compliance reporting. By applying correlation rules and advanced analytics, SIEMs help transform raw event data into actionable security intelligence.

This section covers the following SIEM solution:

- [Wazuh](#wazuh)

### Wazuh

Wazuh is an open-source Security Information and Event Management (SIEM) platform that provides unified security monitoring, threat detection, compliance management, and incident response capabilities. It integrates log data collection, file integrity monitoring, vulnerability detection, and intrusion detection into a single, scalable solution.

Wazuh collects and analyzes data from multiple sources across endpoints, servers, and network devices. It supports real-time alerting, correlation rules, and dashboards, enabling security teams to detect suspicious activity, investigate incidents, and enforce security policies efficiently. Wazuh also provides native integration with Elastic Stack for advanced visualization and reporting.

```
https://wazuh.com/
```

#### Installation & Configuration

Wazuh requires installation on a central manager, which provides monitoring, analysis, and alerting capabilities. The Wazuh manager includes a graphical interface that facilitates the deployment and configuration of Wazuh agents on endpoints. Agents can be installed manually or automatically using the manager’s provided automation scripts.

It is recommended to verify the latest Wazuh version before installation. Official installation instructions and version updates are available at:

> https://documentation.wazuh.com/current/quickstart.html

The installation of the Wazuh manager can be performed using the official installation script. The following commands demonstrate a typical installation on a Linux system:

```bash
# Download the Wazuh installation script
curl -sO https://packages.wazuh.com/version/wazuh-install.sh

# Execute the installation script with agent integration (-a)
sudo bash ./wazuh-install.sh -a
```

After installation, the manager provides credentials for accessing the web interface and other administrative components. These credentials can be extracted from the installation files as follows:

```bash
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

#### Decoders

In Wazuh, **decoders** are components responsible for parsing incoming log data and transforming it into a structured format that the SIEM can interpret. Decoders extract meaningful fields from raw log messages, identify log sources, and classify events according to predefined patterns. Proper decoding is essential for accurate alert generation, correlation, and reporting.

Decoders allow the SIEM to understand diverse log formats from operating systems, applications, network devices, and security tools. By standardizing the log data, decoders enable Wazuh to apply rules consistently and generate actionable alerts.

Custom decoders are stored in the following directory on the Wazuh manager:

```
/var/ossec/etc/decoders/
```

```xml
###############################################################################
#                             WAZUH DECODER SYNTAX                            #
###############################################################################

<decoder name="DECODER_NAME">
    <program_name>LOG_SOURCE</program_name>
    <prematch>OPTIONAL_FAST_MATCH_REGEX</prematch>
    <regex>MAIN_PARSING_REGEX</regex>
    <order>OPTIONAL_ORDER</order>
</decoder>

###############################################################################
#                           EXAMPLE DECODERS                                  #
###############################################################################

<!-- Example 1: SSH authentication failure decoder -->
<decoder name="sshd_failed_login">
    <program_name>sshd</program_name>
    <prematch>Failed password</prematch>
    <regex>Failed password for (?<user>\S+) from (?<src_ip>\S+)</regex>
</decoder>

<!-- Example 2: Successful SSH login decoder -->
<decoder name="sshd_success_login">
    <program_name>sshd</program_name>
    <prematch>Accepted password</prematch>
    <regex>Accepted password for (?<user>\S+) from (?<src_ip>\S+)</regex>
</decoder>

<!-- Example 3: Sudo command execution decoder -->
<decoder name="sudo_command">
    <program_name>sudo</program_name>
    <prematch>COMMAND=</prematch>
    <regex>(?<user>\S+) : TTY=(?<tty>\S+) ; PWD=(?<pwd>\S+) ; USER=(?<run_as>\S+) ; COMMAND=(?<command>.+)</regex>
</decoder>

<!-- Example 4: Web server access log decoder -->
<decoder name="web_access_log">
    <program_name>apache2</program_name>
    <regex>(?<src_ip>\S+) - (?<user>\S+) \[(?<timestamp>[^\]]+)\] "(?<method>\S+) (?<url>\S+) (?<protocol>[^"]+)" (?<status>\d+)</regex>
</decoder>
```

#### Rules

In Wazuh, **rules** are XML definitions that evaluate events parsed by decoders and determine whether an alert should be generated. Rules assign severity levels, classify events, and provide context, enabling security teams to identify suspicious behavior, policy violations, or potential attacks. They can also correlate multiple events, detect patterns over time, and trigger notifications for incident response.

Custom rules allow organizations to extend Wazuh’s detection capabilities to cover proprietary systems, unique workflows, or specific threat scenarios not addressed by the default rulesets.

Custom Wazuh rules are stored in the following directory on the Wazuh manager:

```
/var/ossec/etc/rules/
```

```xml
###############################################################################
#                              WAZUH RULE SYNTAX                              #
###############################################################################

<rule id="RULE_ID" level="SEVERITY_LEVEL">
    <if_sid>DECODER_OR_PARENT_SID</if_sid>
    <field name="FIELD_NAME">MATCH_PATTERN</field>
    <match>OPTIONAL_TEXT_MATCH</match>
    <description>Human-readable description of the alert</description>
    <mitre>TXXXX</mitre>
    <group>GROUP1,GROUP2</group>
</rule>

###############################################################################
#                              EXAMPLE RULES                                  #
###############################################################################

<!-- Example 1: SSH authentication failure -->
<rule id="100001" level="7">
    <if_sid>sshd_failed_login</if_sid>
    <description>SSH authentication failure detected</description>
    <mitre>T1110</mitre>
    <group>authentication_failed,ssh</group>
</rule>

<!-- Example 2: Multiple SSH failures indicating brute-force activity -->
<rule id="100002" level="10">
    <if_matched_sid>100001</if_matched_sid>
    <frequency>5</frequency>
    <timeframe>60</timeframe>
    <description>Possible SSH brute-force attack detected</description>
    <mitre>T1110</mitre>
    <group>authentication_failed,bruteforce,ssh</group>
</rule>

<!-- Example 3: Sudo command execution -->
<rule id="100003" level="6">
    <if_sid>sudo_command</if_sid>
    <description>Sudo command executed by user</description>
    <mitre>T1548</mitre>
    <group>privilege_escalation,sudo</group>
</rule>

<!-- Example 4: Suspicious command execution -->
<rule id="100004" level="9">
    <if_sid>sudo_command</if_sid>
    <field name="command">nc|netcat|bash -i</field>
    <description>Potential malicious command execution detected</description>
    <mitre>T1059</mitre>
    <group>command_execution,suspicious_activity</group>
</rule>
```

#### Lists

In Wazuh, **CDB lists** (Collaborative Database lists) are collections of static values—such as IP addresses, domain names, or file hashes—that can be referenced by rules to detect matches against known indicators of compromise (IOCs) or other relevant entities. Lists enable efficient, centralized management of external data and help rules identify malicious activity or policy violations without embedding large datasets directly into individual rules.

CDB lists are plain text files in which each entry appears on a separate line. Lines beginning with `#` are treated as comments.

CDB lists are typically used to:

- Detect connections to suspicious IPs or domains  
- Identify access to sensitive files or directories  
- Correlate multiple alerts with known threat intelligence  

CDB lists are added to the Wazuh main configuration file:

```
/var/ossec/etc/ossec.conf
```

```xml
# Example entry for a list in configuration file
<list>var/ossec/etc/lists/example</list>
```

The lists themselves are stored in the following directory:

```
/var/ossec/etc/lists/
```

#### Commands

In Wazuh, **commands** are predefined actions or scripts that can be executed automatically in response to alerts or specific events. Commands allow security teams to perform tasks such as quarantining files, blocking IP addresses, sending notifications, or collecting additional system information. By integrating commands into the detection workflow, Wazuh enables automated response and remediation capabilities alongside monitoring and alerting.

Commands are defined in XML and are registered in the **main Wazuh configuration file**:

```
/var/ossec/etc/ossec.conf
```

```xml
###############################################################################
#                              WAZUH COMMAND SYNTAX                           #
###############################################################################

<command>
    <name>COMMAND_NAME</name>
    <executable>BINARY</executable>
    <timeout_allowed>SECONDS</timeout_allowed>
</command>

###############################################################################
#                              EXAMPLE COMMANDS                               #
###############################################################################

<!-- Example 1: Block an IP address using firewall script -->
<command>
    <name>firewall-drop</name>
    <executable>firewall-drop.sh</executable>
    <timeout_allowed>60</timeout_allowed>
</command>

<!-- Example 2: Send an email notification when an alert is triggered -->
<command>
    <name>send-email</name>
    <executable>send-email.sh</executable>
    <timeout_allowed>30</timeout_allowed>
</command>

<!-- Example 3: Quarantine a suspicious file -->
<command>
    <name>quarantine-file</name>
    <executable>quarantine-file.sh</executable>
    <timeout_allowed>no</timeout_allowed>
</command>
```

The commands themselves are usually stored in the `active-response` directory on the wazuh client:

```
# In linux
/var/ossec/active-response/bin/

# In windows
C:\Program Files(x86)\ossec-agent\active-response\bin
```

#### Active Responses

In Wazuh, **active responses** are automated actions triggered by specific rules or events. They allow the system to react immediately to suspicious activity, such as blocking an IP address, terminating a malicious process, or executing a custom remediation script. Active responses enhance security by reducing response time, limiting the impact of attacks, and supporting automated mitigation workflows.

Active responses are defined in XML and are registered in the **main Wazuh configuration file**:

```
/var/ossec/etc/ossec.conf
```

```xml
###############################################################################
#                           WAZUH ACTIVE RESPONSE SYNTAX                      #
###############################################################################

<active-response>
    <disabled>yes|no</disabled>
    <command>COMMAND_NAME</command>
    <location>all|server|local</location>
    <rules_id>RULE_ID_OR_RANGE</rules_id>
    <timeout>SECONDS</timeout>
</active-response>

###############################################################################
#                             EXAMPLE ACTIVE RESPONSES                        #
###############################################################################

<!-- Example 1: Block IP addresses for SSH brute-force detection -->
<active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>100002</rules_id>
    <timeout>60</timeout>
</active-response>

<!-- Example 2: Send email notifications for high-severity alerts -->
<active-response>
    <command>send-email</command>
    <location>server</location>
    <rules_id>100001,100003</rules_id>
</active-response>

<!-- Example 3: Quarantine malicious files detected by Wazuh -->
<active-response>
    <command>quarantine-file</command>
    <location>local</location>
    <rules_id>100004</rules_id>
</active-response>
```

#### Client Monitoring

Wazuh agents (clients) can be configured to monitor specific log files or directories and send events to the central Wazuh manager. This capability enables continuous collection of security-relevant data from endpoints and servers for analysis, alerting, and correlation.

The active-response and monitoring scripts are located in the following directories:

```
# In linux
/var/ossec/etc/ossec.conf

# In windows
C:\Program Files(x86)\ossec-agent\ossec.conf
```

```xml
<ossec_config>
    <!-- Monitor a log file -->
    <localfile>
        <log_format>audit</log_format>
        <location>/var/log/audit/audit.log</location>
    </localfile>

    <!-- Monitor a directory for changes in real-time -->
    <syscheck>
        <directories realtime="yes">/home/user/Downloads</directories>
    </syscheck>
</ossec_config>
```

## Malware Analysis

## Adversary Emulation

Adversary emulation is the structured simulation of real-world threat actor behaviors, techniques, and procedures within a controlled environment. Its purpose is to evaluate the effectiveness of defensive controls, detection mechanisms, and incident response processes by replicating how adversaries operate during different phases of an attack lifecycle.

Unlike generic penetration testing, adversary emulation is intelligence-driven and commonly aligned with established frameworks such as MITRE ATT&CK. By executing known adversarial techniques, defensive teams can validate detection coverage, identify security gaps, and measure the maturity of monitoring and response capabilities.

This section covers the following adversary emulation tool:

- [Atomic Red Team](#atomic-red-team)

### Atomic Red Team

Atomic Red Team is an open-source adversary emulation framework designed to help security teams test and validate defensive controls by executing small, focused tests that simulate individual adversary techniques. Each test, referred to as an *atomic test*, represents a specific behavior mapped to the MITRE ATT&CK framework and is intended to be safe, repeatable, and measurable.

Atomic Red Team enables defenders to assess detection and response capabilities at a granular level by emulating techniques such as credential access, lateral movement, persistence, and command execution. The framework supports multiple operating systems and execution methods, allowing it to be integrated into continuous security validation, purple team exercises, and detection engineering workflows.

```
https://www.atomicredteam.io/
```

#### Installation & Configuration

Atomic Red Team relies on PowerShell for execution. On Linux systems, PowerShell must be installed prior to deploying the framework. Official installation instructions are available from Microsoft:

> https://learn.microsoft.com/en-us/powershell/scripting/install/install-ubuntu?view=powershell-7.5

The installation process consists of two main steps: installing the Atomic Red Team PowerShell framework and downloading the atomic tests, which represent individual adversary techniques and procedures (TTPs).

The following commands install the required PowerShell modules for the current user:

```powershell
# Install the Atomic Red Team framework and required dependencies
Install-Module -Name invoke-atomicredteam,powershell-yaml -Scope CurrentUser

# Download and install the Atomic Red Team TTPs
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicsfolder.ps1' -UseBasicParsing)

Install-AtomicsFolder
```

#### Usage

Atomic Red Team can be used to enumerate available adversary techniques, inspect the atomic tests associated with each technique, validate execution prerequisites, and safely execute or clean up simulated attacks. These capabilities enable defenders to systematically test detection and response mechanisms aligned with specific MITRE ATT&CK techniques.

The following examples demonstrate common usage patterns of the `Invoke-AtomicTest` command.

```powershell
# List atomic tests available for the current operating system (Windows, Linux, or macOS)
Invoke-AtomicTest T1003 -ShowDetailsBrief

# List all atomic tests for a technique, regardless of supported operating system
Invoke-AtomicTest T1003 -ShowDetailsBrief -AnyOS

# Check whether prerequisites are met before executing the atomic tests
Invoke-AtomicTest T1003 -CheckPrereqs

# Execute test number 1 of sub-technique T1218.010
Invoke-AtomicTest T1218.010 -TestNumbers 1

# Execute test number 1 using the abbreviated syntax
Invoke-AtomicTest T1218.010-1

# Clean up artifacts created by test number 1 of sub-technique T1218.010
Invoke-AtomicTest T1218.010 -TestNumbers 1 -Cleanup

# Clean up artifacts created by all executed tests for sub-technique T1218.010
Invoke-AtomicTest T1218.010 -Cleanup
```