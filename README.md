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

Security Information and Event Management (SIEM) systems are...

These section will cover the followings SIEM's:
- [Wazuh](#wazuh)

### Wazuh



## Adversary Emulation

Adversary Emulation consists of...

This section will cover the following Adversary Emulation tools:
- [Atomic Red Team](#atomic-red-team)

### Atomic Red Team