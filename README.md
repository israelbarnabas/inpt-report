#  Internal Penetration Test

Submitted by: Israel Barnabas

## Internal Network Penetration Test  
**For**: CYBERLAB  
**Barnabas Security**  
**2024**

---


## Table of Contents

1. [Testing Methodology](#testing-methodology)
2. [Summary of Findings](#summary-of-findings)
3. [Detailed Findings](#detailed-findings)
    - [Unauthenticated Remote Code Execution (RCE)](#UnauthenticatedRemoteCodeExecution(RCE))
    - [Denial of service (DoS)](#denial_of_service)
    - [UltraVNC DSM Plugin Local Privilege Escalation](#VulnerabilityUltraVNCDSMPluginLocalPrivilegeEscalation)
    - [Weak Tomcat Authentication and Deployment](#WeakTomcatAuthenticationandDeployment)
    - [Arbitrary Code Execution via Base64 Decoding](#sArbitraryCodeExecutionviaBase64Decoding)
    - [Apache Tomcat AJP File Read/Inclusion](#ApacheTomcatAJPFileRead/Inclusion)
4. [CVSS v3.0 Reference Table](#cvss-v30-reference-table)


---
## Testing Methodology
The test begun with host discovery to identify active devices (hosts) on the network. By identifying which hosts are live and reachable, you can determine the targets for further probing, such as port scanning and vulnerability analysis.
The internal network to be exploited are `10.10.10.0/24` and domain `https://virtualinfosecafrica.com`
A **ping scan** was executed to test the reachablility of hosts on the ip address i.e `ping 10.10.10.0/24` and `ping virtualinfosecafrica.com`.

Nmap was another tool which was use for host discovery. These command were used together with nmap to yield the desired output
`-sL`: List Scan - simply list targets to scan,
  `-sn`: Ping Scan - disable port scan (`nmap -sn 10.10.10.0/24`),
  `-Pn`: Treat all hosts as online -- skip host discovery.
  Using the command `nmap -sL 10.10.10.0/24 > targetlist.txt`
 listed all the ip address to be scanned. With a subnet mask of **24**, 256 address are to be produced.
  After running the scan,  15 hosts were up then the filtered output were saved in a file. 

 `$ nmap -sn -iL targetlist.txt | grep -i "nmap scan report" > onlinehost.txt`
 
 ![Screenshot_2024-09-15_21_26_19](https://github.com/user-attachments/assets/3f8036bb-01e0-4283-bc1b-21e01a78791f)

To obtain subdomain enumeration, the `aiodnsbrute`
 tool was used. From the results shown below, a number of subdomain were optained with their respective ip address.

![Screenshot_2024-09-15_08_45_36](https://github.com/user-attachments/assets/4db48e08-70bc-497a-a0c4-048b045d9842)

Next service discovery and port scanning was done to identify the services running on a network and the open ports that could potentially be exploited.
The command `sV` is used to probe open ports to determine service/version info.

![Screenshot_2024-09-15_09_31_08](https://github.com/user-attachments/assets/999c74c7-6a90-4ffe-a743-8c8f63845e01)

From the output obtained, the various ports and service versions associated with the open ports were checked for any exploits. The results are listed below.


## Summary of Findings
| Finding                                        | Severity |
|------------------------------------------------|----------|
| Unauthenticated Remote Code Execution (RCE) | Critical    |
| Denial of service (DoS)                          | Moderate     |
|UltraVNC DSM Plugin Local Privilege Escalation                   | High     |
| Weak Tomcat Authentication and Deployment         | Critical   |
| Arbitrary Code Execution via Base64 Decoding                         | Critical|
| Apache Tomcat AJP File Read/Inclusion |Critical  |


## Detailed Findings
### Unauthenticated Remote Code Execution (RCE)

| *Current Rating:* | CVSS Score   |
|-------------------|--------------|
|Critical           |   9.8         |

#### Evidence
This module exploit an unauthenticated RCE vulnerability which 
  exists in Apache version 2.4.49 (CVE-2021-41773). If files outside 
  of the document root are not protected by ‘require all denied’ 
  and CGI has been explicitly enabled, it can be used to execute 
  arbitrary commands (Remote Command Execution). This vulnerability 
  has been reintroduced in Apache 2.4.50 fix (CVE-2021-42013).


!![Screenshot_2024-09-17_08_02_46](https://github.com/user-attachments/assets/1724afee-bdb2-4d71-a592-efd1c5a288b0)
A costum word list was form for the brute force attack using this command:`cewl https://virtualinfosecaficacom -d 3 -m 5 -w custom_wordlist.txt`


Output after using `metasploit`
![Screenshot_2024-09-16_19_03_57](https://github.com/user-attachments/assets/c62e3062-c8dd-4418-a9f3-a21fb8aef0fd)
![Screenshot_2024-09-16_19_12_28](https://github.com/user-attachments/assets/b475402f-b7b1-48c9-85a0-809f534d19cf)


#### Affected Resources:
`10.10.10.2, 10.10.10.30, 10.10.10.45, 10.10.10.55`

#### Recommendations
Upgrade to a newer patched version of Apache HTTP Server .

---

### Denial of service (DoS)

| *Current Rating:* | CVSS Score   |
|-------------------|--------------|
|Medium          |   6.5         |

These are the vulnerabilities associated with the service version  `MySQL 5.6.49 ` with the port `3306`
#### Evidence
CVE-2020-14765: This vulnerability exists in the FTS component of MySQL Server. It allows a low-privileged attacker with network access to cause a denial of service (DoS) by causing the MySQL Server to hang or crash. The CVSS 3.1 Base Score for this vulnerability is 6.5, indicating a medium level of severity, primarily affecting availability.

CVE-2020-14769: Found in the Optimizer component of MySQL Server, this vulnerability also allows a low-privileged attacker with network access to potentially cause a hang or crash, leading to a complete DoS of the MySQL Server. This issue also has a CVSS 3.1 Base Score of 6.5, indicating medium severity with an impact on availability.


![Screenshot_2024-09-16_20_39_35](https://github.com/user-attachments/assets/50a7a939-f257-4a68-b6ee-66fe0f42cb6f)
![Screenshot_2024-09-16_20_47_05](https://github.com/user-attachments/assets/da90e0ad-c2be-4d78-bc00-cc47bc505eb0)


#### Affected Resources:
`10.10.10.5 , 10.10.10.40`

#### Recommendations
* Rate Limiting: Implement rate limiting to control the number of requests a user can make to a service in a given timeframe. This can help mitigate the impact of DoS attacks by limiting the number of requests that can overwhelm the system.

* Traffic Filtering and Shaping: Use firewalls and intrusion prevention systems (IPS) to filter out malicious traffic. Traffic shaping can prioritize legitimate traffic and limit the impact of the attack.

* Load Balancing: Distribute incoming traffic across multiple servers or resources. This can help prevent any single server from being overwhelmed and ensure continuity of service.

---
### UltraVNC DSM Plugin Local Privilege Escalation Vulnerability
| *Current Rating:* | CVSS Score   |
|-------------------|--------------|
|  High           |     7.8      |

It was discovered that the service version for the affected resourses which is UltraVNC 1.2.1.7 is the old version which contain vulnerabilities which could be exploited.

#### Evidence
CVE-2022-24750	UltraVNC is a free and open source remote pc access software. A vulnerability has been found in versions prior to 1.3.8.0 in which the DSM plugin module, which allows a local authenticated user to achieve local privilege escalation (LPE) on a vulnerable system. The vulnerability has been fixed to allow loading of plugins from the installed directory. Affected users should upgrade their UltraVNC to 1.3.8.1. Users unable to upgrade should not install and run UltraVNC server as a service. It is advisable to create a scheduled task on a low privilege account to launch WinVNC.exe instead. There are no known workarounds if winvnc needs to be started as a service.


![Screenshot_2024-09-17_05_50_51](https://github.com/user-attachments/assets/c2def66c-dc1d-4fa0-b539-319251d3f475)
![Screenshot_2024-09-17_05_59_21](https://github.com/user-attachments/assets/80f0ab14-f19f-445d-abe6-9c6b6bd699bb)


#### Affected resouces:
`10.10.10.50`


#### Recommendation
Upgrade to the latest version preferably version UltraVNC 1.5.0.0

---
###  Apache Tomcat AJP File Read/Inclusion

| *Current Rating:* | CVSS Score   |
|-------------------|--------------|
|  Critical        |        9.8  |

Allows attackers to read or include files from the server using the AJP connector, leading to information disclosure and possible RCE. Attackers send crafted AJP messages to the server. Tools like `ajpycat` can exploit this.

#### Evidence
`Ghostcat` - CVE-2020-193: When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

This is executed using this command: ` eyewitness --web -f hosts_with_ports.txt -d /home/user/inpt-report  --timeout 30`



![Screenshot_2024-09-17_07_40_49](https://github.com/user-attachments/assets/2625c56c-96b0-4b30-a7ea-f278ad438a5b)

With non-standadised ports:` eyewitness --web -f http_hosts_with_ports.txt -d /home/user/inpt-report --timeout 30 --headless --add-ports 8080,8443,8888,9443`

![Screenshot_2024-09-17_07_46_50](https://github.com/user-attachments/assets/59817030-c765-46d9-a45c-82343d2d7fd4)



#### Affected resource:
* [Reducted]
* [Reducted]
* [Reducted]

#### Recommendation
* Update Tomcat to the latest version.
* Disable the AJP connector if not used.
* Restrict AJP connections to trusted IP addresses.





---
### Weak Tomcat Authentication and Deployment

| *Current Rating:* | CVSS Score   |
|-------------------|--------------|
|  Critical        |        9.0   |

This vulnerability allows attackers to upload and execute malicious `.war` files since Tomcat Manager's credentials are weak and publicly accessible. It results in remote code execution, enabling attackers to run arbitrary code on the server.

#### Evidence

`msfvenom -p java/meterpreter/bind_tcp LHOST=10.10.10.55 LPORT=4444 -f war -o shell_bind.war`

![Screenshot_2024-09-15_19_32_46](https://github.com/user-attachments/assets/a225d706-838e-4bfe-8334-fc1f9f499036)

#### Affected Resourse
`10.10.10.55`

#### Recommendation
* Use strong, unique credentials for the Tomcat Manager.
* Limit access to the Tomcat Manager interface by IP whitelisting.
* Disable the Tomcat Manager and Host Manager applications if not needed.
* Regularly update to the latest version to address security flaws.
* Use Tomcat’s Security Manager to restrict what applications can do.
---
### Arbitrary Code Execution via Base64 Decoding

| *Current Rating:* | CVSS Score   |
|-------------------|--------------|
|    Critical    |      10     |

A Python server that executes base64-encoded payloads is vulnerable to arbitrary code execution. An attacker can send malicious base64-encoded commands, which the server decodes and executes, leading to unauthorized actions such as system compromise, data theft, or further network attacks.

#### Evidence
To generate a base64-encoded payload that executes a TCP bind shell, use:

`msfvenom -p python/meterpreter/bind_tcp LHOST=10.10.10.30 LPORT=4444 -e ruby/base64`


![Screenshot_2024-09-17_06_29_11](https://github.com/user-attachments/assets/74c64ba4-ec47-4076-bfa6-d2524292c8d9)

#### Affected resource:
`10.10.10.30`


#### Recommendation
* Avoid executing user-supplied input directly.
* Run code in a secure environment.
* Run the server with minimal permissions.
* Disable Dangerous Functions: Remove functionality that executes raw user input.



---

## CVSS v3.0 Reference Table
| Qualitative Rating | CVSS Score   |
|--------------------|--------------|
| None/Informational | N/A          |
| Low                | 0.1 – 3.9    |
| Medium             | 4.0 – 6.9    |
| High               | 7.0 – 8.9    |
| Critical           | 9.0 – 10.0   |
