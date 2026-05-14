Incident response by splunk\
\
This Incident Response Analysis Lab demonstrates the process of detecting, investigating, analyzing, and responding to suspicious security activity using Splunk enterprise as centralized SIEM platform. The lab uses the dataset Tier-1_SOC_25events.log, which contains simulated security events representing common attack and investigation scenarios encountered in a real Security Operations Center (SOC) environment. The dataset includes authentication failures, account lockouts, suspicious process execution, malware-related activity, unusual network connections, file integrity events, DNS anomalies, and potentially malicious command execution.\
The purpose of this lab is to simulate a real-world Tier 1 and Tier 2 SOC investigation workflow by using Splunk Search Processing Language (SPL) to identify Indicators of Compromise (IOCs), analyze attacker behavior, correlate related events, and reconstruct an incident timeline. The investigation process focuses on event validation, field extraction, authentication analysis, malware detection, network investigation, suspicious process monitoring, and file activity analysis. In addition to investigation techniques, the lab also introduces operational SOC tasks such as creating dashboards, generating alerts, building lookup tables for enrichment, and scheduling automated reports for continuous monitoring and incident tracking.

This lab demonstrates how Splunk can be used not only for log aggregation and search, but also for incident response operations including detection, triage, threat hunting, containment support, and security reporting. The overall workflow reflects common SOC procedures used in enterprise environments where analysts investigate security alerts, identify malicious activity, document findings, and support mitigation efforts through centralized visibility and correlation of security events.

Step 1 — Confirm Incident Dataset & Establish Investigation Baseline, Validate Total Event Volume, Identify Authentication-Related Security Activity, and Identify Sourcetypes and Host Activity\
\
Using Query for “Confirm Incident Dataset”\
\
index=main source="/var/log/auth.log"

\| table \_time host source sourcetype \_raw\
\
This query was used to confirm that the Linux authentication dataset was successfully ingested into [Splunk Enterprise](https://www.splunk.com/en_us/products/splunk-enterprise.html?utm_source=chatgpt.com) and was fully searchable inside the main index. The query displays the event timestamp, host system, source path, sourcetype classification, and raw log data associated with the authentication logs. This step establishes the initial investigation baseline before incident analysis begins. In a real Security Operations Center (SOC) environment, analysts first validate data visibility and log integrity before performing threat hunting or incident correlation. The results confirmed that authentication events, session activity, and security-related logs were available for investigation.\
\
Using Query for “ Validate Total Event volume “\
\
index=main source="/var/log/auth.log"

\| stats count\
\
This query was used to determine the total number of authentication events indexed from the Linux authentication log source. The results returned 1669 events, confirming that the dataset was actively populated with authentication and security activity. Establishing event volume is an important incident response procedure because analysts must understand the size of the investigation scope before beginning correlation and forensic analysis. This validation also confirmed that Splunk successfully indexed the authentication data without ingestion failure.\
\
Using Query for “ Identify Authentication-Related Security Activity “\
\
index=main source="/var/log/auth.log"

("Failed password" OR "Accepted password" OR "Invalid user" OR "sudo" OR "session opened" OR "session closed")

\| table \_time host \_raw\
\
This query was used to isolate authentication-related security events from the Linux authentication logs. The search focused on failed login attempts, successful authentications, invalid account access attempts, sudo activity, and session creation or termination events. These event categories are commonly investigated during incident response because they may indicate brute-force attacks, unauthorized access attempts, privilege escalation, or suspicious account behavior. The query returned 1318 security-related events, confirming the presence of authentication activity suitable for threat analysis and SOC investigation workflows.\
\
Using Query for “ Identify Sourcetypes and Host Activity “\
\
index=main source="/var/log/auth.log"

\| stats count by sourcetype host\
\
\
This query was used to identify the sourcetypes and host systems associated with the authentication dataset. The results showed that the primary sourcetypes were auth and auth-too_small, both originating from the Linux host system. Sourcetype validation is an important SOC procedure because Splunk relies on sourcetypes for parsing, field extraction, event categorization, and correlation accuracy. Proper sourcetype classification improves search efficiency and supports accurate incident investigation throughout the remainder of the lab.\
\
Step 2 — Field Extraction and Authentication Investigation\
\
Identify Failed Login Attempts Query\
\
index=main source="/var/log/auth.log"

"Failed password"

\| table \_time host \_raw\
\
\
This query was used to isolate failed SSH authentication attempts from the Linux authentication logs. Failed password events are important Indicators of Compromise (IOCs) because they may indicate brute-force attacks, password spraying, unauthorized access attempts, or account enumeration activity. The query displays the event timestamp, affected host system, and raw authentication event data associated with each failed login attempt. During incident response operations, analysts investigate failed authentication activity to identify suspicious login behavior, determine attack frequency, and establish the initial timeline of malicious access attempts.\
\
Extract Attacker Source IP Addresses Query\
\
index=main source="/var/log/auth.log"

"Failed password"

\| rex "from (?\<src_ip\>\[0-9a-fA-F\\\\\]+)"

\| stats count by src_ip

\| sort - count\
\
\
This query was used to extract source IP addresses associated with failed authentication attempts from the Linux authentication logs. The rex command performs regular expression field extraction to identify the attacker IP address stored within the raw SSH authentication events. After extracting the src_ip field, the query counts the number of failed login attempts associated with each source IP address and sorts the results in descending order based on frequency. Source IP extraction is a critical incident response and threat hunting procedure because attacker IP addresses become Indicators of Compromise (IOCs) used for alerting, correlation, firewall blocking, threat intelligence enrichment, and mitigation activities.\
\
Identify Targeted Usernames Query\
\
index=main source="/var/log/auth.log"

("Failed password" OR "Invalid user")

\| rex "(?:Failed password for (?:invalid user )?\|Invalid user )(?\<user\>\S+)"

\| stats count by user

\| sort – count\
\
\
This query was used to identify usernames targeted during failed authentication attempts and invalid account access activity. The rex command extracts usernames from SSH authentication logs using regular expression field extraction. After extraction, the query counts the number of authentication events associated with each targeted account and sorts the results by frequency. Username analysis is important during incident response because attackers commonly perform account enumeration, brute-force attacks, and credential guessing against administrative or commonly used usernames. Identifying repeatedly targeted accounts helps analysts prioritize investigation and evaluate potential account compromise risks.\
\
Investigate Privilege Escalation and Sudo Activity Query\
\
index=main source="/var/log/auth.log"\
sudo\
\| table \_time host \_raw\
\
\
This query was used to investigate sudo activity and potential privilege escalation events within the Linux authentication logs. Sudo-related authentication events may indicate administrative access, elevated command execution, privilege escalation attempts, or unauthorized use of privileged accounts. The query displays the event timestamp, affected host system, and raw authentication event data associated with sudo activity. During incident response investigations, analysts review privileged account behavior to determine whether elevated access was abused, whether suspicious commands were executed, and whether attackers attempted to gain higher-level permissions within the system.\
\
\
\
Step 3 — Brute-Force Detection and Authentication Correlation

Now, brute-force behavior, repeated authentication failures, suspicious login patterns, and possible account targeting activity. In a real SOC environment, analysts correlate failed authentication attempts over time to determine whether an attacker is attempting credential guessing, password spraying, or unauthorized access.

Identify Repeated Failed Login Attempts

Query

index=main source="/var/log/auth.log"\
"Failed password"\
\| rex "from (?\<src_ip\>\[0-9a-fA-F\\\\\]+)"\
\| stats count by src_ip\
\| sort – count\
\
\
\
\
This query was used to identify repeated failed login attempts from specific source IP addresses. The results showed 15 failed authentication attempts originating from the source IP address ::1, which is the IPv6 loopback address representing the local system with ip address of 127.0.0.1 Repeated failed authentication attempts may indicate brute-force activity, incorrect credential usage, or authentication testing activity. The query extracted source IP addresses from the Linux authentication logs and counted how many failed login attempts were associated with each address. The rex command extracts the source IP address from SSH authentication events, while the stats command counts the number of failed authentication attempts associated with each IP address. Sorting the results by count helps identify systems generating the highest number of failed logins. Repeated authentication failures from the same source may indicate brute-force activity, password spraying, or unauthorized access attempts targeting the Linux system. So

Identify Targeted Accounts During Failed Logins

Query

index=main source="/var/log/auth.log"\
("Failed password" OR "Invalid user")\
\| rex "(?:Failed password for (?:invalid user )?\|Invalid user )(?\<user\>\S+)"\
\| stats count by user\
\| sort - count


Detect Authentication Activity Over Time

Query

index=main source="/var/log/auth.log"\
"Failed password"\
\| bucket \_time span=5m\
\| stats count by \_time\
\| sort \_time

This query was used to analyze failed authentication activity over time by grouping events into five-minute intervals. The bucket command organizes authentication events into time windows, while the stats command counts the number of failed logins occurring during each interval. Time-based authentication analysis helps identify spikes in failed login activity that may indicate brute-force attacks or automated authentication attempts. This type of timeline analysis is commonly used in SOC environments to detect suspicious authentication behavior and monitor attack frequency.

Investigate Successful Logins After Failed Attempts

Query

index=main source="/var/log/auth.log"\
("Failed password" OR "Accepted password")\
\| table \_time host \_raw

\
\
\
\
This query was used to investigate successful authentication events occurring alongside failed login attempts. Reviewing successful logins after repeated authentication failures is important during incident response because attackers may eventually gain access after brute-force or credential guessing attempts. The query displays authentication activity in chronological order, allowing investigation of suspicious login patterns and potential account compromise activity.\
\
\
Step 4 — Suspicious Sudo Activity and Privilege Escalation Investigation


This step focuses on investigating sudo activity and privileged commands inside the Linux authentication logs. In incident response investigations, sudo events are important because attackers often try to gain elevated privileges after accessing a system.

Investigate Sudo Activity

 Query

index=main source="/var/log/auth.log"\
sudo\
\| table \_time host \_raw

\
\
\
\
\
This query was used to identify sudo activity from the Linux authentication logs. Sudo events show when elevated or administrative commands were executed on the system. Reviewing sudo activity helps identify privileged access, administrative actions, and possible privilege escalation attempts during an investigation. The results display the event time, host system, and the raw sudo-related log events.

 Count Sudo Activity

 Query

index=main source="/var/log/auth.log"\
sudo\
\| stats count

\
\
This query was used to count the total number of sudo-related events found in the authentication logs. Counting privileged activity helps measure how much elevated access activity occurred on the system during the investigation period. A high number of sudo events may indicate heavy administrative usage or suspicious privileged behavior.

 Identify Users Running Sudo Commands

Query

index=main source="/var/log/auth.log"\
sudo\
\| rex "for (?\<user\>\w+)"\
\| stats count by user\
\| sort – count\
\
\
\

 View Sudo Activity Timeline

 Query

index=main source="/var/log/auth.log"\
sudo\
\| bucket \_time span=10m\
\| stats count by \_time\
\| sort \_time

\
\
\
\
This query was used to analyze sudo activity over time by grouping events into ten-minute intervals. This helps visualize when elevated command activity occurred during the investigation period. Timeline analysis is useful during incident response because it helps correlate privileged activity with authentication attempts, suspicious commands, or other security events.\
\
Step 5 — Session Activity and User Access Investigation


This step focuses on investigating session activity and user access behavior inside the Linux authentication logs. Session events help track when users accessed the system and when sessions were closed. During incident response investigations, reviewing session activity helps identify login behavior, user access patterns, and possible suspicious account activity.

Investigate Session Activity\
\
Query


index=main source="/var/log/auth.log"\
("session opened" OR "session closed")\
\| table \_time host \_raw

\
\
\
This query was used to investigate session activity from the Linux authentication logs. The results showed when user sessions were opened or closed on the system. Session activity helps track login behavior and shows when users accessed or exited the system during the investigation period.

 Count Session Events

 Query

index=main source="/var/log/auth.log"\
("session opened" OR "session closed")\
\| stats count

\
\
\
This query was used to count the total number of session-related events found in the Linux authentication logs. Counting session activity helps measure how much user access activity occurred on the system during the investigation.

 Identify Users with Session Activity

 Query

index=main source="/var/log/auth.log"\
("session opened" OR "session closed")\
\| rex "for user (?\<user\>\w+)"\
\| stats count by user\
\| sort - count

\
This query was used to identify which user accounts opened or closed sessions on the Linux system. The query extracts usernames from the session events and counts how many session activities were associated with each account. This helps track user access behavior during the investigation.

 View Session Activity Over Time

 Query

index=main source="/var/log/auth.log"\
("session opened" OR "session closed")\
\| bucket \_time span=10m\
\| stats count by \_time\
\| sort \_time

\
\
\
\
This query was used to analyze session activity over time by grouping events into ten-minute intervals. Timeline analysis helps visualize when user session activity occurred during the investigation period and helps correlate user access with other authentication or security events.\
\
Step-6 Threat Hunting and Suspicious Authentication Activity


This step focuses on searching for suspicious authentication behavior and unusual activity inside the Linux authentication logs. Threat hunting helps identify potentially malicious behavior that may not immediately trigger alerts during an investigation.

 Identify Invalid User Attempts

 Query

index=main source="/var/log/auth.log"\
"Invalid user"\
\| table \_time host \_raw

\
\
\
This query was used to identify invalid user authentication attempts from the Linux authentication logs. Invalid user events occur when login attempts are made against usernames that do not exist on the system. These events may indicate account enumeration attempts or unauthorized access activity during the investigation.

 Count Invalid User Attempts

 Query

index=main source="/var/log/auth.log"\
"Invalid user"\
\| stats count\
\
\

Invalid Usernames

 Query

index=main source="/var/log/auth.log"\
"Invalid user"\
\| rex "Invalid user (?\<user\>\S+)"\
\| stats count by user\
\| sort – count\
\

 View Suspicious Authentication Activity Over Time

 Query

index=main source="/var/log/auth.log"\
("Failed password" OR "Invalid user")\
\| bucket \_time span=10m\
\| stats count by \_time\
\| sort \_time

\
\
This query was used to analyze suspicious authentication activity over time by grouping failed login attempts and invalid user events into ten-minute intervals. Timeline analysis helps identify spikes in suspicious authentication behavior and helps visualize when potential attack activity occurred during the investigation period.\
\
Step 7 — Lookup Table and IOC Enrichment


This step focuses on using lookup tables to enrich authentication events with additional investigation information. In SOC investigations, lookups help attach labels, categories, or threat information to Indicators of Compromise (IOCs) such as source IP addresses.

creating a simple CSV lookup file

| src_ip        | label           |
|---------------|-----------------|
| ::1           | Localhost       |
| 192.168.1.5   | Internal Device |
| 45.155.205.12 | Suspicious IP   |

Uploading the CSV into [Splunk Enterprise](https://www.splunk.com/en_us/products/splunk-enterprise.html?utm_source=chatgpt.com) as a lookup table named: I put the name of file: ip_lookup.csv

 Extract Source IP Addresses

 Query

index=main source="/var/log/auth.log"\
"Failed password"\
\| rex "from (?\<src_ip\>\[0-9a-fA-F\\\\\]+)"\
\| table \_time src_ip \_raw\
\

This query was used to extract source IP addresses from failed authentication events in the Linux authentication logs. The extracted IP addresses become Indicators of Compromise (IOCs) that can later be enriched with additional information using a lookup table.

 Apply Lookup Enrichment

 Query

index=main source="/var/log/auth.log"\
"Failed password"\
\| rex "from (?\<src_ip\>\[0-9a-fA-F\\\\\]+)"\
\| lookup ip_lookup src_ip OUTPUT label\
\| table \_time src_ip label \_raw

\
\
\
This query was used to enrich authentication events using a lookup table. The lookup matches extracted source IP addresses with labels stored inside the CSV file. Enrichment helps analysts quickly identify whether an IP address belongs to localhost, an internal device, or a suspicious system during the investigation.

 Count Events by Lookup Label

 Query

index=main source="/var/log/auth.log"

"Failed password"

\| rex "from (?\<src_ip\>\[0-9a-fA-F\\\\\]+)"

\| lookup ip_lookup src_ip OUTPUT label

\| table \_time src_ip label \_raw

\
\
\
This query extracted the source IP address from failed login events and matched it with the ip_lookup lookup table. The lookup added a readable label to the IP address, which makes the investigation easier to understand. The results showed 15 failed login events with the extracted src_ip and its lookup label. This helps identify whether the failed login activity came from localhost, an internal system, or another labeled source.

 View Enriched Authentication Activity

 Query

index=main source="/var/log/auth.log"\
"Failed password"\
\| rex "from (?\<src_ip\>\[0-9a-fA-F\\\\\]+)"\
\| lookup ip_lookup src_ip OUTPUT label\
\| sort - \_time\
\| table \_time src_ip label host

\
\
This query was used to display enriched authentication activity from the Linux authentication logs. The results show the event time, extracted source IP address, lookup label, and host system associated with failed authentication attempts. Lookup enrichment helps simplify incident investigations by attaching readable information to Indicators of Compromise.\
\
\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\
\
\
Step 8 — Scheduled Reports and Alert Investigation


This step focuses on creating scheduled reports and alerts for suspicious authentication activity inside Splunk enterprise. In a SOC environment, scheduled reports and alerts help analysts continuously monitor failed logins, suspicious access attempts, and authentication-related threats.

 Create Failed Login Monitoring Query

 Query

index=main source="/var/log/auth.log"\
"Failed password"\
\| rex "from (?\<src_ip\>\[0-9a-fA-F\\\\\]+)"\
\| stats count by src_ip\
\| sort - count

\
This query was used to monitor failed authentication attempts from the Linux authentication logs. The query extracts source IP addresses from failed login events and counts how many failed attempts were associated with each address. This type of query is commonly used for scheduled reports and brute-force monitoring in SOC environments.

Save as Scheduled Report\
\
\


This step was used to create a scheduled report for failed authentication monitoring. Scheduled reports allow Splunk to automatically run searches at specific intervals and continuously monitor suspicious activity without requiring manual investigation each time.

 Create Failed Login Alert

 Query

index=main source="/var/log/auth.log"\
"Failed password"\
\| rex "from (?\<src_ip\>\[0-9a-fA-F\\\\\]+)"\
\| stats count by src_ip\
\| where count \>= 5

This query was used to identify source IP addresses generating five or more failed login attempts. The results showed that the source IP address ::1 generated 15 failed authentication attempts in the Linux authentication logs.

Save as Alert\
\

This step was used to create an automated alert for suspicious failed login activity. The alert triggers whenever the query detects failed authentication attempts exceeding the defined threshold. Alerts help SOC analysts quickly identify suspicious activity and respond to possible attacks in real-time.\
\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\
\
\
\
Step 9 — Incident Timeline and Investigation Summary


This final step focuses on building the authentication timeline and summarizing the suspicious activity identified during the Incident Response Analysis Lab. Timeline analysis helps organize authentication events in chronological order and provides a clearer picture of how the activity occurred during the investigation.

Build Authentication Timeline

Query

index=main source="/var/log/auth.log"\
("Failed password" OR "Invalid user" OR "session opened" OR "session closed" OR "sudo")\
\| table \_time host \_raw\
\| sort \_time

\
\
\
\
\
\
\
The output shows 1318 events but 10 events screenshotted. So This query was used to build a timeline of authentication and session activity from the Linux authentication logs. The results showed session opened events, session closed events, root activity, and other authentication-related events in chronological order. Viewing events as a timeline helps organize the investigation and provides a clearer view of system access activity during the incident response process.\
\
The output is showing:\
session opened events,\
session closed events,\
privileged/root activity,\
authentication-related activity,

All are in chronological order

The logs show:

LightDM session activity,\
root session activity,\
CRON session activity,\
systemd session activity,\
pkexec privileged session activity.

Count Security-Related Authentication Events

Query

index=main source="/var/log/auth.log"\
("Failed password" OR "Invalid user" OR "sudo")\
\| stats count

\
\
\
\
This query was used to count the total number of security-related authentication events found during the investigation. The query focused on failed login attempts, invalid user activity, and sudo-related events from the Linux authentication logs.

View Authentication Activity by Event Type

Query

index=main source="/var/log/auth.log"\
\| eval activity=case(\
searchmatch("Failed password"),"Failed Login",\
searchmatch("Invalid user"),"Invalid User",\
searchmatch("sudo"),"Sudo Activity",\
searchmatch("session opened"),"Session Opened",\
searchmatch("session closed"),"Session Closed"\
)\
\| stats count by activity\
\

This query was used to group authentication events by activity type. The query categorized failed logins, invalid user attempts, sudo activity, and session events into separate activity groups. Organizing events by category helps simplify the investigation and provides a better overview of authentication-related activity inside the logs.

Final Incident Investigation Overview

Query

index=main source="/var/log/auth.log"\
\| stats count by sourcetype

\
\
This query was used to display the sourcetypes associated with the Linux authentication logs. The results showed that most events were classified as auth, while a smaller number of events were classified as auth-too_small. This confirmed that the authentication dataset remained searchable throughout the incident response investigation.\
\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\
\
Step 10 — Dashboard Creation and Investigation Visualization\
\
This final step focuses on creating a simple SOC dashboard inside Splunk enterprise to visualize authentication activity, failed login attempts, session activity, and investigation results from the Linux authentication logs. Dashboards help analysts quickly monitor suspicious activity and organize investigation data in one location.

 Create Failed Login Dashboard Panel

 Query

index=main source="/var/log/auth.log"\
"Failed password"\
\| rex "from (?\<src_ip\>\[0-9a-fA-F\\\\\]+)"\
\| stats count by src_ip\
\| sort - count


 Create Session Activity Dashboard Panel

 Query

index=main source="/var/log/auth.log"\
("session opened" OR "session closed")\
\| stats count by host

\
\
\
This dashboard panel was used to visualize session activity from the Linux authentication logs. The results showed that the host system user generated 1084 session-related events during the investigation period.

 Create Sudo Activity Dashboard Panel

 Query

index=main source="/var/log/auth.log"\
sudo\
\| stats count by host

\
\
\
\
This dashboard panel was used to visualize sudo-related activity from the Linux authentication logs. The results showed that the host system user generated 625 sudo-related events during the investigation period.

Save Dashboard\
\


\
Using these panel titles:

Failed Login Attempts by Source IP\
Session Activity Overview\
Sudo Activity Monitoring\
\
This step was used to create a dashboard for visualizing authentication and investigation activity from the Linux authentication logs. The dashboard combined failed login monitoring, session activity, and sudo-related events into a single investigation view for easier SOC monitoring and analysis.\
\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\
\
Visualization\
\
Panel 1 — Failed Login Attempts by Source IP\
\
Query\
\
index=main source="/var/log/auth.log"

"Failed password"

\| rex "from (?\<src_ip\>\[0-9a-fA-F\\\\\]+)"

\| stats count by src_ip\
\| sort – count\
\
\
\
\
\
\
Panel 2 — Session Activity Overview

\
 query


index=main source="/var/log/auth.log"\
("session opened" OR "session closed")\
\| stats count by host

\
\
Panel 3 — Sudo Activity Monitoring\
\
Query\
\
index=main source="/var/log/auth.log"

sudo

\| stats count by host\
\
