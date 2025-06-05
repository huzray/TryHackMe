@@ -1,317 +1,318 @@
![image](https://github.com/user-attachments/assets/785d3ba5-cd52-409c-9828-074f46eebf47)


# Volt-Typhoon-TryHackMe 


This repo contains my blue team walkthrough for the Volt Typhoon challenge on TryHackMe, focusing on detecting and analyzing threat activity using Splunk for log analysis and incident response.



# Volt Typhoon

**Scenario:**  
The SOC has detected suspicious activity indicative of an advanced persistent threat (APT) group known as Volt Typhoon, notorious for targeting high-value organizations. Assume the role of a security analyst and investigate the intrusion by retracing the attacker's steps.

You have been provided with various log types from a two-week time frame during which the suspected attack occurred. Your ability to research the suspected APT and understand how they maneuver through targeted networks will prove to be just as important as your Splunk skills.

Connect to OpenVPN or use the AttackBox to access Splunk. Please give the machine about 4 minutes to boot.

**Splunk Credentials**  
- Username: `volthunter`  
- Password: `voltyp1010`  
- Splunk URL: `http://MACHINE_IP:8000`

# Initial Access
Volt Typhoon often gains initial access to target networks by exploiting vulnerabilities in enterprise software. In recent incidents, Volt Typhoon has been observed leveraging vulnerabilities in Zoho ManageEngine ADSelfService Plus, a popular self-service password management solution used by organizations.

Answer the questions below
### Question 1
### Comb through the ADSelfService Plus logs to begin retracing the attacker’s steps. At what time (ISO 8601 format) was Dean's password changed and their account taken over by the attacker?

The first step was to check what data we were working with by running a broad search query in Splunk:

```
index=*
```

## Checking Sourcetype

Next, I checked the available sourcetypes to focus on relevant logs. Since we are going through adservice plus logs, I found and clicked on the appropriate sourcetype in Splunk to narrow down the data.

![image](https://github.com/user-attachments/assets/c331638f-c6bb-4563-8535-9e8c8e9a31b6)

## Searching for Password Changes

Since we were looking for activity related to a user named **dean** and his password change, I ran a query filtering by username and action, **while keeping the adservice plus index** to stay focused on relevant logs:

```
index=adserviceplus username=dean action="password change"
```
To pinpoint when the password change occurred, I filtered the logs using `status=completed` along with the index to get the exact timestamp of the event:

![image](https://github.com/user-attachments/assets/102f393f-d81c-4fc0-9c52-bf45a25d8180)


Here is out answer: 2024-03-24T11:10:22


### Question 2
### Shortly after Dean's account was compromised, the attacker created a new administrator account. What is the name of the new account that was created?

## Investigating Dean-Admin's WMIC Activity

I searched the logs for WMIC activity related to the user **dean-admin** using this Splunk query:

```
index=* sourcetype=wmic username="dean-admin"
| table _time, ip_address, command, username
```

I used the `table` command to display only the most relevant fields—timestamp, IP address, command, and username—making the output cleaner and easier to analyze.
![image](https://github.com/user-attachments/assets/9c2dc49c-3f4e-4af2-8410-4742c17523ff)

Answer: voltyp-admin

## Execution

Volt Typhoon is known to exploit Windows Management Instrumentation Command-line (WMIC) for various execution techniques. They use WMIC to gather information and dump valuable databases, enabling them to infiltrate and exploit target networks. By leveraging "living off the land" binaries (LOLBins), they blend in with legitimate system activity, making detection more challenging.

## Question 3
In an information gathering attempt, what command does the attacker run to find information about local drives on server01 & server02?

Using the previous query to filter logs by host and command, we were able to identify the exact command the attacker ran to find information about local drives on `server01` and `server02`.
![image](https://github.com/user-attachments/assets/9d6247df-47a3-4662-8a70-11456e4ef49c)

Click exclude from results

Right here is the command
![image](https://github.com/user-attachments/assets/9c475e03-e458-4d98-8046-1d8df74e8d01)
```
wmic /node:server01,server02 logicaldisk get caption, filesystem, freespace, size, volumename
```
What it does:
This command queries the computers server01 and server02 to retrieve information about their disk drives, including:

Caption: Drive letter (e.g., C:)

FileSystem: Type of file system (e.g., NTFS)

FreeSpace: Available free space on the drive

Size: Total size of the drive

VolumeName: Label/name of the drive

### Question 4
### The attacker uses ntdsutil to create a copy of the AD database. After moving the file to a web server, the attacker compresses the database. What password does the attacker set on the archive?

![image](https://github.com/user-attachments/assets/b877a81f-8203-42e6-a8d6-12c1910a473d)
go on page 2 and look it up.


## Persistence

Our target APT frequently employs web shells as a persistence mechanism to maintain a foothold. They disguise these web shells as legitimate files, enabling remote control over the server and allowing them to execute commands undetected.

### Question 5
### To establish persistence on the compromised server, the attacker created a web shell using base64 encoded text. In which directory was the web shell placed?

![image](https://github.com/user-attachments/assets/dc13db47-77fa-4ba3-84c7-0797efcdf858)
### 🔍 Detection: Web Shell Deployment via Base64 on Compromised Host

To investigate potential persistence techniques, we used the following **Splunk query**:

```spl
index=* sourcetype=wmic username="dean-admin"  
| search command="*decode*" OR command="*echo*" OR command="*copy*" OR command="*move*"  
| table _time, ip_address, command  
| sort -_time
```

The query looks for WMIC commands run by the user dean-admin that contain terms commonly used in web shell creation. Commands like decode, echo, copy, and move are typically used to write and deploy base64-decoded payloads to disk.

The answer is C:\Windows\Temp\


## Defense Evasion
Volt Typhoon utilizes advanced defense evasion techniques to significantly reduce the risk of detection. These methods encompass regular file purging, eliminating logs, and conducting thorough reconnaissance of their operational environment.

### In an attempt to begin covering their tracks, the attackers remove evidence of the compromise. They first start by wiping RDP records. What PowerShell cmdlet does the attacker use to remove the “Most Recently Used” record?


![image](https://github.com/user-attachments/assets/fd3295d1-e4bd-4e94-b1c1-b331772ee967)
### How I Found the PowerShell Cmdlet Used to Remove RDP MRU Records

I used the following Splunk query to search for PowerShell commands related to removal actions:

```spl
index=* sourcetype="powershell" *remove*  
| table _time, CommandLine
| sort -_time
```
This query looks for any PowerShell command that includes the word “remove,” which is commonly used in commands that delete files, registry keys, or values.



### The APT continues to cover their tracks by renaming and changing the extension of the previously created archive. What is the file name (with extension) created by the attackers?

![image](https://github.com/user-attachments/assets/9043092c-9ef0-4b5c-a532-76f9212db2f0)
Changing the file extension from `.7z` (a compressed archive) to `.gif` (an image file) is a common defense evasion tactic. This makes the malicious file less likely to be noticed or flagged by security tools and system administrators.

The answer is cl64.gif


### Under what regedit path does the attacker check for evidence of a virtualized environment?

![image](https://github.com/user-attachments/assets/3f47a7a0-1439-4767-8cca-0bf1032259d0)
 ### Virtualization Check via Registry

To detect whether the system is running in a virtualized environment, the attacker used the following PowerShell command:

```powershell
Get-ItemProperty -Path "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control"
```


# Credential Access

Volt Typhoon often combs through target networks to uncover and extract credentials from a range of programs. Additionally, they are known to access hashed credentials directly from system memory.

### Using reg query, Volt Typhoon hunts for opportunities to find useful credentials. What three pieces of software do they investigate?
Answer Format: Alphabetical order separated by a comma and space.

![image](https://github.com/user-attachments/assets/7c980472-0d81-4eaf-a206-a47d6859d3d1)

To view full PowerShell registry queries, I used the following Splunk query:

```spl
index=* sourcetype=powershell "reg query" 
| rex field=_raw "CommandLine=(?<FullCommandLine>[^\n]+)"
| table _time, FullCommandLine
| sort -_time
```

This query searches for PowerShell events containing "reg query". I used the rex command with the field=_raw option to extract the full command line from the raw event data into a new field called FullCommandLine. This helps bypass cases where the standard CommandLine field is truncated or missing.

the answer is OpenSSH PuTTY RealVNC

### What is the full decoded command the attacker uses to download and run mimikatz?

![image](https://github.com/user-attachments/assets/3c8d1e66-d8d2-46f4-8356-72f3dd5bce87)

To identify the full PowerShell command used by the attacker (including potentially obfuscated activity like downloading and executing Mimikatz), I used the following Splunk query:

```spl
index=* sourcetype=powershell CommandLine="*" 
| rex field=_raw "CommandLine=(?<FullCommandLine>[^\n]+)" 
| table FullCommandLine
```

![image](https://github.com/user-attachments/assets/40871a63-61e2-4796-b129-cf4523ee74c2)




## Discovery
Volt Typhoon uses enumeration techniques to gather additional information about network architecture, logging mechanisms, successful logins, and software configurations, enhancing their understanding of the target environment for strategic purposes.

## Lateral Movement
The APT has been observed moving previously created web shells to different servers as part of their lateral movement strategy. This technique facilitates their ability to traverse through networks and maintain access across multiple systems.


The attacker uses wevtutil, a log retrieval tool, to enumerate Windows logs. What event IDs does the attacker search for?
Answer Format: Increasing order separated by a space.


The attacker uses `wevtutil`, a Windows event log retrieval tool, to enumerate specific event IDs from the logs.

## Splunk Query Used

```splunk
index=* sourcetype=powershell CommandLine=wevtutil
| rex field=_raw "CommandLine=(?<FullCommandLine>[^\n]+)"
| table FullCommandLine
```

![image](https://github.com/user-attachments/assets/ca2b2cab-2a88-439e-ac97-206964ac2aa5)



Moving laterally to server-02, the attacker copies over the original web shell. What is the name of the new web shell that was created?

![image](https://github.com/user-attachments/assets/8a27b172-3dec-4b39-8a86-3569e4309cba)


The attacker moves laterally to `server-02` by copying the original web shell to a new location.

## Splunk Query Used

```splunk
index=* sourcetype=powershell 
| rex field=_raw "CommandLine=(?<FullCommandLine>[^\n]+)"
| table _time, FullCommandLine
```
the answer is AuditReport.jspx


## Collection
During the collection phase, Volt Typhoon extracts various types of data, such as local web browser information and valuable assets discovered within the target environment.

The attacker is able to locate some valuable financial information during the collection phase. What three files does Volt Typhoon make copies of using PowerShell?
Answer Format: Increasing order separated by a space.

![image](https://github.com/user-attachments/assets/48127961-bd30-4314-abe2-3131c5c4c47a)
![image](https://github.com/user-attachments/assets/d6f31fc2-2c62-4f7b-af76-9a6b3dcf6768)

the answer is 2022.csv 2023.csv 2024.csv

## C2
Volt Typhoon utilizes publicly available tools as well as compromised devices to establish discreet command and control (C2) channels.

## Cleanup
To cover their tracks, the APT has been observed deleting event logs and selectively removing other traces and artifacts of their malicious activities.

The attacker uses netsh to create a proxy for C2 communications. What connect address and port does the attacker use when setting up the proxy?
Answer Format: IP Port


![image](https://github.com/user-attachments/assets/6544c306-dcee-445c-b3ca-4a38fecbfc6b)

## Splunk Query Used

```splunk
index=* sourcetype=wmic *netsh*
```
The attacker used wmic instead of PowerShell to run netsh because WMIC is less monitored and can help evade detection. It's a stealthier way to execute system commands without triggering PowerShell-specific alerts.



To conceal their activities, what are the four types of event logs the attacker clears on the compromised system?


https://github.com/user-attachments/assets/411ad3d5-a5db-4a3e-85c4-8e0e592c8350
![image](https://github.com/user-attachments/assets/ba3b3e66-ce3e-44c8-bd29-05e39a9d5d66)


Note
If we go back to the previous questions, we can see the attacker uses the wevtutil command to enumerate and interact with event logs. In this case, they used:

```
wevtutil cl Application Security Setup System
```











More actions




