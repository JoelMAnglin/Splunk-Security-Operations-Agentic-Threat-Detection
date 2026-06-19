# Agentic SOC Analyst Report

- Generated: 2026-06-18 17:01:40 UTC
- Mode: `all`
- Time range: `-24h` to `now`
- Findings: `6`

## Executive Summary

1. **CRITICAL** - Impossible Travel Candidate: Sequences successful logins by user and flags country changes within a short travel window. Top evidence: user=carla.ruiz, src_country=US, prev_country=NL, minutes=2.4, src_ip=10.20.5.230, prev_ip=10.10.2.22. Recommended action: Validate source geolocation, review MFA prompts, and check cloud/SaaS activity immediately after the later login.
2. **CRITICAL** - Suspicious Living-off-the-land Process Chain: Finds suspicious Windows process names and scores encoded command or downloader behavior. Top evidence: endpoint_host=api-02, user=svc_ci_cd, process_name=powershell.exe, parents=['explorer.exe', 'services.exe', 'sshd'], risk=70. Recommended action: Collect the full process tree, isolate if this is unexpected, inspect command line content, and pivot to network egress from the same host.
3. **CRITICAL** - Cloud Privilege Escalation or Persistence: Finds sensitive AWS-style IAM and STS actions associated with persistence or privilege escalation. Top evidence: userIdentity.arn=arn:aws:iam::123456789012:user/devon.lee, actions=['AssumeRole', 'AttachUserPolicy', 'ConsoleLogin', 'CreateAccessKey', 'PutUserPolicy', 'UpdateAssumeRolePolicy'], src_ips=['10.10.1.135', '10.10.1.137', '10.10.1.160', '10.10.1.170', '10.10.1.179', '10.10.1.198', '10.10.1.237', '10.10.1.4', '10.10.1.45', '10.10.1.60', '10.10.1.7', '10.10.2.13', '10.10.2.141', '10.10.2.151', '10.10.2.154', '10.10.2.160', '10.10.2.179', '10.10.2.208', '10.10.2.32', '10.10.2.46', '10.10.2.54', '10.10.2.79', '10.20.5.134', '10.20.5.137', '10.20.5.171', '10.20.5.174', '10.20.5.195', '10.20.5.207', '10.20.5.213', '10.20.5.33', '10.20.5.41', '10.20.5.7', '10.20.5.93', '103.77.240.9', '172.16.8.111', '172.16.8.113', '172.16.8.126', '172.16.8.139', '172.16.8.140', '172.16.8.173', '172.16.8.179', '172.16.8.216', '172.16.8.33', '172.16.8.37', '172.16.8.39', '172.16.8.55', '172.16.8.75', '172.16.8.76', '185.220.101.33', '198.51.100.42', '203.0.113.18', '23.91.44.10', '45.66.12.88', '71.19.144.41', '91.240.118.20'], risk=1550. Recommended action: Review whether the principal should perform IAM changes, inspect CloudTrail activity before and after, and rotate credentials if unauthorized.
4. **HIGH** - Brute Force or Password Spray Candidate: Finds accounts with repeated failures, multiple source addresses, or concentrated failed login bursts. Top evidence: user=erin.patel, src_ips=['10.20.5.156', '10.20.5.74', '103.77.240.9', '172.16.8.100', '45.66.12.88'], failures=10, src_count=5. Recommended action: Validate whether the user expected these attempts, review MFA outcome, and pivot into successful logins from the same source addresses.
5. **HIGH** - Suspicious Endpoint Network Egress: Finds endpoint network connections to high-risk ports such as 4444, 9001, 8080, and RDP. Top evidence: endpoint_host=web-02, user=erin.patel, dest_port=4444, dest_ips=['71.19.144.41', '91.240.118.20'], connections=6. Recommended action: Pivot to process_name and command_line on the same host, then validate whether the destination is known business infrastructure.
6. **HIGH** - Risky Web or API Client: Ranks web clients by attack volume, error rate, and latency impact. Top evidence: client_ip=203.0.113.18, user_agent=Edge, attacks=12, error_rate=100.00, risk=152. Recommended action: Review request paths, WAF decisions, authentication attempts, and whether the source has related identity or network activity.

## Impossible Travel Candidate

- Severity: `critical`
- Domain: `identity`
- MITRE: `Initial Access: Valid Accounts (T1078)`
- Rows returned: `5`

### Analyst Assessment

Impossible Travel Candidate: Sequences successful logins by user and flags country changes within a short travel window. Top evidence: user=carla.ruiz, src_country=US, prev_country=NL, minutes=2.4, src_ip=10.20.5.230, prev_ip=10.10.2.22. Recommended action: Validate source geolocation, review MFA prompts, and check cloud/SaaS activity immediately after the later login.

### SPL

```spl
search index=lab_auth action=success src_country=* | sort 0 user _time | streamstats current=f last(_time) as prev_time last(src_country) as prev_country last(src_ip) as prev_ip by user | eval minutes=round((_time-prev_time)/60,1) | where isnotnull(prev_country) AND src_country!=prev_country AND minutes>0 AND minutes<180 | table _time user src_country prev_country src_ip prev_ip minutes mfa_result | sort - _time | head 10
```

### Evidence

| _time | user | src_country | prev_country | src_ip | prev_ip | minutes | mfa_result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-06-18T13:59:41.000+00:00 | carla.ruiz | US | NL | 10.20.5.230 | 10.10.2.22 | 2.4 | push approved |
| 2026-06-18T13:59:04.000+00:00 | grace.hall | US | NL | 10.10.1.17 | 10.10.1.133 | 2.2 | totp approved |
| 2026-06-18T13:57:15.000+00:00 | carla.ruiz | NL | US | 10.10.2.22 | 10.10.2.167 | 2.0 | totp approved |
| 2026-06-18T13:56:52.000+00:00 | grace.hall | NL | US | 10.10.1.133 | 103.77.240.9 | 20.2 | push approved |
| 2026-06-18T13:55:34.000+00:00 | bob.smith | CN | US | 10.20.5.161 | 10.20.5.197 | 25.1 | totp approved |

## Suspicious Living-off-the-land Process Chain

- Severity: `critical`
- Domain: `endpoint`
- MITRE: `Execution: Command and Scripting Interpreter (T1059)`
- Rows returned: `5`

### Analyst Assessment

Suspicious Living-off-the-land Process Chain: Finds suspicious Windows process names and scores encoded command or downloader behavior. Top evidence: endpoint_host=api-02, user=svc_ci_cd, process_name=powershell.exe, parents=['explorer.exe', 'services.exe', 'sshd'], risk=70. Recommended action: Collect the full process tree, isolate if this is unexpected, inspect command line content, and pivot to network egress from the same host.

### SPL

```spl
search index=lab_endpoint event_type=process process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe") | spath input=_raw path=host output=endpoint_host | eval endpoint_host=coalesce(endpoint_host,host), encoded=if(match(command_line,"(?i)-enc|-encodedcommand|frombase64string"),1,0), download=if(match(command_line,"(?i)invoke-webrequest|curl|wget|bitsadmin|http://"),1,0), risk=20+encoded*50+download*35 | stats count as executions max(risk) as risk values(parent_process) as parents values(command_line) as command_lines by endpoint_host user process_name | sort - risk executions | head 10
```

### Evidence

| endpoint_host | user | process_name | executions | risk | parents | command_lines |
| --- | --- | --- | --- | --- | --- | --- |
| api-02 | svc_ci_cd | powershell.exe | 6 | 70 | ['explorer.exe', 'services.exe', 'sshd'] | powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgA |
| db-01 | frank.kim | powershell.exe | 6 | 70 | ['services.exe', 'teams.exe', 'winword.exe'] | powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgA |
| mac-exec-01 | bob.smith | powershell.exe | 6 | 70 | ['launchd', 'teams.exe'] | powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgA |
| api-01 | devon.lee | powershell.exe | 4 | 70 | ['sshd', 'winword.exe'] | powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgA |
| api-01 | grace.hall | powershell.exe | 4 | 70 | ['explorer.exe', 'launchd'] | powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgA |

## Cloud Privilege Escalation or Persistence

- Severity: `critical`
- Domain: `cloud`
- MITRE: `Privilege Escalation: Account Manipulation (T1098)`
- Rows returned: `5`

### Analyst Assessment

Cloud Privilege Escalation or Persistence: Finds sensitive AWS-style IAM and STS actions associated with persistence or privilege escalation. Top evidence: userIdentity.arn=arn:aws:iam::123456789012:user/devon.lee, actions=['AssumeRole', 'AttachUserPolicy', 'ConsoleLogin', 'CreateAccessKey', 'PutUserPolicy', 'UpdateAssumeRolePolicy'], src_ips=['10.10.1.135', '10.10.1.137', '10.10.1.160', '10.10.1.170', '10.10.1.179', '10.10.1.198', '10.10.1.237', '10.10.1.4', '10.10.1.45', '10.10.1.60', '10.10.1.7', '10.10.2.13', '10.10.2.141', '10.10.2.151', '10.10.2.154', '10.10.2.160', '10.10.2.179', '10.10.2.208', '10.10.2.32', '10.10.2.46', '10.10.2.54', '10.10.2.79', '10.20.5.134', '10.20.5.137', '10.20.5.171', '10.20.5.174', '10.20.5.195', '10.20.5.207', '10.20.5.213', '10.20.5.33', '10.20.5.41', '10.20.5.7', '10.20.5.93', '103.77.240.9', '172.16.8.111', '172.16.8.113', '172.16.8.126', '172.16.8.139', '172.16.8.140', '172.16.8.173', '172.16.8.179', '172.16.8.216', '172.16.8.33', '172.16.8.37', '172.16.8.39', '172.16.8.55', '172.16.8.75', '172.16.8.76', '185.220.101.33', '198.51.100.42', '203.0.113.18', '23.91.44.10', '45.66.12.88', '71.19.144.41', '91.240.118.20'], risk=1550. Recommended action: Review whether the principal should perform IAM changes, inspect CloudTrail activity before and after, and rotate credentials if unauthorized.

### SPL

```spl
search index=lab_cloud eventName IN ("CreateAccessKey","AttachUserPolicy","PutUserPolicy","UpdateAssumeRolePolicy","AssumeRole","CreateLoginProfile","ConsoleLogin") | stats count as events values(eventName) as actions values(sourceIPAddress) as src_ips values(awsRegion) as regions by userIdentity.arn recipientAccountId | eval risk=events*5+mvcount(actions)*20+if(match(mvjoin(actions,","),"CreateAccessKey|AttachUserPolicy|PutUserPolicy"),60,0) | sort - risk | head 10
```

### Evidence

| userIdentity.arn | recipientAccountId | events | actions | src_ips | regions | risk |
| --- | --- | --- | --- | --- | --- | --- |
| arn:aws:iam::123456789012:user/devon.lee | 123456789012 | 274 | ['AssumeRole', 'AttachUserPolicy', 'ConsoleLogin', 'CreateAccessKey', 'PutUserPolicy', 'UpdateAssumeRolePolicy'] | ['10.10.1.135', '10.10.1.137', '10.10.1.160', '10.10.1.170', '10.10.1.179', '10.10.1.198', '10.10.1.237', '10.10.1.4', '10.10.1.45', '10.10.1.60', '10.10.1.7', '10.10.2.13', '10.10.2.141', '10.10.2.151', '10.10.2.154', '10.10.2.160', '10.10.2.179', '10.10.2.208', '10.10.2.32', '10.10.2.46', '10.10.2 | ['eu-west-1', 'us-east-1', 'us-east-2', 'us-west-2'] | 1550 |
| arn:aws:iam::123456789012:user/carla.ruiz | 123456789012 | 260 | ['AssumeRole', 'AttachUserPolicy', 'ConsoleLogin', 'CreateAccessKey', 'PutUserPolicy', 'UpdateAssumeRolePolicy'] | ['10.10.1.115', '10.10.1.118', '10.10.1.16', '10.10.1.178', '10.10.1.191', '10.10.1.204', '10.10.1.225', '10.10.1.233', '10.10.1.34', '10.10.1.53', '10.10.1.59', '10.10.1.84', '10.10.1.91', '10.10.1.99', '10.10.2.106', '10.10.2.114', '10.10.2.135', '10.10.2.168', '10.10.2.169', '10.10.2.180', '10.10 | ['eu-west-1', 'us-east-1', 'us-east-2', 'us-west-2'] | 1480 |
| arn:aws:iam::123456789012:user/svc_backup | 123456789012 | 252 | ['AssumeRole', 'AttachUserPolicy', 'ConsoleLogin', 'CreateAccessKey', 'PutUserPolicy', 'UpdateAssumeRolePolicy'] | ['10.10.1.100', '10.10.1.157', '10.10.1.17', '10.10.1.173', '10.10.1.189', '10.10.1.212', '10.10.1.215', '10.10.1.229', '10.10.1.236', '10.10.1.56', '10.10.1.65', '10.10.1.67', '10.10.1.85', '10.10.2.11', '10.10.2.111', '10.10.2.20', '10.10.2.40', '10.10.2.56', '10.20.5.126', '10.20.5.146', '10.20.5 | ['eu-west-1', 'us-east-1', 'us-east-2', 'us-west-2'] | 1440 |
| arn:aws:iam::123456789012:user/alice.nguyen | 123456789012 | 248 | ['AssumeRole', 'AttachUserPolicy', 'ConsoleLogin', 'CreateAccessKey', 'PutUserPolicy', 'UpdateAssumeRolePolicy'] | ['10.10.1.139', '10.10.1.145', '10.10.1.188', '10.10.1.206', '10.10.1.220', '10.10.1.40', '10.10.1.5', '10.10.1.89', '10.10.2.126', '10.10.2.132', '10.10.2.135', '10.10.2.152', '10.10.2.166', '10.10.2.173', '10.10.2.24', '10.10.2.28', '10.10.2.77', '10.10.2.84', '10.10.2.9', '10.20.5.105', '10.20.5. | ['eu-west-1', 'us-east-1', 'us-east-2', 'us-west-2'] | 1420 |
| arn:aws:iam::123456789012:user/svc_ci_cd | 123456789012 | 230 | ['AssumeRole', 'AttachUserPolicy', 'ConsoleLogin', 'CreateAccessKey', 'PutUserPolicy', 'UpdateAssumeRolePolicy'] | ['10.10.1.115', '10.10.1.121', '10.10.1.123', '10.10.1.125', '10.10.1.2', '10.10.1.204', '10.10.1.222', '10.10.1.233', '10.10.1.25', '10.10.1.29', '10.10.1.37', '10.10.1.60', '10.10.1.77', '10.10.1.99', '10.10.2.10', '10.10.2.119', '10.10.2.152', '10.10.2.155', '10.10.2.190', '10.10.2.27', '10.20.5. | ['eu-west-1', 'us-east-1', 'us-east-2', 'us-west-2'] | 1330 |

## Brute Force or Password Spray Candidate

- Severity: `high`
- Domain: `identity`
- MITRE: `Credential Access: Brute Force (T1110)`
- Rows returned: `5`

### Analyst Assessment

Brute Force or Password Spray Candidate: Finds accounts with repeated failures, multiple source addresses, or concentrated failed login bursts. Top evidence: user=erin.patel, src_ips=['10.20.5.156', '10.20.5.74', '103.77.240.9', '172.16.8.100', '45.66.12.88'], failures=10, src_count=5. Recommended action: Validate whether the user expected these attempts, review MFA outcome, and pivot into successful logins from the same source addresses.

### SPL

```spl
search index=lab_auth action=failure | bucket _time span=30m | stats count as failures dc(src_ip) as src_count values(src_ip) as src_ips values(reason) as reasons by user _time | where failures>=6 | sort - failures | head 10
```

### Evidence

| user | _time | failures | src_count | src_ips | reasons |
| --- | --- | --- | --- | --- | --- |
| erin.patel | 2026-06-17T23:30:00.000+00:00 | 10 | 5 | ['10.20.5.156', '10.20.5.74', '103.77.240.9', '172.16.8.100', '45.66.12.88'] | ['bad password', 'mfa denied', 'unknown user'] |
| bob.smith | 2026-06-18T12:30:00.000+00:00 | 8 | 4 | ['10.10.2.177', '10.10.2.6', '10.20.5.179', '172.16.8.10'] | ['account locked', 'bad password', 'unknown user'] |
| svc_ci_cd | 2026-06-18T03:00:00.000+00:00 | 8 | 4 | ['10.10.1.157', '172.16.8.55', '71.19.144.41', '91.240.118.20'] | ['mfa denied', 'unknown user'] |
| alice.nguyen | 2026-06-17T18:00:00.000+00:00 | 6 | 3 | ['10.20.5.116', '10.20.5.24', '172.16.8.187'] | ['mfa denied', 'unknown user'] |
| carla.ruiz | 2026-06-17T23:30:00.000+00:00 | 6 | 3 | ['10.10.2.29', '10.20.5.194', '91.240.118.20'] | ['account locked', 'unknown user'] |

## Suspicious Endpoint Network Egress

- Severity: `high`
- Domain: `endpoint`
- MITRE: `Command and Control: Non-Standard Port (T1571)`
- Rows returned: `5`

### Analyst Assessment

Suspicious Endpoint Network Egress: Finds endpoint network connections to high-risk ports such as 4444, 9001, 8080, and RDP. Top evidence: endpoint_host=web-02, user=erin.patel, dest_port=4444, dest_ips=['71.19.144.41', '91.240.118.20'], connections=6. Recommended action: Pivot to process_name and command_line on the same host, then validate whether the destination is known business infrastructure.

### SPL

```spl
search index=lab_endpoint event_type=network dest_port IN (4444,8080,9001,3389) | spath input=_raw path=host output=endpoint_host | eval endpoint_host=coalesce(endpoint_host,host) | stats count as connections dc(dest_ip) as distinct_dest values(dest_ip) as dest_ips values(process_name) as processes by endpoint_host user dest_port | eval risk=connections+distinct_dest*10+case(dest_port=4444,70,dest_port=9001,50,dest_port=3389,35,true(),10) | sort - risk | head 10
```

### Evidence

| endpoint_host | user | dest_port | connections | distinct_dest | dest_ips | processes | risk |
| --- | --- | --- | --- | --- | --- | --- | --- |
| web-02 | erin.patel | 4444 | 6 | 2 | ['71.19.144.41', '91.240.118.20'] | ['chrome.exe', 'outlook.exe'] | 96 |
| db-01 | erin.patel | 4444 | 4 | 2 | ['203.0.113.18', '45.66.12.88'] | ['chrome.exe', 'powershell.exe'] | 94 |
| db-01 | svc_backup | 4444 | 4 | 2 | ['23.91.44.10', '71.19.144.41'] | ['cmd.exe', 'powershell.exe'] | 94 |
| web-01 | frank.kim | 4444 | 4 | 2 | ['103.77.240.9', '71.19.144.41'] | ['cmd.exe', 'outlook.exe'] | 94 |
| web-02 | grace.hall | 4444 | 4 | 2 | ['45.66.12.88', '71.19.144.41'] | ['chrome.exe', 'cmd.exe'] | 94 |

## Risky Web or API Client

- Severity: `high`
- Domain: `web`
- MITRE: `Initial Access: Exploit Public-Facing Application (T1190)`
- Rows returned: `5`

### Analyst Assessment

Risky Web or API Client: Ranks web clients by attack volume, error rate, and latency impact. Top evidence: client_ip=203.0.113.18, user_agent=Edge, attacks=12, error_rate=100.00, risk=152. Recommended action: Review request paths, WAF decisions, authentication attempts, and whether the source has related identity or network activity.

### SPL

```spl
search index=lab_web | eval error=if(status>=400,1,0), attack=if(attack_type!="none",1,0) | stats count as requests sum(error) as errors sum(attack) as attacks p95(response_ms) as p95_ms values(attack_type) as attack_types by client_ip user_agent | eval error_rate=round(errors/requests*100,2), risk=attacks*10+errors+if(p95_ms>1000,20,0) | where attacks>0 OR error_rate>20 | sort - risk | head 10
```

### Evidence

| client_ip | user_agent | requests | errors | attacks | p95_ms | attack_types | error_rate | risk |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 203.0.113.18 | Edge | 12 | 12 | 12 | 1108 | ['credential_stuffing', 'path_traversal', 'scanner', 'sql_injection', 'xss'] | 100.00 | 152 |
| 198.51.100.42 | Chrome | 12 | 12 | 12 | 990 | ['scanner', 'sql_injection', 'xss'] | 100.00 | 132 |
| 91.240.118.20 | python-requests | 12 | 12 | 12 | 340 | ['credential_stuffing', 'path_traversal', 'xss'] | 100.00 | 132 |
| 103.77.240.9 | Chrome | 10 | 10 | 10 | 225 | ['credential_stuffing', 'scanner', 'sql_injection', 'xss'] | 100.00 | 110 |
| 198.51.100.42 | sqlmap | 10 | 10 | 10 | 317 | ['path_traversal', 'scanner', 'xss'] | 100.00 | 110 |
