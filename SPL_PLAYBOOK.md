# SPL Playbook

This playbook collects the strongest searches in the lab and explains what each proves.

## Data Health

```spl
| tstats count where index IN (lab_auth, lab_web, lab_endpoint, lab_cloud, lab_network) by index sourcetype
```

Shows fast metadata-level validation using `tstats`.

```spl
index=lab_auth OR index=lab_web OR index=lab_endpoint OR index=lab_cloud OR index=lab_network
| stats count min(_time) as first_seen max(_time) as last_seen by index sourcetype
| convert ctime(first_seen) ctime(last_seen)
```

Confirms timestamp parsing and source coverage.

## SOC Prioritization

```spl
`lab_indexes` severity IN ("critical","high")
| eval entity=coalesce(user,host,src_ip,src,client_ip)
| eval technique=coalesce(attack_type,eventName,process_name,signature,action)
| stats count as events values(index) as indexes values(technique) as techniques max(risk_score) as max_risk latest(_time) as last_seen by entity severity
| eval priority=case(severity="critical",100,severity="high",75,true(),25)+coalesce(max_risk,0)+events
| sort - priority
| convert ctime(last_seen)
```

Demonstrates cross-domain normalization and risk-based triage.

## Brute Force and Password Spray

```spl
`failed_auth_base`
| bucket _time span=30m
| stats count as failures dc(src_ip) as src_count values(src_ip) as src_ips values(reason) as reasons min(_time) as first_seen max(_time) as last_seen by user _time
| lookup identity_risk user OUTPUT department privileged vip risk_score
| eval spray_indicator=if(src_count>=5 AND failures>=10,"possible spray","focused brute force")
| eval priority=failures+coalesce(risk_score,0)+if(privileged="true",30,0)+if(vip="true",40,0)
| where failures>=6
| sort - priority
| convert ctime(first_seen) ctime(last_seen)
```

Uses time bucketing, distinct-count source logic, identity enrichment, and risk scoring.

## Impossible Travel

```spl
index=lab_auth action=success src_country=*
| sort 0 user _time
| streamstats current=f last(_time) as prev_time last(src_country) as prev_country last(src_ip) as prev_ip by user
| eval minutes=round((_time-prev_time)/60,1)
| where isnotnull(prev_country) AND src_country!=prev_country AND minutes>0 AND minutes<180
| lookup identity_risk user OUTPUT department privileged vip risk_score
| eval priority=100+coalesce(risk_score,0)+if(privileged="true",30,0)+if(vip="true",40,0)
| table _time user department src_country prev_country src_ip prev_ip minutes mfa_result risk_score priority
| convert ctime(_time)
```

Shows event sequencing with `streamstats`.

## Web Attack and Performance Analytics

```spl
index=lab_web
| eval error=if(status>=400,1,0), attack=if(attack_type!="none",1,0)
| stats count as requests sum(error) as errors sum(attack) as attacks avg(response_ms) as avg_ms p95(response_ms) as p95_ms values(attack_type) as attack_types by client_ip user_agent
| eval error_rate=round(errors/requests*100,2)
| eval risk=attacks*10+errors+if(p95_ms>1000,20,0)
| where attacks>0 OR error_rate>20
| sort - risk
```

Combines security and reliability signals in one ranking.

## Endpoint Living-off-the-land Detection

```spl
index=lab_endpoint event_type=process process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe")
| lookup asset_inventory host OUTPUT asset_owner business_unit criticality environment
| eval encoded=if(match(command_line,"(?i)-enc|-encodedcommand|frombase64string"),1,0)
| eval download=if(match(command_line,"(?i)invoke-webrequest|curl|wget|bitsadmin"),1,0)
| eval risk=20+encoded*50+download*35+case(criticality="critical",40,criticality="high",25,true(),0)
| stats count as executions max(risk) as risk values(parent_process) as parents values(command_line) as command_lines values(user) as users by host process_name criticality business_unit
| sort - risk executions
```

Demonstrates process-chain triage, regex matching, and asset-aware scoring.

## Suspicious Endpoint Egress

```spl
index=lab_endpoint event_type=network dest_port IN (4444,8080,9001,53,3389)
| lookup asset_inventory host OUTPUT asset_owner business_unit criticality environment
| stats count as connections dc(dest_ip) as distinct_dest values(dest_ip) as dest_ips values(process_name) as processes values(action) as actions by host user dest_port criticality
| eval risk=connections+distinct_dest*10+case(dest_port=4444,70,dest_port=9001,50,dest_port=3389,35,true(),10)+case(criticality="critical",40,criticality="high",25,true(),0)
| sort - risk
```

Finds high-risk outbound behavior from endpoints.

## Cloud Privilege Escalation

```spl
index=lab_cloud eventName IN ("CreateAccessKey","AttachUserPolicy","PutUserPolicy","UpdateAssumeRolePolicy","AssumeRole","CreateLoginProfile","ConsoleLogin")
| stats count as events values(eventName) as actions values(sourceIPAddress) as src_ips values(awsRegion) as regions values(errorCode) as errors min(_time) as first_seen max(_time) as last_seen by userIdentity.arn recipientAccountId
| eval risk=events*5+mvcount(actions)*20+if(match(mvjoin(actions,","),"CreateAccessKey|AttachUserPolicy|PutUserPolicy"),60,0)
| sort - risk
| convert ctime(first_seen) ctime(last_seen)
```

Uses CloudTrail-style data to surface identity persistence and privilege escalation behavior.

## Network Beacon Candidate

```spl
index=lab_network action=allowed dest_port IN (443,8080,9001,4444)
| bucket _time span=5m
| stats count as connections avg(bytes) as avg_bytes stdev(bytes) as stdev_bytes values(dest_port) as ports by src dest _time
| eventstats avg(connections) as avg_conn stdev(connections) as stdev_conn by src dest
| eval regularity=if(stdev_conn<1.5 AND avg_conn>=2,1,0)
| where regularity=1
| stats count as intervals avg(avg_bytes) as avg_bytes values(ports) as ports by src dest
| where intervals>=4
| sort - intervals
```

Shows how to reason about periodic traffic patterns with statistical aggregation.
