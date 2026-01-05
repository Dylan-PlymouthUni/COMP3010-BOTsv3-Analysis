# COMP3010 Security Operations & Incident Management

## BOTSv3 SOC Investigation Report

---

## Executive Summary

This report documents my investigation of a cloud security incident using the Boss of the SOC v3 (BOTSv3) dataset in Splunk. The incident involves IAM user "bstoll" (Bud Stoll) modifying an S3 bucket's access control list, making it publicly accessible.

Key findings:
- User bstoll executed a PutBucketAcl API call on bucket "frothlywebcode"
- CloudTrail captured this as event ID ab45689d-69cd-41e7-8705-5350402cf7ac
- An object called "OPEN_BUCKET_PLEASE_FIX. txt" was uploaded to the bucket
- The user's endpoint runs a different Windows edition compared to other hosts
- ConsoleLogin events show sessions where mfaAuthenticated=false, indicating MFA was not used for those logins

The investigation uses log correlation across AWS CloudTrail, S3 access logs, and Windows endpoint telemetry to reconstruct what happened and recommend improvements.

**Important note:** This is a retrospective analysis of simulated data from August 2018. I'm analyzing the logs after the fact, not responding to a live incident. 

---

## 1. Introduction

Security Operations Centres monitor an organization's infrastructure 24/7 to detect and respond to threats. This investigation demonstrates SOC analyst skills using the BOTSv3 dataset, which simulates a realistic enterprise environment for a fictional company called "Frothly."

### What I investigated

I focused on the AWS portion of the dataset, specifically: 
- Which IAM users accessed AWS services
- How to identify whether MFA was used for authentication
- An S3 bucket that had its permissions changed
- What files were uploaded to that bucket
- Differences in endpoint configurations

### My approach

I used Splunk to query different log sources (AWS CloudTrail for API calls, S3 access logs for object operations, and Windows host monitoring for endpoint data). All my queries are saved in the evidence folder so anyone can reproduce my findings.

### Dataset limitations

BOTSv3 is a snapshot of logs from a specific time period. I can't see what happened before or after that window, and I can't perform any remediation actions since it's historical data. This means some questions (like "how long was the bucket exposed? ") can't be fully answered without additional evidence.

---

## 2. SOC Context

### How SOCs are organized

Most SOCs work in tiers: 

Tier 1 analysts handle incoming alerts, validate them (filtering out false positives), and escalate genuine incidents.  In a real environment, they'd probably catch the PutBucketAcl event through an automated alert. 

Tier 2 analysts do the deep investigation work, which is what I'm demonstrating here.  They correlate logs from multiple sources, figure out what actually happened, and determine the scope. 

Tier 3 focuses on threat hunting, building detection rules, and handling the most complex incidents. 

### Incident handling process

I followed the NIST incident handling lifecycle:

1. Detection - I identified the suspicious PutBucketAcl event in CloudTrail
2. Analysis - I figured out it was user bstoll and correlated it with S3 logs
3. Containment - Understanding how the bucket became public and what was exposed
4. Eradication - Identifying what needs to be removed or corrected
5. Recovery - Informing remediation steps
6. Lessons Learned - Improving monitoring and preventive controls

The first two phases are evidence-based from my queries.  The rest are recommendations for what should happen in a production environment.

---

## 3. My Investigation Environment

### Tools and data

- SIEM platform: Splunk Enterprise
- Dataset: BOTSv3 (indexed as "botsv3")
- Investigation period: January 2026 (when I did the analysis)
- Incident timeframe: August 20, 2018 (the simulated events)

### Log sources I used

- aws: cloudtrail - AWS API calls and authentication events
- aws:s3:accesslogs - S3 object operations (e.g., PUT)
- hardware - System specifications for each host
- WinHostMon - Windows operating system and process information

All my queries and screenshots are in the evidence folder for reproducibility.

---

## 4. What I Found

### Question 1: IAM Users

I needed to find all IAM users that accessed AWS services. My query filtered CloudTrail logs for events where the user type was "IAMUser" and counted activity by username.

Query: [evidence/spl-queries/Q1.spl](evidence/spl-queries/Q1.spl)

```spl
index=botsv3 sourcetype=aws:cloudtrail userIdentity.type=IAMUser earliest=0
| stats count by userIdentity.userName
| sort userIdentity.userName
```

Result: Four users - bstoll, btun, splunk_access, and web_admin

Evidence:  evidence/screenshots/COMP3010.evidence 1. png

Why this matters:  Knowing who has AWS access is the foundation of attribution.  If you see a fifth user appear, that's your red flag.  This also helps establish baseline behavior so you can spot anomalies later.

---

### Question 2: MFA Field

I wanted to identify which CloudTrail field shows whether multi-factor authentication was used.  I looked at console login events to see the authentication context.

Query: [evidence/spl-queries/Q2.spl](evidence/spl-queries/Q2.spl)

```spl
index=botsv3 sourcetype=aws:cloudtrail eventName=ConsoleLogin earliest=0
| table _time, userIdentity.type, userIdentity.userName, sourceIPAddress, responseElements, errorMessage
| sort 0 _time
```

The field is:  userIdentity.sessionContext.attributes.mfaAuthenticated

To verify MFA status values, I used: 

```spl
index=botsv3 sourcetype=aws:cloudtrail eventName=ConsoleLogin
| spath
| table _time userIdentity.userName sourceIPAddress userIdentity.sessionContext.attributes.mfaAuthenticated
| sort 0 _time
```

This confirmed that ConsoleLogin events show sessions where mfaAuthenticated=false, indicating MFA was not used for those logins.

I also noticed that in the available ConsoleLogin events I reviewed, bstoll (source IP 157.97.121.132) appeared as the earliest event returned by the query. 

Evidence: evidence/screenshots/COMP3010.evidence 1.5.png

Why this matters: MFA status is critical for security monitoring. If someone's using stolen credentials, they usually can't complete the MFA challenge. Many compliance frameworks (PCI-DSS, HIPAA) require MFA for privileged access, so you need to be able to alert when it's not being used.

---

### Question 3: Processor Type

I needed to identify what CPU the web servers were using. This came from the hardware logs.

Query: [evidence/spl-queries/Q3.spl](evidence/spl-queries/Q3.spl)

```spl
index=botsv3 sourcetype=hardware
| table host CPU_TYPE CPU_COUNT CPU_CACHE HARD_DRIVES
```

Result: Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz

Evidence: evidence/screenshots/Q3_hardware_cpu_processor.png

Why this matters: Hardware inventory helps with vulnerability management (like when Spectre/Meltdown dropped and everyone needed to know what CPUs they had). It also helps validate that systems match your expected configuration during forensics.  The Xeon E5-2676 is typical for AWS EC2 instances, probably M4 or C4 instance types.

---

### Question 4: The PutBucketAcl Event

This is the core of the incident. I searched CloudTrail for PutBucketAcl events, which is the API call used to change S3 bucket permissions.

Query: [evidence/spl-queries/Q4.spl](evidence/spl-queries/Q4.spl)

```spl
index=botsv3 sourcetype=aws:cloudtrail eventName=PutBucketAcl
| table _time userIdentity.userName requestParameters.bucketName eventName sourceIPAddress awsRegion
| sort 0 _time
```

Result: Event ID ab45689d-69cd-41e7-8705-5350402cf7ac

Details:
- User: bstoll
- Bucket: frothlywebcode
- Source IP: 107.77.212.175
- Date: August 20, 2018

Evidence: evidence/screenshots/Q4_putbucketacl_public_access.png

Why this matters: PutBucketAcl events that make buckets public are critical security events.  Misconfigured S3 buckets are one of the most common causes of data breaches. In a real SOC, you'd want an alert that fires immediately when someone tries to make a bucket public, with automatic escalation to a senior analyst.

---

### Question 5: Bud's Username

The question asked for "Bud's" username.  Based on the PutBucketAcl activity, I could see it was bstoll.

Query: [evidence/spl-queries/Q5.spl](evidence/spl-queries/Q5.spl)

```spl
index=botsv3 sourcetype=aws:cloudtrail eventName=PutBucketAcl
| stats count by userIdentity.userName
| sort - count
```

Answer: bstoll (Bud Stoll)

Evidence: evidence/screenshots/Q5_bud_username_bstoll.png

Why this matters: Attribution is crucial. You need to know who did what so you can determine if it was malicious or just a mistake, and so you can work with HR or management on next steps (training, access revocation, etc.).

---

### Question 6: Bucket Name

I needed to identify which bucket had its ACL modified. 

Query: [evidence/spl-queries/Q6.spl](evidence/spl-queries/Q6.spl)

```spl
index=botsv3 sourcetype=aws:cloudtrail eventName=PutBucketAcl
| stats count by requestParameters.bucketName
| sort - count
```

Answer: frothlywebcode

Evidence: evidence/screenshots/Q6_public_bucket_name.png

Why this matters: You need to know which asset was affected to scope the incident. The name "frothlywebcode" suggests it contains web application code, which could mean source code exposure, embedded credentials, or proprietary business logic.  That makes this a higher-severity incident than if it were just static images.

---

### Question 7:  Uploaded File

I searched S3 access logs for PUT operations (file uploads) to see if anyone uploaded anything to the bucket.

Query: [evidence/spl-queries/Q7.spl](evidence/spl-queries/Q7.spl)

```spl
index=botsv3 sourcetype=aws:s3:accesslogs "OPEN_BUCKET_PLEASE_FIX"
| table _time bucket key operation
| sort 0 _time
```

Result: A file called "OPEN_BUCKET_PLEASE_FIX.txt" was uploaded. 

Important clarification: The answer file (evidence/answers/Q7_answer. md) shows "s32018-08-20-13-12-49-CE6005687016BFCE" which is the S3 log filename that contains the record of the upload, not the actual uploaded file name. 

Evidence: evidence/screenshots/Q7_s3_text_file_uploaded.png

Attribution issue: The S3 access logs don't capture who uploaded the file. There's no authenticated user identity in these logs, so I can't definitively say whether it was an external party or an internal user.

Why this matters: The filename "OPEN_BUCKET_PLEASE_FIX.txt" suggests maybe a security researcher found the exposed bucket and was trying to notify someone (ethical disclosure). But any unauthorized modification is still a security incident.  In a real investigation, you'd want to see if there were any GET operations (downloads) which would indicate data exfiltration, not just uploads.

---

### Question 8: Endpoint Differences

I looked at Windows host monitoring data to see if any endpoints had different OS configurations.

Query:

```spl
index=botsv3 sourcetype=WinHostMon Type=OperatingSystem
| stats values(OSName) by host
```

Result: bstoll-l. froth.ly runs a different Windows edition compared to the other monitored hosts.

Evidence: evidence/screenshots/COMP3010.evidence 2.png

Why this matters: Configuration drift can indicate several things - maybe this is an executive's laptop with different software, maybe it's a system that's not properly managed by IT, or maybe it's running an older version with unpatched vulnerabilities. Combined with the AWS misconfiguration, it suggests bstoll might be operating with elevated privileges or less oversight than other users.

---

## 5. Timeline Reconstruction

To understand the sequence of events, I needed to correlate the ACL change with the file upload. Here's a query that shows both events in chronological order:

```spl
index=botsv3 sourcetype=aws:cloudtrail eventName=PutBucketAcl requestParameters.bucketName=frothlywebcode
| eval event_type="PutBucketAcl (Bucket Made Public)"
| eval actor=userIdentity.userName
| eval artifact=requestParameters.bucketName
| table _time event_type actor artifact sourceIPAddress
| append [
    search index=botsv3 sourcetype=aws:s3:accesslogs operation=REST.PUT.OBJECT
    | search key="*OPEN_BUCKET*"
    | eval event_type="S3 Object Upload"
    | eval actor="Unattributed (S3 access logs)"
    | eval artifact=key
    | table _time event_type actor artifact
]
| sort 0 _time
```

What I can confirm: The PutBucketAcl event happened, and subsequently there was an upload to the bucket. 

What I can't determine from the available data: The exact time gap between these events, how long the bucket remained exposed, and when (or if) it was fixed.  BOTSv3 is a snapshot, so I don't have visibility into remediation. 

---

## 6. Root Cause

What definitely happened:  User bstoll executed a PutBucketAcl API call that modified permissions on bucket frothlywebcode.

Why it might have happened (these are educated guesses, not proven):

Hypothesis 1: Bstoll was probably trying to fix an access problem.  Maybe a web application couldn't reach the bucket, and instead of debugging the IAM policy or bucket policy, bstoll took the quick route of opening up the permissions.

Hypothesis 2: Lack of AWS training. If you don't understand the security implications of different ACL settings, you might not realize you're exposing data to the internet.

Hypothesis 3: No approval process.  There doesn't appear to be any change control workflow that would have caught this before it happened.

Hypothesis 4: Over-permissioned IAM user.  Bstoll shouldn't probably have the ability to modify bucket ACLs without additional approval.

I can't determine intent from logs alone.  Was this malicious? Almost certainly not - the username matches a legitimate employee.  Was it careless? Probably.  Was it understandable given inadequate training or tooling? Maybe. 

---

## 7. Impact Assessment

What I know for certain: 
- Bucket frothlywebcode had its ACL changed
- An unauthorized file was uploaded to it
- No availability issues (services kept running)

What I don't know (would need additional queries):
- Whether anyone downloaded files from the bucket (would need to query for GET operations in S3 logs)
- How many files were in the bucket at the time
- What the files actually contained (source code?  credentials? customer data?)
- Exactly how long the bucket was exposed before someone fixed it

In a real incident, I'd run additional queries to answer these questions. The bucket name suggests source code, which would be a confidentiality issue (exposing intellectual property) but probably not a compliance issue unless there were credentials or customer data embedded in the code.

---

## 8. What Should Be Done About This

If this were a real incident in production, here's what I'd recommend: 

Immediate actions:
1. Fix the bucket ACL right now - remove public access
2. Check what's in the bucket and classify it
3. Turn on MFA for all IAM users, especially those with S3 permissions
4. Review bstoll's recent AWS activity for other risky changes
5. Rotate access keys as a precaution

Detection improvements: 

Set up a Splunk alert like this: 

```spl
index=botsv3 sourcetype=aws:cloudtrail eventName=PutBucketAcl
| eval severity="HIGH"
| eval description="S3 bucket ACL modified:  ". requestParameters.bucketName." by user:  ".userIdentity.userName
| table _time severity userIdentity.userName requestParameters.bucketName sourceIPAddress userAgent
```

The alert should fire in real-time (under 60 seconds) and automatically create a ticket for a Tier 2 analyst.

Prevention measures: 
1. Turn on S3 Block Public Access at the account level - this is AWS's "big red button" that prevents public buckets even if someone tries
2. Use AWS Config rules to automatically detect and fix public buckets
3. Restrict who can run PutBucketAcl through IAM policies - most users don't need this permission
4. Deploy AWS GuardDuty for continuous monitoring

Process changes:
1. Require change tickets for infrastructure modifications
2. Provide AWS security training for anyone with cloud access
3. Create a runbook for "public S3 bucket" incidents so the next analyst knows exactly what to do
4. Standardize endpoint configurations so bstoll's system matches everyone else's

---

## 9. Limitations of This Investigation

I need to be clear about what I couldn't do because of dataset constraints:

Dataset limitations:
- BOTSv3 is simulated data from a specific time window.  I can't see what happened before or after. 
- I can't interview bstoll to ask what they were trying to do.
- I can't see if there was a help desk ticket that explains the context. 
- I can't perform remediation or see if remediation happened.

Attribution gaps:
- S3 access logs don't show authenticated user identity for the file upload, so I can't prove who uploaded "OPEN_BUCKET_PLEASE_FIX.txt"
- I don't have threat intelligence data to correlate source IPs
- I can't determine if this was coordinated with other suspicious activity outside AWS

Analysis gaps:
- I didn't calculate exact time deltas between events
- I didn't enumerate all objects in the bucket
- I didn't check for GET operations (potential data exfiltration)
- I didn't analyze the uploaded file contents

In a real SOC investigation, I'd fill these gaps before closing the ticket. 

---

## 10. MITRE ATT&CK Mapping

I mapped the observed behavior to the MITRE ATT&CK framework for cloud: 

| Technique | ID | What I saw |
|-----------|----|-----------| 
| Valid Accounts:  Cloud Accounts | T1078.004 | Bstoll used legitimate IAM credentials |
| Data from Cloud Storage | T1530 | Potential access to S3 bucket (not definitively confirmed) |
| Modify Cloud Compute Infrastructure | T1578 | S3 bucket ACL modification |

Note: I'm listing T1530 as tentative because I don't have proof of data exfiltration, just proof the bucket ACL was changed and a file was uploaded. 

---

## 11. References

1. Amazon Web Services.  AWS CloudTrail User Guide. https://docs.aws.amazon.com/cloudtrail/
2. Amazon Web Services. Amazon S3 Access Control List Overview. https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html
3. Splunk Inc. Boss of the SOC v3 Dataset. https://github.com/splunk/botsv3
4. NIST. Computer Security Incident Handling Guide (SP 800-61 Rev. 2). https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
5. MITRE. ATT&CK for Cloud. https://attack.mitre.org/matrices/enterprise/cloud/

---

## Appendices

### Evidence Manifest

All my evidence is organized in the repository:

| What | Where | Description |
|------|-------|-------------|
| SPL queries | evidence/spl-queries/ | Q1.spl through Q7.spl |
| Screenshots | evidence/screenshots/ | Query results for all 8 questions |
| Answers | evidence/answers/ | Individual answer files for each question |

### Repository Structure

```
COMP3010-BOTsv3-Analysis/
├── README.md (this file)
├── evidence/
│   ├── screenshots/
│   ├── answers/
│   ├── spl-queries/
│   ├── configs/
│   └── dashboards/
└── video/
```

---

## Academic Integrity Statement

I completed this investigation in accordance with Plymouth University's academic integrity policy. 

I used AI tools for: 
- Grammar and spell checking (A5 - Language refinement)
- Checking my SPL syntax for errors (A8 - Technical debugging)

I did not use AI to: 
- Generate fake data or evidence
- Write my analysis or conclusions
- Create the queries
- Make up findings

All the investigation work, evidence collection, and analytical conclusions are my own.
---

This investigation demonstrates practical SOC analyst skills including log correlation, cloud security incident response, and evidence-based documentation. All queries and evidence are in the repository so the findings can be independently verified. 

---
