COMP3010 – Security Operations & Incident Management

BOTSv3 SOC Investigation Report

1. Introduction (10%)

Security Operations Centres (SOCs) play a critical role in modern organisations by providing continuous monitoring, detection, analysis, and response to security incidents across complex infrastructures. With the widespread adoption of cloud services and hybrid environments, SOC analysts must be capable of correlating endpoint, network, and cloud telemetry to identify misconfigurations, misuse, and malicious activity.

This report documents an end-to-end security investigation conducted using the Boss of the SOC v3 (BOTSv3) dataset within Splunk Enterprise. BOTSv3 is a realistic, industry-aligned dataset designed to simulate enterprise-scale security operations, incorporating AWS CloudTrail logs, S3 access logs, endpoint telemetry, and host monitoring data.

The scope of this investigation focuses on AWS-related security events and endpoint context, specifically:

 IAM user activity within AWS
 A misconfigured Amazon S3 bucket that became publicly accessible
 Object uploads occurring while the bucket was exposed
 Endpoint operating system discrepancies relevant to SOC triage

The objective is to demonstrate practical SOC analysis using Splunk, supported by accurate SPL queries, validated evidence, and reflection on how findings map to real-world SOC workflows.

Assumptions:

The BOTSv3 dataset represents a simulated but realistic enterprise environment
All timestamps and events are treated as ground truth for investigative purposes The investigation is conducted from the perspective of a SOC analyst responding post-incident


2. SOC Roles & Incident Handling Reflection (10%)

A mature SOC typically operates using a tiered structure:

Tier 1 (Triage & Monitoring)**: Initial alert handling, validation, and escalation
Tier 2 (Investigation & Analysis)**: Deep-dive analysis, log correlation, and scoping
Tier 3 (Threat Hunting & Response Engineering)**: Advanced analysis, tooling, and remediation support

In the context of this investigation, Tier 1 activity would likely identify anomalous AWS API calls (e.g., PutBucketAcl events) or policy violations through automated alerts. Escalation to Tier 2 enables correlation across CloudTrail, S3 access logs, and endpoint telemetry to understand intent, impact, and exposure.

The incident handling lifecycle applied throughout this investigation aligns with standard SOC methodology:

1. Detection, Identification of suspicious AWS API activity and public S3 access
2. Analysis, Attribution of actions to specific IAM users and affected resources
3. Containment, Identifying the misconfiguration enabling public access
4. Eradication, Understanding how access was abused (object upload)
5. Recovery, Informing remediation (ACL correction, IAM review)
6. Lessons Learned, Improving monitoring and preventive controls

This structured approach ensures findings are actionable and defensible within an operational SOC environment.


3. Installation & Data Preparation (15%)

Splunk Environment Setup

Splunk Enterprise was deployed locally and configured to ingest the BOTSv3 dataset following official guidance. Indexing and parsing were validated to ensure accurate timestamping and field extraction across all source types.

Dataset Ingestion

The following source types were ingested and validated:

 `aws:cloudtrail` – AWS API activity and IAM events
 `aws:s3:accesslogs` – S3 object-level access and HTTP responses
`hardware` – Host hardware specifications
 `WinHostMon` – Windows endpoint telemetry (OS, drivers, processes)

Indexing was performed under the `botsv3` index to maintain dataset consistency. Validation searches confirmed expected event counts and field availability prior to investigation.

Design Justification

Splunk was selected due to its strength in:

 Cross-domain log correlation
 SPL flexibility for ad-hoc investigation
 SOC-aligned workflows and dashboards

Field extraction was leveraged where necessary using `rex` and `spath` to ensure precise data retrieval, reflecting realistic SOC investigative practice.


4. Guided Questions – AWS & Endpoint Investigation (40%)

This section presents a complete answer set to BOTSv3’s AWS-focused 200-level questions. Each question includes the investigative approach, SPL query, evidence, and SOC relevance.


Question 1 – IAM Users Accessing AWS Services

Objective: Identify IAM users that accessed AWS services successfully or unsuccessfully.

SPL Query:

```spl
index=botsv3 sourcetype=aws:cloudtrail userIdentity.type=IAMUser
| stats count by userIdentity.userName
| sort userIdentity.userName
```

Result:
`bstoll,btun,splunk_access,web_admin`

SOC Relevance:
Enumerating IAM user activity is a foundational SOC task, enabling attribution, baseline behaviour analysis, and detection of compromised or misused credentials.


Question 2 – AWS API Activity Without MFA

Objective: Identify the field indicating AWS API activity performed without MFA.

Identified Field:
`userIdentity.sessionContext.attributes.mfaAuthenticated`

SOC Relevance:
API activity without MFA represents elevated risk. SOC teams routinely monitor this field to enforce strong authentication controls and trigger alerts.


Question 3 – Processor Number Used on Web Servers

Objective: Identify the processor model used by web servers.

SPL Query:

```spl
index=botsv3 sourcetype=hardware CPU_TYPE
```

Result:
`Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz`

SOC Relevance:
Hardware awareness supports capacity planning, forensic consistency checks, and anomaly detection during incident response.



Question 4 – Event Enabling Public S3 Access

Objective: Identify the CloudTrail event ID that enabled public S3 access.

SPL Query:

```spl
index=botsv3 sourcetype=aws:cloudtrail eventName=PutBucketAcl userIdentity.userName=bstoll
| table _time eventID requestParameters.bucketName requestParameters.x-amz-acl
```

Result:
`ab45689d-69cd-41e7-8705-5350402cf7ac`

SOC Relevance:
Tracking configuration-change events is critical for identifying cloud misconfigurations that expose data publicly.



Question 5 – Bud’s Username

Answer:
`bstoll`

SOC Relevance:
Clear user attribution supports accountability, insider threat analysis, and corrective action.



Question 6 – Publicly Accessible S3 Bucket Name

**Answer**:
`frothlywebcode`

SOC Relevance:
Asset identification allows SOC teams to scope exposure and prioritise remediation efforts.



Question 7: File Uploaded While Bucket Was Public

SPL Query:

```spl
index=botsv3 sourcetype=aws:s3:accesslogs "REST.PUT.OBJECT"
| rex field=_raw "PUT\s+(?<uri>\S+)"
| eval filename=mvindex(split(uri,"/"),-1)
| where status=200
| stats count by filename
```

Result:
`OPEN_BUCKET_PLEASE_FIX.txt`

SOC Relevance:
Identifying exposed objects is essential for impact assessment and breach notification decisions.


Question 8: Endpoint with Different Windows Edition

SPL Query:

```spl
index=botsv3 sourcetype=WinHostMon Type=OperatingSystem
| stats values(OSName) by host
```

Result:
`bstoll-l.froth.ly`

SOC Relevance:
Endpoint discrepancies may indicate elevated privilege systems, exceptions, or misconfigurations requiring further scrutiny.


5. Conclusion & Recommendations (5%)

This investigation identified a clear sequence of events resulting in unintended public exposure of an S3 bucket, attributable to IAM user activity. Correlation across AWS and endpoint telemetry demonstrated the importance of unified visibility within a SOC.

Key lessons:

 Cloud misconfigurations pose immediate data exposure risks
 IAM activity must be continuously monitored and constrained
 Endpoint context enhances investigative confidence

Recommendations:

 Enforce MFA on all IAM users
 Implement automated alerts for `PutBucketAcl` events
 Apply preventative S3 bucket policies

 Regularly audit endpoint configurations



6. References

 1. Amazon Web Services. AWS CloudTrail User Guide.
 2. Amazon Web Services. Amazon S3 Access Control List (ACL) Overview.
 3. Splunk Inc. Boss of the SOC v3 Dataset.



 7. Appendices



