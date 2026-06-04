# Microsoft Entra ID Identity Operations Lab 06  
## Baseline Validation and Access State Analysis

---

## Overview

This investigation validates identity state in Microsoft Entra ID using Microsoft Graph API and compares it against historical event-driven identity drift analysis from Lab 05.

The focus is on identity validation, RBAC enforcement, group-based access control, and reconciliation between event-based and state-based identity models.

---

## Objective

This lab addresses four core IAM questions:

- What is the current identity state in Microsoft Entra ID
- How RBAC controls visibility of identity objects
- Whether group membership reflects stable or changing access
- How current state compares with historical identity drift (Lab 05)

---

## Dataset

- Microsoft Graph API responses (live queries)
- Entra ID tenant metadata
- Group membership responses
- RBAC restricted responses
- Lab 05 audit log based identity drift reference

---

## Methodology

- Identity scope definition
- Tenant validation using Microsoft Graph organization endpoint
- Identity retrieval using /me endpoint
- Group membership analysis using /memberOf
- RBAC visibility testing using /directoryRoles
- State reconstruction using Graph API
- Drift comparison with Lab 05 audit logs

---

## Identity Scope Definition

Primary Identity  
iam-lab-user-01@ruialmeidadacunhagmail.onmicrosoft.com  

Administrative Actor (Lab 05 Reference)  
rui.almeidadacunha_gmail.com#EXT#@ruialmeidadacunhagmail.onmicrosoft.com  

Authentication Context Identity  
live.com#rui.almeidadacunha@gmail.com  

Group Under Analysis  
IAM-Lab-Group (0e7e5c30-9eff-467a-b1c1-44422b438c19)

---

## Tenant Validation

Microsoft Graph organization endpoint confirmed:

- Single active Entra ID tenant
- Default directory configuration
- Tenant ID: 2c0009ed-1f8d-41a1-9d6c-836d6fc700ab
- Verified domain: ruialmeidadacunhagmail.onmicrosoft.com

Conclusion  
Correct identity scope confirmed with no cross-tenant ambiguity.

---

## Identity Validation

The /me endpoint confirms:

- Authenticated Entra ID identity
- Stable object ID across session
- Valid tenant association
- Consistent authentication context

Conclusion  
Identity is stable and correctly resolved within Entra ID.

---

## Group Membership Analysis

Findings from /me/memberOf:

- At least one group membership confirmed
- Group object ID visible
- Group display name partially restricted
- Limited metadata exposure due to RBAC

Conclusion  
Access is group-based and governed by RBAC with restricted directory visibility.

---

## Role and Privilege Visibility

Query result:

- /directoryRoles returns Access Denied

Interpretation:

- No privileged role visibility
- No directory role enumeration access
- Standard user permission boundary enforced

Conclusion  
Least privilege model is correctly applied.

---

## Identity Drift Comparison (Lab 05 vs Lab 06)

Lab 05 (Event-Based Model)
- Group membership removal observed
- Group membership re-addition observed
- Administrative actor performed changes
- Identity reconstructed from audit logs

Lab 06 (State-Based Model)
- Current identity state is stable
- No active identity drift detected
- No privilege escalation observed

Drift Conclusion  
Identity drift is historical only and not present in current state.

---

## Identity Model Architecture

Event Layer (Lab 05)
- Entra ID audit logs
- Group membership changes
- Identity lifecycle events
- Temporal reconstruction of identity changes

State Layer (Lab 06)
- Microsoft Graph API
- Current identity configuration
- RBAC enforced visibility

Combined Model  
Both layers are required for complete IAM analysis.

---

## Security Observations

- RBAC is correctly enforced
- Least privilege model is active
- Directory role access is restricted
- No identity anomalies detected
- No privilege escalation observed

---

## Detection Engineering Extension

Detection Goal  
Identify repeated group membership changes indicating identity instability.

Detection Hypothesis  
Repeated add/remove cycles may indicate:
- Misconfiguration
- Administrative churn
- Access instability
- Governance gaps

---

## Microsoft Sentinel KQL Query

```kql
AuditLogs
| where OperationName in ("Add member to group", "Remove member from group")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend Target = tostring(TargetResources[0].userPrincipalName)
| where isnotempty(Target)
| summarize
    ActionCount = count(),
    Actions = make_set(OperationName),
    FirstSeen = min(TimeGenerated),
   
