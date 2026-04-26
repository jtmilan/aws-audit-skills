---
name: iam-policy-audit
description: Audit AWS IAM policies for security antipatterns and hygiene issues. Flags wildcard actions, resource wildcards with privileged actions, inline policies, and stale roles. Outputs findings as a markdown table with severity levels and remediation commands.
triggers:
  - iam-audit
  - audit-iam-policies
  - iam-policy-audit
---

# IAM Policy Audit Skill

This Claude Code skill audits AWS IAM policies for security antipatterns and hygiene issues in your AWS account.

## Features

- **Wildcard Action Detection**: Flags policies with `Action: "*"` on non-admin policies (severity: high)
- **Privileged Action with Wildcard Resources**: Detects policies granting wildcard resources (`Resource: "*"`) with privileged actions like `s3:*`, `iam:*`, `ec2:TerminateInstances`, `kms:*`, or `dynamodb:*` (severity: high)
- **Inline Policy Detection**: Identifies roles with inline policies that should be managed policies (severity: medium)
- **Stale Role Detection**: Flags roles created over 90 days ago that may be unused (severity: low)

## Output

Findings are presented as a markdown table with the following columns:
- **Resource**: The role or policy name
- **Finding**: Description of the security issue
- **Severity**: high, med, or low
- **Fix Command**: Shell command or instructions to remediate the issue

## Permissions Required

This skill requires read-only IAM permissions:
- `iam:ListRoles`
- `iam:ListPolicies`
- `iam:GetPolicy`
- `iam:GetPolicyVersion`
- `iam:GetRole`
- `iam:ListRolePolicies`
- `iam:GetRolePolicy`
- `iam:ListAttachedRolePolicies`
