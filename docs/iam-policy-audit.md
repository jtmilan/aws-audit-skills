# IAM Policy Audit User Documentation

## Description

The IAM Policy Audit skill audits AWS IAM policies for security antipatterns and hygiene issues. It identifies four categories of findings:

1. **Wildcard Actions**: Detects policies that grant `Action: "*"` on non-administrative roles, which violates the principle of least privilege.
2. **Wildcard Resources with Privileged Actions**: Identifies policies combining `Resource: "*"` with highly sensitive actions like `s3:*`, `iam:*`, `kms:*`, `dynamodb:*`, or `ec2:TerminateInstances`.
3. **Inline Policies**: Flags roles with inline policies that should be converted to managed policies for better auditability and reusability.
4. **Stale Roles**: Detects roles created over 90 days ago that may be unused and should be reviewed for deletion.

The skill outputs findings as a markdown table with severity levels and actionable remediation guidance.

## Installation

The skill is installed via `install.sh` in the project root, which symlinks all skills into `~/.claude/skills/`. To install:

```bash
bash install.sh
```

This makes the skill available to Claude Code as an autonomous skill that can be invoked programmatically.

## Usage

### Example 1: Audit with High Severity Filter

```bash
python audit.py --account-id 123456789012 --severity high
```

This audits AWS account `123456789012` and reports only high-severity findings (wildcard actions and wildcard resources with privileged actions).

### Example 2: Audit with Medium Severity and Dry-Run Mode

```bash
python audit.py --account-id 123456789012 --severity med --dry-run
```

This runs in dry-run mode (using fixture data instead of live AWS API calls) and reports both medium and high-severity findings. Dry-run mode is useful for testing without AWS credentials or to demonstrate the skill's capabilities on sample data.

## Output Format

The skill outputs findings as a markdown table with four columns:

| Column | Description |
|--------|-------------|
| **Resource** | The name of the IAM role or policy where the finding was detected |
| **Finding** | A human-readable description of the security issue or hygiene problem |
| **Severity** | The severity level: `high`, `med`, or `low` |
| **Fix Command** | A shell command or step-by-step instructions to remediate the issue |

If no findings are detected, the skill outputs:
```
## No IAM Policy Issues Found
```

## Findings Reference

### Wildcard Action

**Severity**: high

**Description**: A non-administrative IAM policy grants the wildcard action `Action: "*"`, allowing all API actions without restriction.

**Risk**: This violates the principle of least privilege and grants excessive permissions that could be exploited if credentials are compromised.

**Remediation**: Review the policy and replace the wildcard with specific actions required for the role's legitimate function. For example, if a Lambda function only needs to write logs, grant `logs:CreateLogGroup`, `logs:CreateLogStream`, and `logs:PutLogEvents` instead of `*`.

**Example Fix Command**:
```bash
Review policy and replace wildcard with specific actions
```

---

### Wildcard Resource with Privileged Action

**Severity**: high

**Description**: A policy grants `Resource: "*"` combined with one of the following privileged actions:
- `s3:*` - All S3 operations on all buckets
- `iam:*` - All IAM operations
- `kms:*` - All Key Management Service operations
- `dynamodb:*` - All DynamoDB operations
- `ec2:TerminateInstances` - Ability to terminate any EC2 instance

Note: The skill uses two-tier matching:
- **Tier 1 (Exact Match)**: Actions explicitly listed above (e.g., `s3:*`, `iam:*`, `ec2:TerminateInstances`, `kms:*`, `dynamodb:*`)
- **Tier 2 (Service Wildcard)**: Any action matching `<service>:*` where `<service>` is one of: `s3`, `iam`, `kms`, or `dynamodb` (e.g., `s3:GetObject` falls under `s3:*`)

**Risk**: Unrestricted access to sensitive services could allow an attacker to exfiltrate data (S3), modify identity and access management (IAM), encrypt critical data with attacker-controlled KMS keys, or delete databases (DynamoDB).

**Remediation**: Restrict the `Resource` field to specific ARNs. For example:
- Replace `Resource: "*"` with `Resource: "arn:aws:s3:::my-bucket/*"` for S3 operations
- Use IAM resource constraints to limit operations to specific roles or users
- For KMS, specify the key ARN instead of all resources

**Example Fix Command**:
```bash
Restrict Resource to specific ARNs (e.g., arn:aws:s3:::my-bucket/*)
```

---

### Inline Policies

**Severity**: med

**Description**: A role has inline policies (policies directly embedded in the role) rather than managed policies (standalone policies that can be reused and versioned).

**Risk**: Inline policies are harder to audit, audit, and manage at scale. They cannot be reused across multiple roles, making policy updates error-prone and difficult to track.

**Remediation**: Convert inline policies to managed policies. This improves auditability, enables policy versioning, and allows the same policy to be attached to multiple roles.

**Example Fix Command**:
```bash
Convert inline policy to managed policy and attach to role
```

---

### Stale Roles

**Severity**: low

**Description**: A role was created over 90 days ago and may be unused.

**Risk**: Unused roles accumulate in the account, increasing the attack surface and creating compliance risks. Roles that are no longer needed should be deleted.

**Limitation**: Stale role detection is based on `CreateDate` only. No AccessAdvisor API is called. Long-running infrastructure roles (e.g., Lambda execution roles, service-linked roles created in 2022) may be flagged as stale even though they are actively used. Always review findings before deletion.

**Remediation**: Verify the role is no longer needed, then delete it:
```bash
aws iam delete-role --role-name <role-name>
```

Note: If the role has inline policies or attached managed policies, you must first remove them using:
```bash
aws iam delete-role-policy --role-name <role-name> --policy-name <policy-name>
aws iam detach-role-policy --role-name <role-name> --policy-arn <policy-arn>
```

**Example Fix Command**:
```bash
Review role usage. If unused, delete with: aws iam delete-role --role-name <role-name>
```

---

## Severity Levels

| Severity | Definition | Examples | Typical Remediation Time |
|----------|-----------|----------|--------------------------|
| **high** | Immediate security risk; violates principle of least privilege and could enable privilege escalation or data exfiltration | Wildcard actions on non-admin policies; wildcard resources with `s3:*`, `iam:*`, `kms:*`, `dynamodb:*` | 1–4 hours (should be prioritized) |
| **med** | Hygiene issue; increases operational and compliance risk | Inline policies that should be managed | 4–24 hours (address within a sprint) |
| **low** | Operational inefficiency; potential unused or orphaned resource | Roles created >90 days ago with no recent activity | 1–7 days (review periodically) |

## AWS Permissions Required

To run the IAM Policy Audit skill, the AWS principal (user or role) must have the following read-only IAM permissions:

- `iam:ListRoles` - List all roles in the account
- `iam:ListPolicies` - List all customer-managed policies
- `iam:GetPolicy` - Retrieve policy metadata
- `iam:GetPolicyVersion` - Retrieve policy document for a specific version
- `iam:GetRole` - Get role details and metadata
- `iam:ListRolePolicies` - List inline policies attached to a role
- `iam:GetRolePolicy` - Retrieve an inline policy document
- `iam:ListAttachedRolePolicies` - List managed policies attached to a role

Here is a minimal IAM policy to grant these permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListRoles",
        "iam:ListPolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:GetRole",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies"
      ],
      "Resource": "*"
    }
  ]
}
```

The skill is read-only and does not modify any IAM policies, roles, or permissions.

## Troubleshooting

### Error: "AWS credentials not found"

**Cause**: The skill could not find valid AWS credentials in your environment.

**Solution**:
1. Ensure your AWS credentials are configured. Check:
   - Environment variables: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
   - Credentials file: `~/.aws/credentials`
   - AWS SSO profile: Run `aws sso login --profile <profile-name>`

2. If using a profile, set the `AWS_PROFILE` environment variable:
   ```bash
   export AWS_PROFILE=my-profile
   python audit.py --account-id 123456789012
   ```

### Error: "Insufficient IAM permissions"

**Cause**: Your AWS credentials don't have the required IAM read permissions.

**Solution**:
1. Verify your user or role has all eight required IAM permissions listed in the "AWS Permissions Required" section.
2. Ask your AWS administrator to attach an IAM policy granting the required permissions.
3. If using an assumed role, ensure the trust relationship allows your principal to assume the role.

### Error: "Invalid choice: 'invalid' (choose from 'low', 'med', 'high')"

**Cause**: You specified an invalid severity level.

**Solution**: Use only `low`, `med`, or `high` for the `--severity` flag:
```bash
python audit.py --account-id 123456789012 --severity high
```

### Error: "--account-id must be a 12-digit numeric AWS account ID"

**Cause**: The account ID is not numeric or is not 12 digits.

**Solution**: Provide a valid 12-digit AWS account ID (no hyphens or other characters):
```bash
python audit.py --account-id 123456789012
```

### Dry-Run Mode Returns No Findings

**Cause**: The fixture files may be missing or the dry-run mode is not loading data correctly.

**Solution**:
1. Verify fixture files exist in the skill directory:
   ```bash
   ls -la ~/.claude/skills/iam-policy-audit/fixtures/
   ```
2. If missing, reinstall the skill:
   ```bash
   bash install.sh
   ```

### Stale Role Findings Seem Incorrect

**Cause**: The skill flags roles created >90 days ago, but your role may be actively used.

**Solution**:
1. This is a known limitation. The skill uses `CreateDate` only and does not call the AccessAdvisor API for actual access logs.
2. Review each flagged role to determine if it's still needed.
3. If the role is still active, you can safely ignore the finding or delete the role if it's no longer needed.
4. Plan to enhance the skill in the future to use CloudTrail or EventBridge logs for more accurate last-access detection.

---

**For more information**: Review the `SKILL.md` file in the skill directory or contact your AWS security team.
