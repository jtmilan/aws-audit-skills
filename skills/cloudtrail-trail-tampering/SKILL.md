---
name: cloudtrail-trail-tampering
description: Flags CloudTrail events that disable or weaken audit logging
version: 0.1.0
entry_point: detect.py
---

# CloudTrail Trail Tampering Detection

This skill detects CloudTrail events that indicate attempts to disable or weaken audit logging in your AWS account.

## Detected Event Types

The skill flags the following high-risk events:

| Event Name | Description | Risk |
|------------|-------------|------|
| **DeleteTrail** | CloudTrail trail was deleted | Removes audit logging entirely |
| **StopLogging** | Logging was stopped on a trail | Suspends event collection |
| **UpdateTrail** | Trail configuration changed with logging disabled | Disables audit logging via configuration |
| **PutBucketPublicAccessBlock** | S3 bucket public access block disabled | May expose audit logs to public access |

### Event Classification Details

- **DeleteTrail**: Any deletion of a CloudTrail trail is flagged as tampering
- **StopLogging**: Any stop logging action is flagged as tampering
- **UpdateTrail**: Only flagged when `requestParameters.isLogging` is explicitly set to `false`
- **PutBucketPublicAccessBlock**: Only flagged when ALL FOUR protections are disabled:
  - `BlockPublicAcls: false`
  - `IgnorePublicAcls: false`
  - `BlockPublicPolicy: false`
  - `RestrictPublicBuckets: false`

## CLI Arguments

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--lookback-hours` | integer | 24 | Number of hours to look back for events |
| `--account-id` | string | None | AWS account ID to scope events. Defaults to caller's account via STS. |
| `--dry-run` | flag | false | Use fixture data instead of calling AWS API |

### Usage Examples

```bash
# Check for tampering events in the last 24 hours (default)
python3 detect.py

# Check for tampering events in the last 48 hours
python3 detect.py --lookback-hours 48

# Check for tampering events with explicit account ID
python3 detect.py --account-id 111111111111

# Check for tampering events in a specific account over 72 hours
python3 detect.py --account-id 111111111111 --lookback-hours 72

# Run with fixture data (no AWS credentials required)
python3 detect.py --dry-run
```

## Required IAM Permissions

The skill requires the following IAM permission to query CloudTrail events:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["cloudtrail:LookupEvents"],
      "Resource": "*"
    }
  ]
}
```

## Output Format

The skill outputs a markdown table with the following columns:

| Column | Description |
|--------|-------------|
| `event_time` | ISO 8601 timestamp of the event |
| `principal` | IAM ARN, username, or principal ID of the actor |
| `action` | The CloudTrail event name |
| `target_resource` | Trail name or S3 bucket name affected |
| `severity` | Always "high" for tampering events |

### Example Output

```markdown
| event_time | principal | action | target_resource | severity |
|------------|-----------|--------|-----------------|----------|
| 2024-01-15T10:30:00+00:00 | arn:aws:iam::<account-id>:user/malicious-user | DeleteTrail | audit-trail | high |
| 2024-01-15T11:00:00+00:00 | arn:aws:iam::<account-id>:user/another-user | StopLogging | main-trail | high |
```
