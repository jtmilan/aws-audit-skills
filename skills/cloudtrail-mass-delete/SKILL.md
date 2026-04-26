---
name: cloudtrail-mass-delete
description: Detects bursts of >10 Delete* API calls within 5 minutes from the same principal in CloudTrail.
triggers:
  - cloudtrail-mass-delete
  - detect-mass-delete
---

# CloudTrail Mass Delete Detector

Detects mass deletion activity in AWS CloudTrail logs by identifying bursts of Delete* API calls within sliding 5-minute windows. This skill helps identify potential data destruction attacks, runaway automation, or unauthorized deletion campaigns.

## Overview

The skill queries CloudTrail history and identifies principals (IAM users, roles, or services) that performed more than 10 deletion operations within any 5-minute window. This pattern-matching approach surfaces suspicious behavior while filtering out normal operational deletions.

## Prerequisites

- **CloudTrail enabled** in your AWS account with management event logging
- **AWS credentials** configured (`aws configure` or environment variables)
- **IAM permissions**: `cloudtrail:LookupEvents`

## Usage

```bash
# Analyze the last 24 hours of CloudTrail logs
python3 skills/cloudtrail-mass-delete/detect.py --lookback-hours 24

# Filter to a specific principal
python3 skills/cloudtrail-mass-delete/detect.py --lookback-hours 12 \
  --principal arn:aws:iam::123456789012:user/admin

# Use fixture data for testing (no AWS API calls)
python3 skills/cloudtrail-mass-delete/detect.py --lookback-hours 1 --dry-run
```

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--lookback-hours HOURS` | Yes | Number of hours of CloudTrail history to analyze |
| `--principal ARN` | No | Filter results to a specific IAM principal ARN |
| `--dry-run` | No | Use fixture data instead of calling AWS APIs |

## Output Format

### Detection Found

When mass deletion activity is detected, the skill outputs a markdown table with the following columns:

| window_start | principal | action_count | sample_actions |
|--------------|-----------|--------------|----------------|
| 2026-04-26T10:05:00Z | arn:aws:iam::123456789012:user/admin | 15 | DeleteBucket, DeleteObject, DeleteUser |
| 2026-04-26T09:30:00Z | arn:aws:iam::123456789012:role/automation | 12 | DeleteFunction, DeleteRole |

**Column Descriptions**:
- `window_start`: UTC timestamp marking the start of the 5-minute window where the burst was detected
- `principal`: IAM principal ARN (user, role, or service) that performed the deletions
- `action_count`: Total number of Delete* API calls within the window
- `sample_actions`: Up to 3 unique action names (alphabetically sorted) representing the types of deletions

Results are sorted by `action_count` (descending), then by `window_start` (ascending).

### No Detection

When no mass deletion activity is detected:

```markdown
## No Mass Delete Activity Detected
```

## Detection Algorithm

1. **Query CloudTrail**: Fetch events for the specified time range (now - lookback_hours to now)
2. **Filter deletions**: Keep only events where `eventName` starts with "Delete"
3. **Group by principal**: Organize events by IAM principal ARN
4. **Sliding window analysis**: For each principal:
   - Sort events chronologically
   - Apply a 5-minute sliding window
   - Count events within each window
   - Flag windows with >10 events as bursts
5. **Output results**: Sort by severity (action count) and present as markdown table

## Example Scenarios

### Scenario 1: Compromised Credentials

An attacker gains access to admin credentials and begins deleting S3 buckets:

```bash
$ python3 skills/cloudtrail-mass-delete/detect.py --lookback-hours 2
| window_start | principal | action_count | sample_actions |
|--------------|-----------|--------------|----------------|
| 2026-04-26T14:22:00Z | arn:aws:iam::123456789012:user/admin | 47 | DeleteBucket, DeleteObject |
```

**Interpretation**: Admin user performed 47 deletions in 5 minutes—highly suspicious.

### Scenario 2: Runaway Automation

A misconfigured cleanup script deletes Lambda functions:

```bash
$ python3 skills/cloudtrail-mass-delete/detect.py --lookback-hours 6
| window_start | principal | action_count | sample_actions |
|--------------|-----------|--------------|----------------|
| 2026-04-26T12:15:00Z | arn:aws:iam::123456789012:role/cleanup-automation | 23 | DeleteFunction |
```

**Interpretation**: Automation role deleted 23 Lambda functions—likely a bug in cleanup logic.

### Scenario 3: Normal Operations

Low-volume deletions across multiple users:

```bash
$ python3 skills/cloudtrail-mass-delete/detect.py --lookback-hours 24
## No Mass Delete Activity Detected
```

**Interpretation**: No concerning deletion patterns in the last 24 hours.

## Limitations

- **Window size**: Fixed at 5 minutes (not configurable)
- **Threshold**: Fixed at >10 events (not configurable)
- **Region**: Uses default AWS region from your configuration
- **Pagination**: Very large lookback periods may be slow due to CloudTrail API pagination
- **Time precision**: Relies on CloudTrail event timestamps (typically accurate to the second)

## Troubleshooting

### "AWS credentials not configured"

Ensure your AWS credentials are set:
```bash
aws configure
# OR
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
```

### "Access denied"

Your IAM principal needs the `cloudtrail:LookupEvents` permission:
```json
{
  "Effect": "Allow",
  "Action": "cloudtrail:LookupEvents",
  "Resource": "*"
}
```

### "No events found"

- Verify CloudTrail is enabled in your account
- Check that the lookback period includes the time range of interest
- Ensure deletion events were logged (some services may not emit CloudTrail events)

## Exit Codes

- **0**: Success (bursts detected or no bursts)
- **1**: Error (AWS API error, invalid arguments, missing credentials, etc.)

## Performance Notes

- **API calls**: One `lookup_events` call per 50 events (with automatic pagination)
- **Memory usage**: All events are loaded into memory for sliding window analysis
- **Processing time**: Typically <5 seconds for 24 hours of history on a moderately active account

## Related AWS Services

This skill analyzes CloudTrail logs. To investigate further after detection:
- **CloudTrail Console**: View full event details
- **CloudWatch Logs**: Set up alarms for real-time detection
- **AWS Config**: Review resource configuration changes
- **IAM Access Analyzer**: Identify permission issues

## See Also

- [AWS CloudTrail Documentation](https://docs.aws.amazon.com/cloudtrail/)
- [CloudTrail Event Reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html)
