---
name: cloudtrail-novel-country-login
description: "Flags ConsoleLogin events from countries or IPs not seen in the last 30 days"
triggers:
  - novel-login
  - cloudtrail-login
---

# CloudTrail Novel Country Login

Detects and flags AWS ConsoleLogin events originating from countries or IP addresses not seen in the past 30 days. Useful for identifying suspicious or anomalous login activity based on geographic location and IP address history.

## Usage

### Basic Usage

Run the detector with default settings (24-hour lookback):

```bash
python detect.py
```

### Dry-Run Mode

Test with embedded fixture data without requiring AWS credentials:

```bash
python detect.py --dry-run
```

### Custom Lookback Window

Query CloudTrail history for a longer period (in hours):

```bash
python detect.py --lookback-hours 72
```

### Combined Options

Dry-run with custom lookback hours:

```bash
python detect.py --dry-run --lookback-hours 48
```

### Specify AWS Region

Query CloudTrail in a specific AWS region:

```bash
python detect.py --region us-west-2
```

### Help

Display all available options:

```bash
python detect.py --help
```

## Prerequisites

- **Python 3.12 or later** — Required by PEP 723 inline dependency specification
- **AWS credentials** — Configured for your AWS account (via AWS CLI, environment variables, or IAM role)
  - Credentials can be configured using `aws configure` or environment variables like `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
- **Internet connectivity** — For real runs (not needed for `--dry-run`)

## AWS Permissions Required

The AWS IAM user or role executing this skill must have the `cloudtrail:LookupEvents` permission. Use this policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudtrail:LookupEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

This permission allows the skill to query CloudTrail events within your AWS account. No write or modify permissions are required—this is a read-only audit skill.

## Output

The skill produces a markdown-formatted report showing:

- **event_time** — Timestamp of the login event (UTC)
- **principal** — AWS user identity (principal ID or username)
- **source_ip** — IP address of the login attempt
- **country** — Country code derived from the source IP
- **severity** — Risk level:
  - `high` — Login from a new country not seen in the baseline
  - `med` — Login from a new IP in a country previously seen

## Baseline Management

The skill automatically maintains a 30-day rolling baseline of seen login locations in:

```
~/.cache/aws-audit-skills/novel-country-baseline.json
```

- **First run:** Baseline is created automatically with the current logins
- **Subsequent runs:** All logins are compared against the baseline; novel ones are flagged and added to it
- **Auto-cleanup:** Entries older than 30 days are automatically pruned when the baseline is saved

You can delete this file to reset the baseline at any time.
