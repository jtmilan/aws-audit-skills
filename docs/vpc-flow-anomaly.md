# VPC Flow Anomaly Skill

Analyze VPC Flow Logs from S3 for traffic anomalies.

## Prerequisites

- VPC Flow Logs configured to publish to S3 (version 2 default format)
- IAM permissions: `s3:GetObject`, `s3:ListObjectsV2`, `ec2:DescribeFlowLogs`, `ec2:DescribeVpcs`

## Usage

### Basic Analysis

```bash
python skills/vpc-flow-anomaly/flow_check.py --vpc-id vpc-12345678
```

### Custom Lookback Window

```bash
python skills/vpc-flow-anomaly/flow_check.py --vpc-id vpc-12345678 --lookback-hours 48
```

### Dry Run (Fixture Data)

```bash
python skills/vpc-flow-anomaly/flow_check.py --dry-run
```

## Detection Rules

### Top Talker Anomalies

IPs with traffic volume z-score > 2.0 compared to 7-day baseline.

- **CRITICAL**: z-score > 5.0
- **HIGH**: z-score > 3.0
- **MEDIUM**: z-score > 2.0

### DROP List Matches

Outbound traffic to Spamhaus DROP-listed IP ranges.

- All matches are **CRITICAL** severity
- DROP list cached at `~/.cache/aws-audit-skills/drop.txt` for 24 hours

### Suspicious East-West Traffic

Internal traffic on ports typically ingress-only (22, 3389, 5432).

- **HIGH**: Port 5432 (PostgreSQL)
- **MEDIUM**: Port 22 (SSH), Port 3389 (RDP)

### Flow Log Gaps

Missing log intervals > 5 minutes between consecutive records.

- **CRITICAL**: Gap > 60 minutes
- **HIGH**: Gap > 15 minutes
- **MEDIUM**: Gap > 5 minutes

## Output Format

Markdown report with sections for each anomaly type, including:
- Evidence details
- Severity rating
- Suggested next steps

## Troubleshooting

### "No S3-destination flow logs configured"

Ensure VPC Flow Logs are enabled with S3 as the destination. CloudWatch Logs destinations are not supported.

### "Access denied to flow log bucket"

Verify IAM permissions include `s3:GetObject` and `s3:ListObjectsV2` for the flow log bucket.

### "Failed to fetch Spamhaus DROP list"

Check network connectivity. If offline, pre-populate the cache at `~/.cache/aws-audit-skills/drop.txt`.

### "AWS credentials not found"

Configure AWS credentials via:
- AWS CLI: `aws configure`
- Environment variables: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
- IAM role (when running on EC2/Lambda)

### "VPC not found or not accessible"

Verify the VPC ID is correct and that your IAM user/role has `ec2:DescribeVpcs` permission for the VPC.
