---
name: vpc-flow-anomaly
description: Reads VPC Flow Logs from S3 and flags traffic anomalies including top-talker outliers, DROP-list matches, suspicious east-west traffic, and flow log gaps. Report-only — never auto-blocks traffic.
triggers: []
---

# VPC Flow Anomaly

Analyze VPC Flow Logs for traffic anomalies.

## Usage

```bash
# Analyze VPC flow logs (last 24 hours)
python skills/vpc-flow-anomaly/flow_check.py --vpc-id vpc-12345678

# Custom lookback window
python skills/vpc-flow-anomaly/flow_check.py --vpc-id vpc-12345678 --lookback-hours 48

# Dry run with fixture data
python skills/vpc-flow-anomaly/flow_check.py --dry-run
```

## Prerequisites

- VPC Flow Logs configured to publish to S3
- IAM permissions: `s3:GetObject`, `s3:ListObjectsV2`, `ec2:DescribeFlowLogs`, `ec2:DescribeVpcs`
