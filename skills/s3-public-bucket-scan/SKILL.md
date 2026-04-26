---
name: s3-public-bucket-scan
description: "Scans S3 buckets for public exposure via ACL, policy, and BlockPublicAccess"
version: 0.1.0
entry_point: scan.py
---

# s3-public-bucket-scan

Identifies publicly exposed S3 buckets across AWS accounts.

## Usage

```bash
# Scan default region
python scan.py

# Scan specific region
python scan.py --region us-west-2

# Scan all regions
python scan.py --region all

# Include empty buckets
python scan.py --include-empty

# Dry-run mode (no AWS credentials needed)
python scan.py --dry-run
```

## AWS Permissions Required

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketLocation",
        "s3:ListBucket",
        "s3:GetObjectAcl",
        "s3:GetBucketTagging",
        "ec2:DescribeRegions"
      ],
      "Resource": "*"
    }
  ]
}
```

Note: `ec2:DescribeRegions` is only required when using `--region all`.

## Output

Markdown report to stdout with:
- Summary statistics
- Per-bucket findings with exposure vectors
- Sample affected objects
- AWS CLI remediation commands
