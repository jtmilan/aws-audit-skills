# S3 Public Bucket Scan - User Documentation

## Overview

The `s3-public-bucket-scan` skill identifies publicly exposed AWS S3 buckets across your AWS account. It detects exposure through multiple vectors:

- **Bucket ACL grants** to AllUsers or AuthenticatedUsers groups
- **Bucket policies** with wildcard principals lacking IP restrictions
- **BlockPublicAccess configurations** that are disabled
- **Object-level ACLs** on sample objects within buckets

The skill outputs a comprehensive markdown report listing exposed buckets, their exposure vectors, sample affected objects, and AWS CLI remediation commands. It can distinguish intentionally public buckets via tags and supports dry-run mode with fixture data for testing without AWS credentials.

## Prerequisites

### AWS Credentials

Configure AWS credentials before running the scan. The skill supports standard AWS credential methods:

- **AWS CLI configuration**: `~/.aws/credentials` and `~/.aws/config`
- **Environment variables**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
- **IAM role**: When running on EC2, ECS, or Lambda with an attached IAM role

Verify your credentials are configured:
```bash
aws sts get-caller-identity
```

### IAM Permissions

The following IAM permissions are required to run the scan:

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

**Permission Details:**
- `s3:ListAllMyBuckets` - List all S3 buckets in the account
- `s3:GetBucketAcl` - Read bucket ACL configurations
- `s3:GetBucketPolicy` - Read bucket policy documents
- `s3:GetBucketPublicAccessBlock` - Read BlockPublicAccess settings
- `s3:GetBucketLocation` - Determine bucket region
- `s3:ListBucket` - List objects within buckets (for sampling)
- `s3:GetObjectAcl` - Read object-level ACL configurations
- `s3:GetBucketTagging` - Check for intentional public bucket tags
- `ec2:DescribeRegions` - Enumerate enabled regions (only required for `--region all`)

## Usage

### Basic Usage Examples

#### 1. Scan default region

Scan all buckets in your default AWS region (from AWS CLI configuration):

```bash
python scan.py
```

#### 2. Scan specific region

Scan all buckets in a specific AWS region:

```bash
python scan.py --region us-west-2
```

Other region examples:
```bash
python scan.py --region us-east-1
python scan.py --region eu-west-1
python scan.py --region ap-southeast-1
```

#### 3. Scan all regions

Scan all buckets across all enabled AWS regions:

```bash
python scan.py --region all
```

**Note:** This option requires the `ec2:DescribeRegions` permission and may take longer to complete.

#### 4. Include empty buckets

By default, buckets with zero objects are excluded from the report. To include them:

```bash
python scan.py --include-empty
```

This is useful for identifying publicly accessible buckets that might be used for future uploads.

#### 5. Dry-run mode

Test the skill without AWS credentials using hardcoded fixture data:

```bash
python scan.py --dry-run
```

This mode is useful for:
- Testing the skill before configuring AWS credentials
- Demonstrating the output format
- Validating the skill installation

### Combining Options

You can combine multiple options:

```bash
# Scan all regions and include empty buckets
python scan.py --region all --include-empty

# Scan specific region and include empty buckets
python scan.py --region us-west-2 --include-empty
```

## Output Format

The scan produces a markdown report to stdout with the following structure:

### Report Header

```markdown
# S3 Public Bucket Scan Report

**Region:** us-west-2
**Timestamp:** 2026-04-26T14:30:00.123456
**Buckets Scanned:** 42
**Public Buckets Found:** 3
```

### Findings Section

Each public bucket is reported in a separate section:

```markdown
## Findings

### my-public-bucket

**Exposure Vectors:**
- ACL: Grant FULL_CONTROL to AllUsers
- Policy: Statement 0 allows Principal='*' without aws:SourceIp restriction
- BlockPublicAccess: BlockPublicAcls=false, IgnorePublicAcls=false

**Sample Affected Objects:**
- s3://my-public-bucket/data/file1.csv (ACL: READ)
- s3://my-public-bucket/logs/access.log (ACL: FULL_CONTROL)

**Remediation:**
```bash
# Remove public ACL
aws s3api put-bucket-acl --bucket my-public-bucket --acl private

# Enable BlockPublicAccess
aws s3api put-public-access-block --bucket my-public-bucket \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Review and update bucket policy
aws s3api get-bucket-policy --bucket my-public-bucket
# Then edit policy and apply with:
# aws s3api put-bucket-policy --bucket my-public-bucket --policy file://policy.json
```

### Intentionally Public Buckets

Buckets tagged with `public=true` are marked as `[INTENTIONAL]`:

```markdown
### my-website-bucket [INTENTIONAL]

**Exposure Vectors:**
- ACL: Grant READ to AllUsers

**Remediation:**
```bash
# Remove public ACL
aws s3api put-bucket-acl --bucket my-website-bucket --acl private
```

These buckets are still reported but distinguished from unintentional exposure.

## Interpreting Results

### Exposure Types

#### 1. ACL Exposure

```
ACL: Grant FULL_CONTROL to AllUsers
ACL: Grant READ to AuthenticatedUsers
```

**What it means:** The bucket's Access Control List grants permissions to public groups.

- **AllUsers**: Anyone on the internet can access the bucket (no authentication required)
- **AuthenticatedUsers**: Any AWS account holder can access the bucket

**Permissions:**
- `READ`: List bucket contents
- `WRITE`: Upload/delete objects
- `READ_ACP`: Read bucket ACL
- `WRITE_ACP`: Modify bucket ACL
- `FULL_CONTROL`: All permissions

**Risk Level:** HIGH - Direct public access

#### 2. Policy Exposure

```
Policy: Statement 0 allows Principal='*' without aws:SourceIp restriction
```

**What it means:** The bucket policy allows actions from any principal (wildcard `*`) without restricting by IP address.

**Risk Level:** HIGH - May allow unintended public access depending on policy actions

**Note:** The scan flags policies with `Principal='*'` that lack `aws:SourceIp` conditions. Manual review is recommended to verify if the policy is intentionally public (e.g., for CloudFront or public website hosting).

#### 3. BlockPublicAccess Disabled

```
BlockPublicAccess: BlockPublicAcls=false
BlockPublicAccess: IgnorePublicAcls=false
BlockPublicAccess: BlockPublicPolicy=false
BlockPublicAccess: RestrictPublicBuckets=false
```

**What it means:** Amazon S3 Block Public Access settings are disabled, allowing public ACLs or policies to take effect.

**AWS Block Public Access Settings:**
- `BlockPublicAcls`: Prevents new public ACLs from being applied
- `IgnorePublicAcls`: Ignores existing public ACLs
- `BlockPublicPolicy`: Prevents public bucket policies
- `RestrictPublicBuckets`: Restricts cross-account access

**Risk Level:** MEDIUM - Allows public exposure if ACLs or policies are misconfigured

**Best Practice:** Enable all four settings unless you have a specific need for public buckets.

#### 4. Object-Level ACL Exposure

```
Sample Affected Objects:
- s3://bucket/path/file.txt (ACL: READ)
```

**What it means:** Individual objects within the bucket have public ACLs, even if the bucket itself is private.

**Risk Level:** HIGH - Object-level exposure can bypass bucket-level restrictions

**Note:** The scan checks the first 10 objects in each bucket as a representative sample. More objects may be affected.

### Intentional Public Buckets

Buckets can be marked as intentionally public by adding a tag:

- **Tag Key**: `public`
- **Tag Value**: `true` (case-sensitive)

To tag a bucket as intentionally public:

```bash
aws s3api put-bucket-tagging --bucket my-bucket \
  --tagging 'TagSet=[{Key=public,Value=true}]'
```

These buckets will still appear in the report with the `[INTENTIONAL]` marker, but won't trigger alerts in automated monitoring systems.

## Remediation Guidance

### 1. Remove Public ACLs

Make bucket and objects private by setting the private ACL:

```bash
# Set bucket to private
aws s3api put-bucket-acl --bucket BUCKET_NAME --acl private

# Remove public ACL from specific object
aws s3api put-object-acl --bucket BUCKET_NAME --key OBJECT_KEY --acl private

# Remove public ACLs from all objects (use with caution)
aws s3 cp s3://BUCKET_NAME/ s3://BUCKET_NAME/ --recursive --acl private
```

### 2. Enable Block Public Access

Enable all Block Public Access settings (recommended for non-public buckets):

```bash
aws s3api put-public-access-block --bucket BUCKET_NAME \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

Enable at the account level (applies to all buckets):

```bash
aws s3control put-public-access-block \
  --account-id ACCOUNT_ID \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

### 3. Review and Update Bucket Policies

Retrieve the current bucket policy:

```bash
aws s3api get-bucket-policy --bucket BUCKET_NAME --query Policy --output text | jq .
```

Remove a bucket policy entirely:

```bash
aws s3api delete-bucket-policy --bucket BUCKET_NAME
```

Update a bucket policy (after editing policy.json):

```bash
aws s3api put-bucket-policy --bucket BUCKET_NAME --policy file://policy.json
```

**Policy Best Practices:**
- Avoid `Principal: "*"` unless necessary for public access
- Use `Condition` blocks to restrict access by IP, VPC, or user agent
- Specify explicit actions rather than using wildcards
- Use `aws:SecureTransport` condition to require HTTPS

Example restricted policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RestrictedPublicRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::BUCKET_NAME/*",
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": [
            "203.0.113.0/24",
            "198.51.100.0/24"
          ]
        }
      }
    }
  ]
}
```

### 4. Verify Changes

After applying remediation, verify the bucket is no longer public:

```bash
# Check bucket ACL
aws s3api get-bucket-acl --bucket BUCKET_NAME

# Check Block Public Access settings
aws s3api get-public-access-block --bucket BUCKET_NAME

# Check bucket policy
aws s3api get-bucket-policy --bucket BUCKET_NAME

# Re-run the scan
python scan.py --region REGION
```

## Troubleshooting

### Error: AWS credentials not configured

**Symptom:**
```
Error: AWS credentials not configured.
Configure credentials via AWS CLI, environment variables, or IAM role.
```

**Solution:**
- Run `aws configure` to set up credentials
- Export environment variables: `export AWS_ACCESS_KEY_ID=...`
- Ensure IAM role is attached (if running on AWS compute)

### Warning: Access denied to bucket

**Symptom:**
```
Warning: Access denied to bucket 'some-bucket'. Skipping.
```

**Solution:**
- Verify your IAM user/role has the required S3 permissions
- Check bucket policies that might deny access
- Some buckets may be in other accounts and not accessible

### No buckets found in region

**Symptom:**
Report shows "Buckets Scanned: 0"

**Solution:**
- Verify buckets exist in the specified region
- Check that `s3:ListAllMyBuckets` permission is granted
- Try `--region all` to scan all regions

### Dry-run mode doesn't require credentials

**Symptom:**
Dry-run mode works but real scan fails

**Solution:**
This is expected behavior. Dry-run mode uses hardcoded fixture data and doesn't contact AWS. Configure credentials to run real scans.

## Advanced Usage

### Redirecting Output to a File

Save the markdown report to a file:

```bash
python scan.py --region us-west-2 > report.md
```

### Converting to HTML

Convert the markdown report to HTML using pandoc:

```bash
python scan.py --region us-west-2 | pandoc -f markdown -t html -o report.html
```

### Filtering Results

Extract only bucket names with public exposure:

```bash
python scan.py | grep "^### " | grep -v "INTENTIONAL" | sed 's/^### //'
```

### Scheduled Scanning

Run periodic scans using cron (Linux/macOS):

```bash
# Add to crontab (run daily at 2 AM)
0 2 * * * /usr/bin/python3 /path/to/scan.py --region all > /var/log/s3-scan-$(date +\%Y\%m\%d).md 2>&1
```

### Multi-Account Scanning

To scan multiple AWS accounts, use AWS CLI profiles:

```bash
# Configure profiles
aws configure --profile account1
aws configure --profile account2

# Scan each account
AWS_PROFILE=account1 python scan.py --region all > account1-report.md
AWS_PROFILE=account2 python scan.py --region all > account2-report.md
```

## Security Considerations

### Read-Only Operations

This skill performs only read-only AWS API operations. It will never modify bucket configurations, ACLs, or policies. All remediation must be performed manually using the provided AWS CLI commands.

### Credential Security

- Never commit AWS credentials to version control
- Use IAM roles with minimum required permissions
- Rotate access keys regularly
- Enable MFA for sensitive accounts

### False Positives

The policy detection uses basic heuristics and may flag policies that are intentionally public but safe (e.g., CloudFront Origin Access Identity patterns). Always manually review flagged policies before applying remediation.

### Sampling Limitations

Object-level ACL checks sample only the first 10 objects in each bucket. Buckets with thousands of objects may have additional public objects not detected by the scan. For comprehensive object-level scanning, use AWS Access Analyzer or custom scripts.

## Additional Resources

- [AWS S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [AWS S3 Bucket Policies](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html)
- [AWS S3 ACLs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html)
- [AWS Access Analyzer for S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-analyzer.html)
- [AWS Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
