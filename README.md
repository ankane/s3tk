# s3tk

A security toolkit for Amazon S3

![Screenshot](https://gist.githubusercontent.com/ankane/13a9230353c78c0d5c35fd9319a23d98/raw/434b9c54bff9d41c398aa3b57f0d0494217ef7fa/console2.gif)

:tangerine: Battle-tested at [Instacart](https://www.instacart.com/opensource)

## Installation

Run:

```sh
pip install s3tk
```

You can use the [AWS CLI](https://github.com/aws/aws-cli) or [AWS Vault](https://github.com/99designs/aws-vault) to set up your AWS credentials:

```sh
pip install awscli
aws configure
```

See [IAM policies](#iam-policies) needed for each command.

## Commands

### Scan

Scan your buckets for:

- ACL open to public
- policy open to public
- public access blocked
- logging enabled
- versioning enabled
- default encryption enabled

```sh
s3tk scan
```

Only run on specific buckets

```sh
s3tk scan my-bucket my-bucket-2
```

Also works with wildcards

```sh
s3tk scan "my-bucket*"
```

Confirm correct log bucket(s) and prefix

```
s3tk scan --log-bucket my-s3-logs --log-bucket other-region-logs --log-prefix "{bucket}/"
```

Check CloudTrail object-level logging [experimental]

```sh
s3tk scan --object-level-logging
```

Skip logging, versioning, or default encryption

```sh
s3tk scan --skip-logging --skip-versioning --skip-default-encryption
```

Get email notifications of failures (via SNS)

```sh
s3tk scan --sns-topic arn:aws:sns:...
```

### List Policy

List bucket policies

```sh
s3tk list-policy
```

Only run on specific buckets

```sh
s3tk list-policy my-bucket my-bucket-2
```

Show named statements

```sh
s3tk list-policy --named
```

### Set Policy

**Note:** This replaces the previous policy

Only private uploads

```sh
s3tk set-policy my-bucket --no-object-acl
```

### Delete Policy

Delete policy

```sh
s3tk delete-policy my-bucket
```

### Block Public Access

Block public access on specific buckets

```sh
s3tk block-public-access my-bucket my-bucket-2
```

Use the `--dry-run` flag to test

### Enable Logging

Enable logging on all buckets

```sh
s3tk enable-logging --log-bucket my-s3-logs
```

Only on specific buckets

```sh
s3tk enable-logging my-bucket my-bucket-2 --log-bucket my-s3-logs
```

Set log prefix (`{bucket}/` by default)

```sh
s3tk enable-logging --log-bucket my-s3-logs --log-prefix "logs/{bucket}/"
```

Use the `--dry-run` flag to test

A few notes about logging:

- buckets with logging already enabled are not updated at all
- the log bucket must in the same region as the source bucket - run this command multiple times for different regions
- it can take over an hour for logs to show up

### Enable Versioning

Enable versioning on all buckets

```sh
s3tk enable-versioning
```

Only on specific buckets

```sh
s3tk enable-versioning my-bucket my-bucket-2
```

Use the `--dry-run` flag to test

### Enable Default Encryption

Enable [default encryption](https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html) on all buckets

```sh
s3tk enable-default-encryption
```

Only on specific buckets

```sh
s3tk enable-default-encryption my-bucket my-bucket-2
```

This does not encrypt existing objects - use the `encrypt` command for this

Use the `--dry-run` flag to test

### Scan Object ACL

Scan ACL on all objects in a bucket

```sh
s3tk scan-object-acl my-bucket
```

Only certain objects

```sh
s3tk scan-object-acl my-bucket --only "*.pdf"
```

Except certain objects

```sh
s3tk scan-object-acl my-bucket --except "*.jpg"
```

### Reset Object ACL

Reset ACL on all objects in a bucket

```sh
s3tk reset-object-acl my-bucket
```

This makes all objects private. See [bucket policies](#bucket-policies) for how to enforce going forward.

Use the `--dry-run` flag to test

Specify certain objects the same way as [scan-object-acl](#scan-object-acl)

### Encrypt

Encrypt all objects in a bucket with [server-side encryption](https://docs.aws.amazon.com/AmazonS3/latest/dev/serv-side-encryption.html)

```sh
s3tk encrypt my-bucket
```

Use [S3-managed keys](https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingServerSideEncryption.html) by default. For [KMS-managed keys](https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingKMSEncryption.html), use:

```sh
s3tk encrypt my-bucket --kms-key-id arn:aws:kms:...
```

For [customer-provided keys](https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerSideEncryptionCustomerKeys.html), use:

```sh
s3tk encrypt my-bucket --customer-key secret-key
```

Use the `--dry-run` flag to test

Specify certain objects the same way as [scan-object-acl](#scan-object-acl)

**Note:** Objects will lose any custom ACL

### Delete Unencrypted Versions

Delete all unencrypted versions of objects in a bucket

```sh
s3tk delete-unencrypted-versions my-bucket
```

For safety, this will not delete any current versions of objects

Use the `--dry-run` flag to test

Specify certain objects the same way as [scan-object-acl](#scan-object-acl)

### Scan DNS

Scan Route 53 for buckets to make sure you own them

```sh
s3tk scan-dns
```

Otherwise, you may be susceptible to [subdomain takeover](https://hackerone.com/reports/207576)

## Credentials

Credentials can be specified in `~/.aws/credentials` or with environment variables. See [this guide](https://boto3.readthedocs.io/en/latest/guide/configuration.html) for an explanation of environment variables.

You can specify a profile to use with:

```sh
AWS_PROFILE=your-profile s3tk
```

## IAM Policies

Here are the permissions needed for each command. Only include statements you need.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Scan",
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:GetBucketAcl",
                "s3:GetBucketPolicy",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetBucketLogging",
                "s3:GetBucketVersioning",
                "s3:GetEncryptionConfiguration"
            ],
            "Resource": "*"
        },
        {
            "Sid": "ScanObjectLevelLogging",
            "Effect": "Allow",
            "Action": [
                "cloudtrail:ListTrails",
                "cloudtrail:GetTrail",
                "cloudtrail:GetEventSelectors",
                "s3:GetBucketLocation"
            ],
            "Resource": "*"
        },
        {
            "Sid": "ScanDNS",
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "route53:ListHostedZones",
                "route53:ListResourceRecordSets"
            ],
            "Resource": "*"
        },
        {
            "Sid": "ListPolicy",
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:GetBucketPolicy"
            ],
            "Resource": "*"
        },
        {
            "Sid": "SetPolicy",
            "Effect": "Allow",
            "Action": [
                "s3:PutBucketPolicy"
            ],
            "Resource": "*"
        },
        {
            "Sid": "DeletePolicy",
            "Effect": "Allow",
            "Action": [
                "s3:DeleteBucketPolicy"
            ],
            "Resource": "*"
        },
        {
            "Sid": "BlockPublicAccess",
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:PutBucketPublicAccessBlock"
            ],
            "Resource": "*"
        },
        {
            "Sid": "EnableLogging",
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:PutBucketLogging"
            ],
            "Resource": "*"
        },
        {
            "Sid": "EnableVersioning",
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:PutBucketVersioning"
            ],
            "Resource": "*"
        },
        {
            "Sid": "EnableDefaultEncryption",
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:PutEncryptionConfiguration"
            ],
            "Resource": "*"
        },
        {
            "Sid": "ResetObjectAcl",
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:GetObjectAcl",
                "s3:PutObjectAcl"
            ],
            "Resource": [
                "arn:aws:s3:::my-bucket",
                "arn:aws:s3:::my-bucket/*"
            ]
        },
        {
            "Sid": "Encrypt",
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:GetObject",
                "s3:PutObject"
            ],
            "Resource": [
                "arn:aws:s3:::my-bucket",
                "arn:aws:s3:::my-bucket/*"
            ]
        },
        {
            "Sid": "DeleteUnencryptedVersions",
            "Effect": "Allow",
            "Action": [
                "s3:ListBucketVersions",
                "s3:GetObjectVersion",
                "s3:DeleteObjectVersion"
            ],
            "Resource": [
                "arn:aws:s3:::my-bucket",
                "arn:aws:s3:::my-bucket/*"
            ]
        }
    ]
}
```

## Access Logs

[Amazon Athena](https://aws.amazon.com/athena/) is great for querying S3 logs. [Create a table](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-s3-access-logs-to-identify-requests.html#querying-s3-access-logs-for-requests) and query away:

```sql
SELECT
    parse_datetime(requestdatetime, 'dd/MMM/yyyy:HH:mm:ss Z') AS time,
    key,
    remoteip,
    useragent
FROM
    s3_access_logs_db.mybucket_logs
WHERE
    requester = '-'
    AND httpstatus LIKE '2%'
    AND key LIKE 'some-keys%'
ORDER BY 1
```

## CloudTrail Logs

Amazon Athena is also great for querying CloudTrail logs. [Create a table](https://docs.aws.amazon.com/athena/latest/ug/create-cloudtrail-table.html) and query away:

```sql
SELECT
    eventtime,
    eventname,
    useridentity.username,
    requestparameters
FROM
    cloudtrail_logs
WHERE
    eventname LIKE '%Bucket%'
ORDER BY 1
```

## Best Practices

Keep things simple and follow the principle of least privilege to reduce the chance of mistakes.

- Strictly limit who can perform bucket-related operations
- Avoid mixing objects with different permissions in the same bucket (use a bucket policy to enforce this)
- Don’t specify public read permissions on a bucket level (no `GetObject` in bucket policy)
- Monitor configuration frequently for changes

## Bucket Policies

Only private uploads

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:PutObjectAcl",
            "Resource": "arn:aws:s3:::my-bucket/*"
        }
    ]
}
```

## Performance

For commands that iterate over bucket objects (`scan-object-acl`, `reset-object-acl`, `encrypt`, and `delete-unencrypted-versions`), run s3tk on an EC2 server for minimum latency.

## Notes

The `set-policy`, `block-public-access`, `enable-logging`, `enable-versioning`, and `enable-default-encryption` commands are provided for convenience. We recommend [Terraform](https://www.terraform.io/) for managing your buckets.

```tf
resource "aws_s3_bucket" "my_bucket" {
  bucket = "my-bucket"
  acl    = "private"

  logging {
    target_bucket = "my-s3-logs"
    target_prefix = "my-bucket/"
  }

  versioning {
    enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "my_bucket" {
  bucket = "${aws_s3_bucket.my_bucket.id}"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

## Upgrading

Run:

```sh
pip install s3tk --upgrade
```

To use master, run:

```sh
pip install git+https://github.com/ankane/s3tk.git --upgrade
```

## Docker

Run:

```sh
docker run -it ankane/s3tk aws configure
```

Commit your credentials:

```sh
docker commit $(docker ps -l -q) my-s3tk
```

And run:

```sh
docker run -it my-s3tk s3tk scan
```

## History

View the [changelog](https://github.com/ankane/s3tk/blob/master/CHANGELOG.md)

## Contributing

Everyone is encouraged to help improve this project. Here are a few ways you can help:

- [Report bugs](https://github.com/ankane/s3tk/issues)
- Fix bugs and [submit pull requests](https://github.com/ankane/s3tk/pulls)
- Write, clarify, or fix documentation
- Suggest or add new features

To get started with development:

```sh
git clone https://github.com/ankane/s3tk.git
cd s3tk
pip install --group dev
```
