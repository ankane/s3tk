# s3tk

A security toolkit for Amazon S3

> Another day, another leaky Amazon S3 bucket
>
> &mdash; The Register, 12 Jul 2017

Don’t be the next [big](https://www.theregister.co.uk/2017/07/12/14m_verizon_customers_details_out/) [data](https://www.theregister.co.uk/2017/08/17/chicago_voter_leak/) [leak](https://www.theregister.co.uk/2017/09/05/twc_loses_4m_customer_records/) [this](https://www.theregister.co.uk/2017/07/18/dow_jones_index_of_customers_not_prices_leaks_from_aws_repo/) [year](https://www.theregister.co.uk/2017/08/22/open_aws_s3_bucket_leaked_hotel_booking_service_data_says_kromtech/)

![Screenshot](https://gist.githubusercontent.com/ankane/13a9230353c78c0d5c35fd9319a23d98/raw/82889dbc9482246bab8941e6adf8195cbc65e99c/console.gif)

:tangerine: Battle-tested at [Instacart](https://www.instacart.com/opensource)

## Installation

Run:

```sh
pip install s3tk
```

## Commands

### Scan

Scan your buckets for:

- ACL open to public
- policy open to public
- logging enabled
- versioning enabled

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

Skip logging or versioning

```sh
s3tk scan --skip-logging --skip-versioning
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

This makes all objects private so you only need to manage bucket permissions (best practice). See [bucket policies](#bucket-policies) for how to enforce going forward.

Use the `--dry-run` flag to test

Specify certain objects the same way as [scan-object-acl](#scan-object-acl)

### Encrypt

Encrypt all objects in a bucket with [server-side encryption](http://docs.aws.amazon.com/AmazonS3/latest/dev/serv-side-encryption.html)

```sh
s3tk encrypt my-bucket
```

Use [S3-managed keys](http://docs.aws.amazon.com/AmazonS3/latest/dev/UsingServerSideEncryption.html) by default. For [KMS-managed keys](http://docs.aws.amazon.com/AmazonS3/latest/dev/UsingKMSEncryption.html), use:

```sh
s3tk encrypt my-bucket --kms-key-id arn:aws:kms:...
```

For [customer-provided keys](http://docs.aws.amazon.com/AmazonS3/latest/dev/ServerSideEncryptionCustomerKeys.html), use:

```sh
s3tk encrypt my-bucket --customer-key secret-key
```

Use the `--dry-run` flag to test

Specify certain objects the same way as [scan-object-acl](#scan-object-acl)

A few notes about encryption:

- objects will lose any custom ACL
- we recommend setting a bucket policy to deny unencrypted uploads - see links above for instructions (currently not possible for customer-provided keys)

## Credentials

Credentials can be specified in `~/.aws/credentials` or with environment variables.

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
                "s3:GetBucketLogging",
                "s3:GetBucketVersioning"
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
            "Sid": "ResetObjectAcl",
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
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
        }
    ]
}
```

## Access Logs

To query S3 access logs, we recommend [Amazon Athena](https://aws.amazon.com/athena/).

Thankfully, [this post](http://aws.mannem.me/?p=1462) makes this easy. Create a table with:

```sql
CREATE EXTERNAL TABLE my_bucket (
    bucket_owner string,
    bucket string,
    timestamp string,
    remote_ip string,
    requester string,
    request_id string,
    operation string,
    key string,
    request_verb string,
    request_url string,
    request_proto string,
    status_code string,
    error_code string,
    bytes_sent string,
    object_size string,
    total_time string,
    turn_around_time string,
    referrer string,
    user_agent string,
    version_id string
)
ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.RegexSerDe'
WITH SERDEPROPERTIES (
    'serialization.format' = '1',
    'input.regex' = '([^ ]*) ([^ ]*) \\[(.*?)\\] ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) \\\"([^ ]*) ([^ ]*) (- |[^ ]*)\\\" (-|[0-9]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) (\"[^\"]*\\") ([^ ]*)$'
) LOCATION 's3://my-s3-logs/my-bucket/';
```

Change the last line to point to your log bucket and prefix, and query away

```sql
SELECT
    date_parse(timestamp, '%d/%b/%Y:%H:%i:%S +0000') AS timestamp,
    request_url,
    remote_ip,
    user_agent
FROM
    my_bucket
WHERE
    requester = '-'
    AND status_code LIKE '2%'
    AND bucket = 'my-bucket'
    AND request_url LIKE '/some-keys%'
ORDER BY 1
```

## Best Practices

Keep things simple and follow the principle of least privilege to reduce the chance of mistakes.

- Strictly limit who can perform bucket-related operations
- Don’t allow ACL to be set on individual objects (no `s3:PutObjectAcl`)
- Avoid mixing objects with different permissions in the same bucket
- Monitor configuration frequently for changes

## Bucket Policies

Prevent ACL on individual objects

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyObjectAcl",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:PutObjectAcl",
            "Resource": "arn:aws:s3:::my-bucket/*"
        }
    ]
}
```

## Notes

The `enable-logging` and `enable-versioning` commands are provided for convenience. We recommend [Terraform](https://www.terraform.io/) for managing your buckets.

```tf
resource "aws_s3_bucket" "b" {
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
```

## Upgrading

Run:

```sh
pip install s3tk --upgrade
```

To use master, run:

```sh
pip install git+git://github.com/ankane/s3tk.git --upgrade
```

## History

View the [changelog](https://github.com/ankane/s3tk/blob/master/CHANGELOG.md)

## Contributing

Everyone is encouraged to help improve this project. Here are a few ways you can help:

- [Report bugs](https://github.com/ankane/s3tk/issues)
- Fix bugs and [submit pull requests](https://github.com/ankane/s3tk/pulls)
- Write, clarify, or fix documentation
- Suggest or add new features
