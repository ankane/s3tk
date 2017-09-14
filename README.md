# s3tk

A security toolkit for Amazon S3

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

Skip logging or versioning

```sh
s3tk scan --skip-logging --skip-versioning
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

Use the `--dry-run` flag to test

A few notes about logging:

- buckets with logging already enabled are not updated at all
- the log bucket must in the same region as the source bucket - run this command multiple times for different regions
- the log prefix is set to `%(bucket-name)/`
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

### Encrypt

Encrypt all objects in a bucket with [server-side encryption](http://docs.aws.amazon.com/AmazonS3/latest/dev/serv-side-encryption.html)

```sh
s3tk encrypt my-bucket
```

Use [S3-managed keys](http://docs.aws.amazon.com/AmazonS3/latest/dev/UsingServerSideEncryption.html) by default. For [KMS-managed keys](http://docs.aws.amazon.com/AmazonS3/latest/dev/UsingKMSEncryption.html), use:

```sh
s3tk encrypt my-bucket --kms-key-id arn:aws:kms:...
```

For [customer-provided keys](http://docs.aws.amazon.com/AmazonS3/latest/dev/ServerSideEncryptionCustomerKeys.html), use: [master]

```sh
s3tk encrypt my-bucket --customer-key secret-key
```

Use the `--dry-run` flag to test

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

## Best Practices

Keep things simple and follow the principle of least privilege to reduce the chance of mistakes.

- Don’t allow ACL to be set on individual objects (no `s3:PutObjectAcl`). Use bucket policies instead.
- Keep bucket policies simple. Avoid mixing objects with different permissions in the same bucket.
- Strictly limit who can perform bucket-related operations

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
