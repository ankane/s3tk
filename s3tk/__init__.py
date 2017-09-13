import sys
import os.path
import boto3
import botocore
import click
from clint.textui import colored, puts, indent
from .checks import AclCheck, PolicyCheck, LoggingCheck, VersioningCheck

__version__ = '0.1.1'

s3 = boto3.resource('s3')


def notice(message):
    puts(colored.yellow(message))


def abort(message):
    puts(colored.red(message))
    sys.exit(1)


def perform(check):
    check.perform()

    with indent(2):
        if check.status == 'passed':
            puts(colored.green(check.name + ' ' + check.pass_message))
        elif check.status == 'failed':
            puts(colored.red(check.name + ' ' + check.fail_message))
        else:
            puts(colored.red(check.name + ' access denied'))

    return check


def fetch_buckets(buckets):
    return [s3.Bucket(bn) for bn in buckets] if buckets else s3.buckets.all()


def fix_check(klass, buckets, dry_run, fix_args={}):
    buckets = fetch_buckets(buckets)

    try:
        for bucket in buckets:
            check = klass(bucket)
            check.perform()

            if check.status == 'passed':
                message = colored.green('already enabled')
            elif check.status == 'denied':
                message = colored.red('access denied')
            else:
                if dry_run:
                    message = colored.yellow('to be enabled')
                else:
                    try:
                        check.fix(fix_args)
                        message = colored.blue('just enabled')
                    except botocore.exceptions.ClientError as e:
                        message = colored.red(str(e))

            puts(bucket.name + ' ' + message)

    # can't list buckets
    except (botocore.exceptions.ClientError, botocore.exceptions.NoCredentialsError) as e:
        abort(str(e))


@click.group()
def cli():
    pass


@cli.command()
@click.argument('buckets', nargs=-1)
@click.option('--skip-logging', is_flag=True, help='Skip logging check')
@click.option('--skip-versioning', is_flag=True, help='Skip versioning check')
def scan(buckets, skip_logging=False, skip_versioning=False):
    buckets = fetch_buckets(buckets)

    checks = []

    try:
        for bucket in buckets:
            puts(bucket.name)

            checks.append(perform(AclCheck(bucket)))

            checks.append(perform(PolicyCheck(bucket)))

            if not skip_logging:
                checks.append(perform(LoggingCheck(bucket)))

            if not skip_versioning:
                checks.append(perform(VersioningCheck(bucket)))

            puts()

        if sum(1 for c in checks if c.status != 'passed') > 0:
            sys.exit(1)

    # can't list buckets
    except (botocore.exceptions.ClientError, botocore.exceptions.NoCredentialsError) as e:
        abort(str(e))


@cli.command(name='enable-logging')
@click.argument('buckets', nargs=-1)
@click.option('--dry-run', is_flag=True, help='Dry run')
@click.option('--log-bucket', required=True, help='Bucket to store logs')
def enable_logging(buckets, log_bucket=None, dry_run=False):
    fix_check(LoggingCheck, buckets, dry_run, {'log_bucket': log_bucket})


@cli.command(name='enable-versioning')
@click.argument('buckets', nargs=-1)
@click.option('--dry-run', is_flag=True, help='Dry run')
def enable_versioning(buckets, dry_run=False):
    fix_check(VersioningCheck, buckets, dry_run)


@cli.command()
@click.argument('bucket')
@click.option('--dry-run', is_flag=True, help='Dry run')
@click.option('--kms-key-id', help='KMS key ARN')
def encrypt(bucket, dry_run=False, kms_key_id=None):
    bucket = s3.Bucket(bucket)

    encryption = 'aws:kms' if kms_key_id else 'AES256'

    for obj_summary in bucket.objects.all():
        obj = obj_summary.Object()
        if obj.server_side_encryption == encryption:
            puts(obj.key + ' ' + colored.green('already encrypted'))
        else:
            if dry_run:
                puts(obj.key + ' ' + colored.yellow('to be encrypted'))
            else:
                copy_source = {'Bucket': bucket.name, 'Key': obj.key}
                if kms_key_id:
                    obj.copy_from(CopySource=copy_source, ServerSideEncryption=encryption, SSEKMSKeyId=kms_key_id)
                else:
                    obj.copy_from(CopySource=copy_source, ServerSideEncryption=encryption)
                puts(obj.key + ' ' + colored.blue('just encrypted'))
