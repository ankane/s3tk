import sys
import os.path
import json
import fnmatch
import boto3
import botocore
import click
from joblib import Parallel, delayed
from clint.textui import colored, puts, indent
from .checks import AclCheck, PolicyCheck, LoggingCheck, VersioningCheck

__version__ = '0.1.4'

s3 = boto3.resource('s3')

canned_acls = [
    {
        'acl': 'private',
        'grants': []
    },
    {
        'acl': 'public-read',
        'grants': [
            {'Grantee': {'Type': 'Group', 'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}, 'Permission': 'READ'}
        ]
    },
    {
        'acl': 'public-read-write',
        'grants': [
            {'Grantee': {'Type': 'Group', 'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}, 'Permission': 'READ'},
            {'Grantee': {u'Type': 'Group', u'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}, 'Permission': 'WRITE'}
        ]
    },
    {
        'acl': 'authenticated-read',
        'grants': [
            {'Grantee': {'Type': 'Group', 'URI': 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'}, 'Permission': 'READ'}
        ]
    },
    {
        'acl': 'aws-exec-read',
        'grants': [
            {'Grantee': {'Type': 'CanonicalUser', 'DisplayName': 'za-team', 'ID': '6aa5a366c34c1cbe25dc49211496e913e0351eb0e8c37aa3477e40942ec6b97c'}, 'Permission': 'READ'}
        ]
    }
]

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
    if buckets:
        if any('*' in b for b in buckets):
            return [b for b in s3.buckets.all() if any(fnmatch.fnmatch(b.name, bn) for bn in buckets)]
        else:
            return [s3.Bucket(bn) for bn in buckets]
    else:
        return s3.buckets.all()


def fix_check(klass, buckets, dry_run, fix_args={}):
    try:
        for bucket in fetch_buckets(buckets):
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


def encrypt_object(bucket_name, key, dry_run, kms_key_id, customer_key):
    obj = s3.Object(bucket_name, key)

    try:
        if customer_key:
            obj.load(SSECustomerAlgorithm='AES256', SSECustomerKey=customer_key)

        encrypted = None
        if customer_key:
            encrypted = obj.sse_customer_algorithm is not None
        elif kms_key_id:
            encrypted = obj.server_side_encryption == 'aws:kms'
        else:
            encrypted = obj.server_side_encryption == 'AES256'

        if encrypted:
            puts(obj.key + ' ' + colored.green('already encrypted'))
        else:
            if dry_run:
                puts(obj.key + ' ' + colored.yellow('to be encrypted'))
            else:
                copy_source = {'Bucket': bucket_name, 'Key': obj.key}

                # TODO support going from customer encryption to other forms
                if kms_key_id:
                    obj.copy_from(
                        CopySource=copy_source,
                        ServerSideEncryption='aws:kms',
                        SSEKMSKeyId=kms_key_id
                    )
                elif customer_key:
                    obj.copy_from(
                        CopySource=copy_source,
                        SSECustomerAlgorithm='AES256',
                        SSECustomerKey=customer_key
                    )
                else:
                    obj.copy_from(
                        CopySource=copy_source,
                        ServerSideEncryption='AES256'
                    )

                puts(obj.key + ' ' + colored.blue('just encrypted'))

    except (botocore.exceptions.ClientError, botocore.exceptions.NoCredentialsError) as e:
        puts(obj.key + ' ' + colored.red(str(e)))


def scan_object(bucket_name, key):
    obj = s3.Object(bucket_name, key)

    try:
        acl = obj.Acl()
        owner = acl.owner
        grants = acl.grants
        non_owner_grants = [grant for grant in grants if not (grant['Grantee'].get('ID') == owner['ID'] and grant['Permission'] == 'FULL_CONTROL')]

        # TODO bucket-owner-read and bucket-owner-full-control
        mode = next((ca['acl'] for ca in canned_acls if ca['grants'] == non_owner_grants), 'custom')

        if mode == 'private':
            puts(obj.key + ' ' + colored.green(mode))
        else:
            puts(obj.key + ' ' + colored.yellow(mode))

    except (botocore.exceptions.ClientError, botocore.exceptions.NoCredentialsError) as e:
        puts(obj.key + ' ' + colored.red(str(e)))


def reset_object(bucket_name, key, dry_run):
    obj = s3.Object(bucket_name, key)

    try:
        if dry_run:
            puts(obj.key + ' ' + colored.yellow('ACL to be reset'))
        else:
            obj.Acl().put(ACL='private')
            puts(obj.key + ' ' + colored.blue('ACL reset'))

    except (botocore.exceptions.ClientError, botocore.exceptions.NoCredentialsError) as e:
        puts(obj.key + ' ' + colored.red(str(e)))


def object_matches(key, only, _except):
    match = True

    if only:
        match = fnmatch.fnmatch(key, only)

    if _except and match:
        match = not fnmatch.fnmatch(key, _except)

    return match


def parallelize(bucket, only, _except, fn, args=()):
    try:
        bucket = s3.Bucket(bucket)

        # use prefix for performance
        prefix = None
        if only:
            # get the first prefix before wildcard
            prefix = '/'.join(only.split('*')[0].split('/')[:-1])
            if prefix:
                prefix = prefix + '/'

        objects = bucket.objects.filter(Prefix=prefix) if prefix else bucket.objects.all()

        Parallel(n_jobs=10, backend='threading')(delayed(fn)(bucket.name, os.key, *args) for os in objects if object_matches(os.key, only, _except))
    except (botocore.exceptions.ClientError, botocore.exceptions.NoCredentialsError) as e:
        abort(str(e))


@click.group()
@click.version_option(version=__version__)
def cli():
    pass


@cli.command()
@click.argument('buckets', nargs=-1)
@click.option('--log-bucket', multiple=True, help='Check log bucket(s)')
@click.option('--log-prefix', help='Check log prefix')
@click.option('--skip-logging', is_flag=True, help='Skip logging check')
@click.option('--skip-versioning', is_flag=True, help='Skip versioning check')
def scan(buckets, log_bucket=None, log_prefix=None, skip_logging=False, skip_versioning=False):
    checks = []

    try:
        for bucket in fetch_buckets(buckets):
            puts(bucket.name)

            checks.append(perform(AclCheck(bucket)))

            checks.append(perform(PolicyCheck(bucket)))

            if not skip_logging:
                checks.append(perform(LoggingCheck(bucket, log_bucket=log_bucket, log_prefix=log_prefix)))

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
@click.option('--log-prefix', help='Log prefix')
def enable_logging(buckets, log_bucket=None, log_prefix=None, dry_run=False):
    fix_check(LoggingCheck, buckets, dry_run, {'log_bucket': log_bucket, 'log_prefix': log_prefix})


@cli.command(name='enable-versioning')
@click.argument('buckets', nargs=-1)
@click.option('--dry-run', is_flag=True, help='Dry run')
def enable_versioning(buckets, dry_run=False):
    fix_check(VersioningCheck, buckets, dry_run)


@cli.command()
@click.argument('bucket')
@click.option('--only', help='Only certain objects')
@click.option('--except', '_except', help='Except certain objects')
@click.option('--dry-run', is_flag=True, help='Dry run')
@click.option('--kms-key-id', help='KMS key id')
@click.option('--customer-key', help='Customer key')
def encrypt(bucket, only=None, _except=None, dry_run=False, kms_key_id=None, customer_key=None):
    parallelize(bucket, only, _except, encrypt_object, (dry_run, kms_key_id, customer_key))


@cli.command(name='scan-object-acl')
@click.argument('bucket')
@click.option('--only', help='Only certain objects')
@click.option('--except', '_except', help='Except certain objects')
def scan_object_acl(bucket, only=None, _except=None):
    parallelize(bucket, only, _except, scan_object)


@cli.command(name='reset-object-acl')
@click.argument('bucket')
@click.option('--only', help='Only certain objects')
@click.option('--except', '_except', help='Except certain objects')
@click.option('--dry-run', is_flag=True, help='Dry run')
def reset_object_acl(bucket, only=None, _except=None, dry_run=False):
    parallelize(bucket, only, _except, reset_object, (dry_run,))


@cli.command(name='list-policy')
@click.argument('buckets', nargs=-1)
def list_policy(buckets):
    try:
        for bucket in fetch_buckets(buckets):
            puts(bucket.name)

            policy = None
            try:
                policy = bucket.Policy().policy
            except botocore.exceptions.ClientError as e:
                if 'NoSuchBucket' not in str(e):
                    raise

            with indent(2):
                if policy is None:
                    puts(colored.yellow('None'))
                else:
                    puts(colored.yellow(json.dumps(json.loads(policy), indent=4)))

            puts()

    except (botocore.exceptions.ClientError, botocore.exceptions.NoCredentialsError) as e:
        abort(str(e))
