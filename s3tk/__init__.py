import sys
import os.path
import json
import fnmatch
from collections import Counter, OrderedDict
import boto3
import botocore
import click
from joblib import Parallel, delayed
from clint.textui import colored, puts, indent
from .checks import AclCheck, PolicyCheck, LoggingCheck, VersioningCheck, EncryptionCheck

__version__ = '0.2.1'

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

cached_s3 = None

def s3():
    # memoize
    global cached_s3
    if cached_s3 is None:
        cached_s3 = boto3.resource('s3')
    return cached_s3


def notice(message):
    puts(colored.yellow(message))


def abort(message):
    puts(colored.red(message))
    sys.exit(1)


def unicode_key(key):
    if sys.version_info[0] < 3 and isinstance(key, unicode):
        return key.encode('utf-8')
    else:
        return key


def perform(check):
    check.perform()

    with indent(2):
        if check.status == 'passed':
            puts(colored.green('✔ ' + check.name + ' ' + check.pass_message))
        elif check.status == 'failed':
            puts(colored.red('✘ ' + check.name + ' ' + check.fail_message))
        else:
            puts(colored.red('✘ ' + check.name + ' access denied'))

    return check


def fetch_buckets(buckets):
    if buckets:
        if any('*' in b for b in buckets):
            return [b for b in s3().buckets.all() if any(fnmatch.fnmatch(b.name, bn) for bn in buckets)]
        else:
            return [s3().Bucket(bn) for bn in buckets]
    else:
        return s3().buckets.all()


def fix_check(klass, buckets, dry_run, fix_args={}):
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


def encrypt_object(bucket_name, key, dry_run, kms_key_id, customer_key):
    obj = s3().Object(bucket_name, key)
    str_key = unicode_key(key)

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
            puts(str_key + ' ' + colored.green('already encrypted'))
            return 'already encrypted'
        else:
            if dry_run:
                puts(str_key + ' ' + colored.yellow('to be encrypted'))
                return 'to be encrypted'
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

                puts(str_key + ' ' + colored.blue('just encrypted'))
                return 'just encrypted'

    except (botocore.exceptions.ClientError, botocore.exceptions.NoCredentialsError) as e:
        puts(str_key + ' ' + colored.red(str(e)))
        return 'error'


def determine_mode(acl):
    owner = acl.owner
    grants = acl.grants
    non_owner_grants = [grant for grant in grants if not (grant['Grantee'].get('ID') == owner['ID'] and grant['Permission'] == 'FULL_CONTROL')]

    # TODO bucket-owner-read and bucket-owner-full-control
    return next((ca['acl'] for ca in canned_acls if ca['grants'] == non_owner_grants), 'custom')


def scan_object(bucket_name, key):
    obj = s3().Object(bucket_name, key)
    str_key = unicode_key(key)

    try:
        mode = determine_mode(obj.Acl())

        if mode == 'private':
            puts(str_key + ' ' + colored.green(mode))
        else:
            puts(str_key + ' ' + colored.yellow(mode))

        return mode
    except (botocore.exceptions.ClientError, botocore.exceptions.NoCredentialsError) as e:
        puts(str_key + ' ' + colored.red(str(e)))
        return 'error'


def reset_object(bucket_name, key, dry_run, acl):
    obj = s3().Object(bucket_name, key)
    str_key = unicode_key(key)

    try:
        obj_acl = obj.Acl()
        mode = determine_mode(obj_acl)

        if mode == acl:
            puts(str_key + ' ' + colored.green('ACL already ' + acl))
            return 'ACL already ' + acl
        elif dry_run:
            puts(str_key + ' ' + colored.yellow('ACL to be updated to ' + acl))
            return 'ACL to be updated to ' + acl
        else:
            obj_acl.put(ACL=acl)
            puts(str_key + ' ' + colored.blue('ACL updated to ' + acl))
            return 'ACL updated to ' + acl

    except (botocore.exceptions.ClientError, botocore.exceptions.NoCredentialsError) as e:
        puts(str_key + ' ' + colored.red(str(e)))
        return 'error'


def delete_unencrypted_version(bucket_name, key, id, dry_run):
    object_version = s3().ObjectVersion(bucket_name, key, id)

    try:
        obj = object_version.get()
        if obj.get('ServerSideEncryption') or obj.get('SSECustomerAlgorithm'):
            puts(key + ' ' + id + ' ' + colored.green('encrypted'))
            return 'encrypted'
        else:
            if dry_run:
                puts(key + ' ' + id + ' ' + colored.blue('to be deleted'))
                return 'to be deleted'
            else:
                puts(key + ' ' + id + ' ' + colored.blue('deleted'))
                object_version.delete()
                return 'deleted'
    except (botocore.exceptions.ClientError, botocore.exceptions.NoCredentialsError) as e:
        puts(key + ' ' + id + ' ' + colored.red(str(e)))
        return 'error'


def object_matches(key, only, _except):
    match = True

    if only:
        match = fnmatch.fnmatch(key, only)

    if _except and match:
        match = not fnmatch.fnmatch(key, _except)

    return match


def parallelize(bucket, only, _except, fn, args=(), versions=False):
    bucket = s3().Bucket(bucket)

    # use prefix for performance
    prefix = None
    if only:
        # get the first prefix before wildcard
        prefix = '/'.join(only.split('*')[0].split('/')[:-1])
        if prefix:
            prefix = prefix + '/'

    if versions:
        object_versions = bucket.object_versions.filter(Prefix=prefix) if prefix else bucket.object_versions.all()
        # delete markers have no size
        return Parallel(n_jobs=24)(delayed(fn)(bucket.name, ov.object_key, ov.id, *args) for ov in object_versions if object_matches(ov.object_key, only, _except) and not ov.is_latest and ov.size is not None)
    else:
        objects = bucket.objects.filter(Prefix=prefix) if prefix else bucket.objects.all()

        if only and not '*' in only:
            objects = [s3().Object(bucket, only)]

        return Parallel(n_jobs=24)(delayed(fn)(bucket.name, os.key, *args) for os in objects if object_matches(os.key, only, _except))


def public_statement(bucket):
    return OrderedDict([
        ('Sid', 'Public'),
        ('Effect', 'Allow'),
        ('Principal', '*'),
        ('Action', 's3:GetObject'),
        ('Resource', 'arn:aws:s3:::%s/*' % bucket.name)
    ])


def no_object_acl_statement(bucket):
    return OrderedDict([
        ('Sid', 'NoObjectAcl'),
        ('Effect', 'Deny'),
        ('Principal', '*'),
        ('Action', 's3:PutObjectAcl'),
        ('Resource', 'arn:aws:s3:::%s/*' % bucket.name)
    ])


def public_uploads_statement(bucket):
    return OrderedDict([
        ('Sid', 'PublicUploads'),
        ('Effect', 'Deny'),
        ('Principal', '*'),
        ('Action', ['s3:PutObject', 's3:PutObjectAcl']),
        ('Resource', 'arn:aws:s3:::%s/*' % bucket.name),
        ('Condition', {'StringNotEquals': {'s3:x-amz-acl': 'public-read'}})
    ])


def no_uploads_statement(bucket):
    return OrderedDict([
        ('Sid', 'NoUploads'),
        ('Effect', 'Deny'),
        ('Principal', '*'),
        ('Action', 's3:PutObject'),
        ('Resource', 'arn:aws:s3:::%s/*' % bucket.name)
    ])


def encryption_statement(bucket):
    return OrderedDict([
        ('Sid', 'Encryption'),
        ('Effect', 'Deny'),
        ('Principal', '*'),
        ('Action', 's3:PutObject'),
        ('Resource', 'arn:aws:s3:::%s/*' % bucket.name),
        ('Condition', {'StringNotEquals': {'s3:x-amz-server-side-encryption': 'AES256'}})
    ])


def statement_matches(s1, s2):
    s1 = dict(s1)
    s2 = dict(s2)
    s1.pop('Sid', None)
    s2.pop('Sid', None)
    return s1 == s2


def fetch_policy(bucket):
    policy = None
    try:
        policy = bucket.Policy().policy
    except botocore.exceptions.ClientError as e:
        if 'NoSuchBucket' not in str(e):
            raise

    if policy:
        policy = json.loads(policy, object_pairs_hook=OrderedDict)

    return policy


def print_dns_bucket(name, buckets, found_buckets):
    if not name in found_buckets:
        puts(name)
        with indent(2):
            if name in buckets:
                puts(colored.green('owned'))
            else:
                puts(colored.red('not owned'))

            puts()

        found_buckets.add(name)


def print_policy(policy):
    with indent(2):
        if any(policy['Statement']):
            puts(colored.yellow(json.dumps(policy, indent=4)))
        else:
            puts(colored.yellow("None"))


def summarize(values):
    summary = Counter(values)

    puts()
    puts("Summary")
    for k, v in summary.most_common():
        puts(k + ': ' + str(v))


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
@click.option('--skip-default-encryption', is_flag=True, help='Skip default encryption check')
@click.option('--default-encryption', is_flag=True) # no op, can't hide from help until click 7 released
@click.option('--sns-topic', help='Send SNS notification for failures')
def scan(buckets, log_bucket=None, log_prefix=None, skip_logging=False, skip_versioning=False, skip_default_encryption=False, default_encryption=True, sns_topic=None):
    checks = []
    for bucket in fetch_buckets(buckets):
        puts(bucket.name)

        checks.append(perform(AclCheck(bucket)))

        checks.append(perform(PolicyCheck(bucket)))

        if not skip_logging:
            checks.append(perform(LoggingCheck(bucket, log_bucket=log_bucket, log_prefix=log_prefix)))

        if not skip_versioning:
            checks.append(perform(VersioningCheck(bucket)))

        if not skip_default_encryption:
            checks.append(perform(EncryptionCheck(bucket)))

        puts()

    failed_checks = [c for c in checks if c.status != 'passed']
    if any(failed_checks):
        if sns_topic:
            topic = boto3.resource('sns').Topic(sns_topic)
            message = ''
            for check in failed_checks:
                msg = check.fail_message if check.status == 'failed' else 'access denied'
                message += check.bucket.name + ': ' + check.name + ' ' + msg + '\n'
            topic.publish(Message=message, Subject='[s3tk] Scan Failures')
        sys.exit(1)


@cli.command(name='scan-dns')
def scan_dns():
    buckets = set([b.name for b in s3().buckets.all()])
    found_buckets = set()

    client = boto3.client('route53')
    paginator = client.get_paginator('list_hosted_zones')

    for page in paginator.paginate():
        for hosted_zone in page['HostedZones']:
            paginator2 = client.get_paginator('list_resource_record_sets')
            for page2 in paginator2.paginate(HostedZoneId=hosted_zone['Id']):
                for resource_set in page2['ResourceRecordSets']:
                    if resource_set.get('AliasTarget'):
                        value = resource_set['AliasTarget']['DNSName']
                        if value.startswith('s3-website-') and value.endswith('.amazonaws.com.'):
                            print_dns_bucket(resource_set['Name'][:-1], buckets, found_buckets)
                    elif resource_set.get('ResourceRecords'):
                        for record in resource_set['ResourceRecords']:
                            value = record['Value']
                            if value.endswith('.s3.amazonaws.com'):
                                print_dns_bucket('.'.join(value.split('.')[:-3]), buckets, found_buckets)
                            if 's3-website-' in value and value.endswith('.amazonaws.com'):
                                print_dns_bucket(resource_set['Name'][:-1], buckets, found_buckets)


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


@cli.command(name='enable-default-encryption')
@click.argument('buckets', nargs=-1)
@click.option('--dry-run', is_flag=True, help='Dry run')
def enable_versioning(buckets, dry_run=False):
    fix_check(EncryptionCheck, buckets, dry_run)


@cli.command()
@click.argument('bucket')
@click.option('--only', help='Only certain objects')
@click.option('--except', '_except', help='Except certain objects')
@click.option('--dry-run', is_flag=True, help='Dry run')
@click.option('--kms-key-id', help='KMS key id')
@click.option('--customer-key', help='Customer key')
def encrypt(bucket, only=None, _except=None, dry_run=False, kms_key_id=None, customer_key=None):
    summarize(parallelize(bucket, only, _except, encrypt_object, (dry_run, kms_key_id, customer_key,)))


@cli.command(name='scan-object-acl')
@click.argument('bucket')
@click.option('--only', help='Only certain objects')
@click.option('--except', '_except', help='Except certain objects')
def scan_object_acl(bucket, only=None, _except=None):
    summarize(parallelize(bucket, only, _except, scan_object))


@cli.command(name='reset-object-acl')
@click.argument('bucket')
@click.option('--only', help='Only certain objects')
@click.option('--except', '_except', help='Except certain objects')
@click.option('--acl', default='private', help='ACL to use')
@click.option('--dry-run', is_flag=True, help='Dry run')
def reset_object_acl(bucket, only=None, _except=None, acl=None, dry_run=False):
    summarize(parallelize(bucket, only, _except, reset_object, (dry_run, acl,)))


@cli.command(name='delete-unencrypted-versions')
@click.argument('bucket')
@click.option('--only', help='Only certain objects')
@click.option('--except', '_except', help='Except certain objects')
@click.option('--dry-run', is_flag=True, help='Dry run')
def delete_unencrypted_versions(bucket, only=None, _except=None, dry_run=False):
    summarize(parallelize(bucket, only, _except, delete_unencrypted_version, (dry_run,), True))


@cli.command(name='list-policy')
@click.argument('buckets', nargs=-1)
@click.option('--named', is_flag=True, help='Print named statements')
def list_policy(buckets, named=False):
    for bucket in fetch_buckets(buckets):
        puts(bucket.name)

        policy = fetch_policy(bucket)

        with indent(2):
            if policy is None:
                puts(colored.yellow('None'))
            else:
                if named:
                    public = public_statement(bucket)
                    no_object_acl = no_object_acl_statement(bucket)
                    public_uploads = public_uploads_statement(bucket)
                    no_uploads = no_uploads_statement(bucket)
                    encryption = encryption_statement(bucket)

                    for statement in policy['Statement']:
                        if statement_matches(statement, public):
                            named_statement = 'Public'
                        elif statement_matches(statement, no_object_acl):
                            named_statement = 'No object ACL'
                        elif statement_matches(statement, public_uploads):
                            named_statement = 'Public uploads'
                        elif statement_matches(statement, no_uploads):
                            named_statement = 'No uploads'
                        elif statement_matches(statement, encryption):
                            named_statement = 'Encryption'
                        else:
                            named_statement = 'Custom'

                        puts(colored.yellow(named_statement))

                else:
                    puts(colored.yellow(json.dumps(policy, indent=4)))

        puts()


@cli.command(name='set-policy')
@click.argument('bucket')
@click.option('--public', is_flag=True, help='Make all objects public')
@click.option('--no-object-acl', is_flag=True, help='Prevent object ACL')
@click.option('--public-uploads', is_flag=True, help='Only public uploads')
@click.option('--no-uploads', is_flag=True, help='Prevent new uploads')
@click.option('--encryption', is_flag=True, help='Require encryption')
@click.option('--dry-run', is_flag=True, help='Dry run')
def set_policy(bucket, public=False, no_object_acl=False, public_uploads=False, no_uploads=False, encryption=False, dry_run=False):
    bucket = s3().Bucket(bucket)
    bucket_policy = bucket.Policy()

    statements = []

    if public:
        statements.append(public_statement(bucket))

    if no_object_acl:
        statements.append(no_object_acl_statement(bucket))

    if public_uploads:
        statements.append(public_uploads_statement(bucket))

    if no_uploads:
        statements.append(no_uploads_statement(bucket))

    if encryption:
        statements.append(encryption_statement(bucket))

    if any(statements):
        puts('New policy')
        policy = OrderedDict([
            ('Version', '2012-10-17'),
            ('Statement', statements)
        ])
        print_policy(policy)

        if not dry_run:
            bucket_policy.put(Policy=json.dumps(policy))
    else:
        abort('No policies specified')


# experimental
@cli.command(name='update-policy')
@click.argument('bucket')
@click.option('--encryption/--no-encryption', default=None, help='Require encryption')
@click.option('--dry-run', is_flag=True, help='Dry run')
def update_policy(bucket, encryption=None, dry_run=False):
    bucket = s3().Bucket(bucket)

    policy = fetch_policy(bucket)
    if not policy:
        policy = OrderedDict([
            ('Version', '2012-10-17'),
            ('Statement', [])
        ])

    es = encryption_statement(bucket)
    es_index = next((i for i, s in enumerate(policy['Statement']) if statement_matches(s, es)), -1)

    if es_index != -1:
        if encryption:
            puts("No encryption change")
            print_policy(policy)
        elif encryption is False:
            puts("Removing encryption")
            policy['Statement'].pop(es_index)
            print_policy(policy)

            if not dry_run:
                if any(policy['Statement']):
                    bucket.Policy().put(Policy=json.dumps(policy))
                else:
                    bucket.Policy().delete()
    else:
        if encryption:
            puts("Adding encryption")
            policy['Statement'].append(es)
            print_policy(policy)

            if not dry_run:
                bucket.Policy().put(Policy=json.dumps(policy))
        elif encryption is False:
            puts(colored.yellow("No encryption change"))
            print_policy(policy)


@cli.command(name='delete-policy')
@click.argument('bucket')
def delete_policy(bucket):
    s3().Bucket(bucket).Policy().delete()
    puts('Policy deleted')
