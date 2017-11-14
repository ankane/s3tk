import json
import botocore


class Check:
    def __init__(self, bucket, **kwargs):
        self.bucket = bucket
        self.options = kwargs

    def perform(self):
        try:
            self.status = 'passed' if self._passed() else 'failed'
        except botocore.exceptions.ClientError:
            self.status = 'denied'

    def fix(self, options):
        self._fix(options)
        self.status = 'passed'


class AclCheck(Check):
    name = 'ACL'
    pass_message = 'not open to public'
    fail_message = 'open to public'
    bad_grantees = [
        'http://acs.amazonaws.com/groups/global/AllUsers',
        'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
    ]

    def _passed(self):
        for grant in self.bucket.Acl().grants:
            if grant['Grantee'].get('URI', None) in self.bad_grantees:
                return False
        return True


class PolicyCheck(Check):
    name = 'Policy'
    pass_message = 'not open to public'
    fail_message = 'open to public'

    def _passed(self):
        policy = None
        try:
            policy = self.bucket.Policy().policy
        except botocore.exceptions.ClientError as e:
            if 'NoSuchBucket' not in str(e):
                raise

        if policy is not None:
            policy = json.loads(policy)
            for s in policy['Statement']:
                if s['Effect'] == 'Allow' and (s['Principal'] == '*' or s['Principal'] == {'AWS': '*'}):
                    return False

        return True


class LoggingCheck(Check):
    name = 'Logging'
    pass_message = 'enabled'
    fail_message = 'disabled'

    def _passed(self):
        enabled = self.bucket.Logging().logging_enabled
        log_bucket = self.options.get('log_bucket', None)
        log_prefix = self.options.get('log_prefix', None)
        if log_prefix:
            log_prefix = log_prefix.replace("{bucket}", self.bucket.name)

        if not enabled:
            return False
        elif log_bucket and enabled['TargetBucket'] not in log_bucket:
            self.fail_message = 'to wrong bucket: ' + enabled['TargetBucket']
            return False
        elif log_prefix and enabled['TargetPrefix'] != log_prefix:
            self.fail_message = 'to wrong prefix: ' + enabled['TargetPrefix']
            return False

        self.pass_message = 'to ' + enabled['TargetBucket']
        if enabled['TargetPrefix']:
            self.pass_message = self.pass_message + '/' + enabled['TargetPrefix']

        return True

    def _fix(self, options):
        log_prefix = (options['log_prefix'] or '{bucket}/').replace("{bucket}", self.bucket.name)

        self.bucket.Logging().put(
            BucketLoggingStatus={
                'LoggingEnabled': {
                    'TargetBucket': options['log_bucket'],
                    'TargetGrants': [
                        {
                            'Grantee': {
                                'Type': 'Group',
                                'URI': 'http://acs.amazonaws.com/groups/s3/LogDelivery'
                            },
                            'Permission': 'WRITE'
                        },
                        {
                            'Grantee': {
                                'Type': 'Group',
                                'URI': 'http://acs.amazonaws.com/groups/s3/LogDelivery'
                            },
                            'Permission': 'READ_ACP'
                        },
                    ],
                    'TargetPrefix': log_prefix
                }
            }
        )


class VersioningCheck(Check):
    name = 'Versioning'
    pass_message = 'enabled'
    fail_message = 'disabled'

    def _passed(self):
        return self.bucket.Versioning().status == 'Enabled'

    def _fix(self, options):
        self.bucket.Versioning().enable()


class EncryptionCheck(Check):
    name = 'Default encryption'
    pass_message = 'enabled'
    fail_message = 'disabled'

    def _passed(self):
        response = None
        try:
            response = self.bucket.meta.client.get_bucket_encryption(
                Bucket=self.bucket.name
            )
        except botocore.exceptions.ClientError as e:
            if 'ServerSideEncryptionConfigurationNotFoundError' not in str(e):
                raise

        return response is not None

    def _fix(self, options):
        self.bucket.meta.client.put_bucket_encryption(
            Bucket=self.bucket.name,
            ServerSideEncryptionConfiguration={
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        }
                    }
                ]
            }
        )
