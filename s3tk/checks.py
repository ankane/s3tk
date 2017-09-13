import botocore


class Check:
    def __init__(self, bucket):
        self.bucket = bucket

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

    def _passed(self):
        for grant in self.bucket.Acl().grants:
            if 'AllUsers' in str(grant['Grantee']) or 'AuthenticatedUsers' in str(grant['Grantee']):
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
                if s['Effect'] == 'Allow' and s['Principal'] == '*':
                    return False

        return True


class LoggingCheck(Check):
    name = 'Logging'
    pass_message = 'enabled'
    fail_message = 'disabled'

    def _passed(self):
        return self.bucket.Logging().logging_enabled

    def _fix(self, options):
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
                    'TargetPrefix': self.bucket.name + '/'
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
