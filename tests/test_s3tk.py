from s3tk import object_matches


def test_object_only_patterns_respect_case_sensitive_s3_keys():
    assert not object_matches('Reports/Annual.CSV', 'reports/*.csv', None)


def test_object_except_patterns_respect_case_sensitive_s3_keys():
    assert object_matches('Reports/Annual.CSV', None, 'reports/*.csv')
