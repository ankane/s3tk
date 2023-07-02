## 0.4.0 (unreleased)

- Fixed warning with clint
- Dropped support for Python < 3.8

## 0.3.1 (2020-08-17)

- Added experimental `--object-level-logging` option to `scan` command

## 0.3.0 (2020-01-05)

- Added check for public access allowed
- Added `block-public-access` command

## 0.2.1 (2018-10-16)

- Fixed error with joblib 0.12

## 0.2.0 (2018-04-15)

- Scan default encryption by default
- More greppable output
- Performance optimization for single objects

## 0.1.8 (2018-02-16)

- Added `delete-unencrypted-versions` command
- Added `--acl` option to `reset-object-acl` command
- Added check for existing object ACL before reset
- Fixed issue with unicode keys in Python 2

## 0.1.7 (2017-11-13)

- Added `enable-default-encryption` command
- Added `--dry-run` and `public-uploads` options to `set-policy` command
- Added summary to `scan-object-acl` and `encrypt` commands
- Added `--default-encryption` and `--sns-topic` to `scan` command

## 0.1.6 (2017-10-01)

- Added `scan-dns` command
- Added `set-policy` command
- Added `delete-policy` command
- Added `--named` option to `list-policy` command
- 2x performance for object commands

## 0.1.5 (2017-09-18)

- Fixed error with `enable-logging`

## 0.1.4 (2017-09-17)

- Added `scan-object-acl` command
- Added `--only` and `--except` options
- Added `--log-bucket` and `--log-prefix` options to `scan` command
- Added `--log-prefix` option to `enable-logging` command

## 0.1.3 (2017-09-14)

- Fixed policy check
- Added `list-policy` command
- Added `reset-object-acl` command
- Added support for wildcards
- Added support for customer-provided encryption key
- Added `--version` option
- Parallelize encryption

## 0.1.2 (2017-09-13)

- Fixed issue with packaging

## 0.1.1 (2017-09-12)

- Fixed json error
- Better message for missing credentials

## 0.1.0 (2017-09-12)

- First release
