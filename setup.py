from setuptools import setup

setup(
    name='s3tk',
    version='0.2.0',
    description='A security toolkit for Amazon S3',
    url='https://github.com/ankane/s3tk',
    author='Andrew Kane',
    author_email='andrew@chartkick.com',
    license='MIT',
    packages=['s3tk'],
    scripts=['bin/s3tk'],
    install_requires=[
        'boto3>=1.4.7',
        'botocore>=1.7.43',
        'clint',
        'click',
        'joblib<0.12.0'
    ],
    zip_safe=False
)
