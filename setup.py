from setuptools import setup

setup(
    name='s3tk',
    version='0.1.5',
    description='A security toolkit for Amazon S3',
    url='https://github.com/ankane/s3tk',
    author='Andrew Kane',
    author_email='andrew@chartkick.com',
    license='MIT',
    packages=['s3tk'],
    scripts=['bin/s3tk'],
    install_requires=[
        'boto3',
        'clint',
        'click',
        'joblib'
    ],
    zip_safe=False
)
