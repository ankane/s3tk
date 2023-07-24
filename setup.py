from setuptools import setup

with open('README.md', 'r', encoding='utf-8') as fh:
    long_description = fh.read()

setup(
    name='s3tk',
    version='0.4.0',
    description='A security toolkit for Amazon S3',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/ankane/s3tk',
    author='Andrew Kane',
    author_email='andrew@ankane.org',
    license='MIT',
    packages=['s3tk'],
    scripts=['bin/s3tk'],
    python_requires='>=3.8',
    install_requires=[
        'boto3>=1.9.46',
        'botocore>=1.12.46',
        'clint',
        'click',
        'joblib'
    ],
    zip_safe=False
)
