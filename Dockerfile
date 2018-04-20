FROM python:3-alpine

MAINTAINER Andrew Kane <andrew@chartkick.com>

ENV INSTALL_PATH /app

RUN mkdir -p $INSTALL_PATH

WORKDIR $INSTALL_PATH

COPY . ./

RUN pip install --no-cache-dir -r requirements.txt

RUN python setup.py install

RUN pip install awscli

CMD s3tk
