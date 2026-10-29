FROM python:3-alpine

LABEL org.opencontainers.image.authors="Andrew Kane <andrew@ankane.org>"

RUN pip install s3tk==0.5.1

RUN pip install awscli

CMD ["s3tk"]
