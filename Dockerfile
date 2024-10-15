FROM python:3-alpine

LABEL org.opencontainers.image.authors="Andrew Kane <andrew@ankane.org>"

ENV INSTALL_PATH=/app

RUN mkdir -p $INSTALL_PATH

WORKDIR $INSTALL_PATH

COPY . ./

RUN pip install --no-cache-dir -r requirements.txt

RUN pip install .

RUN pip install awscli

CMD ["s3tk"]
