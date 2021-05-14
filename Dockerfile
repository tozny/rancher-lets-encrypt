FROM python:3.9-alpine

RUN apk update
RUN apk add --no-cache gcc py-pip musl-dev libffi-dev openssl-dev linux-headers openssl libffi cargo

RUN mkdir -p /python /var/www

COPY files/requirements.txt /python/
RUN pip install -r /python/requirements.txt

COPY files/* /python/

ENTRYPOINT /python/rancher.py
