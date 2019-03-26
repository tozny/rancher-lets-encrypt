FROM python:3.7-alpine3.9

RUN mkdir -p /python /var/www
RUN apk add --no-cache gcc py-pip python-dev musl-dev libffi-dev openssl-dev linux-headers openssl libffi

COPY files/* /python/
RUN pip install -r /python/requirements.txt

ENTRYPOINT /python/rancher.py
