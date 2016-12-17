FROM python:2.7-alpine

RUN mkdir /python
RUN apk add --no-cache gcc py-pip python-dev musl-dev libffi-dev openssl-dev linux-headers openssl libffi

COPY requirements.txt /python
RUN pip install -r /python/requirements.txt
COPY rancher.py /python
RUN mkdir -p /var/www/

ENTRYPOINT /python/rancher.py
