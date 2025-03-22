FROM python:3.9-buster

COPY . /app/plugins
WORKDIR /app/plugins

RUN apt-get update
RUN apt-get install -y build-essential cmake musl-dev gcc g++ libffi-dev libssl-dev python3-dev curl libkrb5-dev librocksdb-dev libleveldb-dev libsnappy-dev liblz4-dev
RUN pip install scrypt x11_hash
RUN pip install -r /app/plugins/requirements.txt
RUN rm -rf /var/cache/apk/*
RUN rm -rf /usr/share/man
RUN rm -rf /tmp/*

ENV ALLOW_ROOT 1
ENV EVENT_LOOP_POLICY="uvloop"

EXPOSE 8000 9000

CMD ["python3", "/app/plugins/main.py"]
