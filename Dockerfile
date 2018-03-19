FROM ubuntu:16.04
MAINTAINER Edgar Felizmenio "edgarfelizmenio@gmail.com"

ADD . /code
WORKDIR /code

RUN apt update && apt install --yes build-essential flex bison wget subversion m4 python3 python3-dev python3-setuptools libgmp-dev libssl-dev
RUN wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz && tar xvf pbc-0.5.14.tar.gz && cd pbc-0.5.14 && ./configure LDFLAGS="-lgmp" && make && make install && ldconfig
WORKDIR charm
RUN ./configure.sh && make && make install && ldconfig

RUN apt install -y -q python3-pip

WORKDIR /code

RUN pip3 install -r requirements.txt
RUN pip3 install gunicorn

RUN pip3 freeze
