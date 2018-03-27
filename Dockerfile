FROM edgarfelizmenio/cs300-unified:latest
LABEL maintainer="edgarfelizmenio@gmail.com"

ADD . /code
WORKDIR /code

RUN pip3 freeze


