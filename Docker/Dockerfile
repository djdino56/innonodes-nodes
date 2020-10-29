FROM ubuntu:16.04

RUN mkdir /src

WORKDIR /src

RUN apt-get update --fix-missing

RUN apt-get -y install \
  vim \
  git \
  wget \
  curl \
  lsb-core

ENTRYPOINT /bin/bash