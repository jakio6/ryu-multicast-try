# Ryu SDN Framework
#
# VERSION 0.0.1

FROM ubuntu:20.04

# ENV HTTP_PROXY="http://192.168.31.158:8889"
ENV HOME /root

WORKDIR /root

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    python3-pip \
    netbase \
    ssh \
 && rm -rf /var/lib/apt/lists/*

# RUN http_proxy="http://192.168.31.158:8889" pip3 install ryu
RUN pip3 install ryu
