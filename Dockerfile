FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

RUN apt-get update

RUN apt-get install -y gcc gcc-multilib g++-multilib build-essential wget unzip python3-pip
RUN dpkg --add-architecture i386 && \ 
    apt-get update && \ 
    apt-get install -y linux-libc-dev:i386 \
    apt-get install -y gcc-arm-linux-gnueabi gcc-mips-linux-gnu
RUN pip3 install angr

RUN gcc -m32 -dumpmachine \
    && arm-linux-gnueabi-gcc -dumpmachine \
    && mips-linux-gnu-gcc -dumpmachine

WORKDIR /work