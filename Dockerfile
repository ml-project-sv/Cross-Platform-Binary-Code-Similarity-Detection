FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

RUN apt-get update
RUN apt-get install -y gcc gcc-multilib g++-multilib libc6-dev-i386 build-essential wget unzip python3-pip
RUN apt-get install -y gcc-arm-linux-gnueabi gcc-mips-linux-gnu
RUN pip3 install angr

RUN gcc -m32 -dumpmachine \
    && arm-linux-gnueabi-gcc -dumpmachine \
    && mips-linux-gnu-gcc -dumpmachine

WORKDIR /work