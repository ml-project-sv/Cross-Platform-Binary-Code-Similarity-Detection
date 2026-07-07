#!/usr/bin/env bash

apt-get update
apt-get install -y gcc gcc-multilib g++-multilib libc6-dev-i386 build-essential wget unzip python3-pip
apt-get install -y gcc-arm-linux-gnueabi gcc-mips-linux-gnu
pip install angr
apt-get update

gcc -m32 -dumpmachine
arm-linux-gnueabi-gcc -dumpmachine
mips-linux-gnu-gcc -dumpmachine