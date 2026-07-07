#!/usr/bin/env bash

apt-get update
apt-get update

apt-get install -y gcc gcc-multilib build-essential wget unzip python3-pip
apt-get install -y gcc-arm-linux-gnueabi gcc-mips-linux-gnu

pip install angr

gcc -m32 -dumpmachine
arm-linux-gnueabi-gcc -dumpmachine
mips-linux-gnu-gcc -dumpmachine