#!/bin/sh
export ARCH=arm 
export PATH=$PATH:/home/r/arm-2009q3/bin:/usr/java/jdk1.6.0_21/bin
export CROSS_COMPILE=/home/r/arm-2009q3/bin/arm-none-linux-gnueabi-
export ac_cv_linux_vers=2.6.32
export CC=/home/r/arm-2009q3/bin/arm-none-linux-gnueabi-gcc
#export CC=/home/r/galaxy/agcc
export LD=/home/r/arm-2009q3/bin/arm-none-linux-gnueabi-ld
export AR=/home/r/arm-2009q3/bin/arm-none-linux-gnueabi-ar
export RANLIB=/home/r/arm-2009q3/arm-none-linux-gnueabi/bin/ranlib
export PATH=$PATH:/home/r/arm-2009q3/bin
export PATH=$PATH:/home/r/arm-2009q3/
export PATH=$PATH:/home/r/arm-2009q3/lib
#export CFLAGS="-static -Os -mcpu=cortex-a8 -mfpu=neon -mfloat-abi=softfp -fno-gcse -fprefetch-loop-arrays --param l2-cache-size=512 --param l1-cache-size=64 --param simultaneous-prefetches=6 --param prefetch-latency=400 --param l1-cache-line-size=64"
export CFLAGS="-static -Os -fstack-protector -fstack-protector-all"
export LDFLAGS="-static -Os"
export CPPFLAGS="-static -Os"

echo "./configure --host=arm-none-linux-gnueabi --target=arm-none-linux-gnueabi"
