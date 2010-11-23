#!/bin/sh
export ARCH=arm 
export PATH=$PATH:/home/r/arm-2010.09/bin:/usr/java/jdk1.6.0_21/bin
export CROSS_COMPILE=/home/r/arm-2010.09/bin/arm-none-eabi-
export ac_cv_linux_vers=2.6.32
export CC=/home/r/arm-2010.09/bin/arm-none-eabi-gcc
#export CC=/home/r/galaxy/agcc
export LD=/home/r/arm-2010.09/bin/arm-none-eabi-ld
export AR=/home/r/arm-2010.09/bin/arm-none-eabi-ar
export RANLIB=/home/r/arm-2010.09/arm-none-eabi/bin/ranlib
export PATH=$PATH:/home/r/arm-2010.09/bin
export PATH=$PATH:/home/r/arm-2010.09/
export PATH=$PATH:/home/r/arm-2010.09/lib
export CFLAGS="-static -Os"
export LDFLAGS="-static -Os"
export CPPFLAGS="-static -Os"

echo "./configure --host=arm-none-eabi --target=arm-none-eabi"
