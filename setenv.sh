#!/bin/sh
export ARCH=arm 
export PATH=$PATH:/home/r/arm-2010q1/bin:/usr/java/jdk1.6.0_21/bin
#export CROSS_COMPILE=/home/r/mydroid/prebuilt/linux-x86/toolchain/arm-eabi-4.2.1/bin/arm-eabi-
#export CROSS_COMPILE=/home/r/galaxy/opensrc/prebuilt/linux-x86/toolchain/arm-eabi-4.2.1/bin/arm-eabi-
export CROSS_COMPILE=/home/r/arm-2010q1/bin/arm-none-eabi-
export ac_cv_linux_vers=2.6.32
export CC=/home/r/arm-2010q1/bin/arm-none-eabi-gcc
#export CC=/home/r/galaxy/agcc
export LD=/home/r/arm-2010q1/bin/arm-none-eabi-ld
export AR=/home/r/arm-2010q1/bin/arm-none-eabi-ar
export RANLIB=/home/r/arm-2010q1/arm-none-eabi/bin/ranlib
export PATH=$PATH:/home/r/arm-2010q1/bin
export PATH=$PATH:/home/r/arm-2010q1/
export PATH=$PATH:/home/r/arm-2010q1/lib
export CFLAGS="-static -Os"
export LDFLAGS="-static -Os"
export CPPFLAGS="-static -Os"

echo "./configure --host=arm-none-eabi --target=arm-none-eabi"
