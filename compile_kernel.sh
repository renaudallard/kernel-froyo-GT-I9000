#/bin/sh
. ./setenv.sh
make -i clean
make -j4
find . -name *.ko | while read MODULE; do cp $MODULE ../initramfs/lib/modules/ ; done
make -j4
