#/bin/sh
. ./setenv.sh
make -i clean
make -j4
find . -name *.ko | while read MODULE; do cp $MODULE ../initramfs/root/lib/modules/ ; done
make -j4
cp arch/arm/boot/zImage /home/public_html/r/
