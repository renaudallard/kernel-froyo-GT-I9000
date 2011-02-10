#! /bin/sh
#
# This is kernel build script for ubuntu 9.04's 2.6.28 kernel.
#

die () {
    echo $1
    exit 1
}

VERSION=`uname -r | cut -d - -f 1,2`
VERSION=`apt-cache search ^linux-image-2.6.28-..- | cut -b 13-21 | awk ' { print $1 }' | sort -r | uniq | head -n 1`
export CONCURRENCY_LEVEL=`grep -c '^processor' /proc/cpuinfo` || die "Can't export."

apt-get -y install wget
for key in 0A0AC927 17063E6D 174BF01A 191FCD8A 60E80B5B 63549F8E 76682A37 8BF9EFE6 3255AAF4 5E0577F2
do
  gpg --list-keys $key 2> /dev/null > /dev/null || wget -O - 'http://pgp.mit.edu:11371/pks/lookup?op=get&search=0x'$key | gpg --import || die "Can't import PGP key."
done

# Download TOMOYO Linux patches.
mkdir -p /usr/src/rpm/SOURCES/
cd /usr/src/rpm/SOURCES/ || die "Can't chdir to /usr/src/rpm/SOURCES/ ."
if [ ! -r ccs-patch-1.7.2-20110121.tar.gz ]
then
    wget -O ccs-patch-1.7.2-20110121.tar.gz 'http://sourceforge.jp/frs/redir.php?f=/tomoyo/43375/ccs-patch-1.7.2-20110121.tar.gz' || die "Can't download patch."
fi

# Install kernel source packages.
cd /usr/src/ || die "Can't chdir to /usr/src/ ."
apt-get install fakeroot build-essential || die "Can't install packages."
apt-get build-dep linux-image-${VERSION}-generic || die "Can't install packages."
apt-get source linux-image-${VERSION}-generic || die "Can't install kernel source."
apt-get install linux-headers-${VERSION} || die "Can't install packages."
apt-get build-dep linux-restricted-modules-${VERSION}-generic || die "Can't install packages."
apt-get source linux-restricted-modules-${VERSION}-generic || die "Can't install kernel source."

# Apply patches and create kernel config.
cd linux-2.6.28/ || die "Can't chdir to linux-2.6.28/ ."
tar -zxf /usr/src/rpm/SOURCES/ccs-patch-1.7.2-20110121.tar.gz || die "Can't extract patch."
patch -p1 < patches/ccs-patch-2.6.28-ubuntu-9.04.diff || die "Can't apply patch."
rm -fR patches/ specs/ || die "Can't delete patch."
for i in `find debian.master/ -type f -name '*generic*'`; do cp -p $i `echo $i | sed -e 's/generic/ccs/g'`; done
for i in debian.master/config/*/config; do cat config.ccs >> $i; done
rm debian.master/control.stub || die "Can't delete control.stub."
make -f debian.master/rules debian.master/control.stub || die "Can't update control.stub."
rm debian/control || die "Can't delete control."
debian/rules debian/control || die "Can't update control."
for i in debian.master/abi/2.6.28-*/*/ ; do touch $i/ccs.ignore; done

# Make modified header files go into local header package.
patch -p0 << "EOF" || die "Can't patch link-headers."
--- debian.master/scripts/link-headers
+++ debian.master/scripts/link-headers
@@ -39,4 +39,17 @@
 done
 )
 
+if [ $flavour == "ccs" ]
+then
+    cd $hdrdir/../../../../$symdir/usr/src/$symdir/include/linux/
+    for i in sched.h init_task.h ccsecurity.h
+    do
+	rm -f $hdrdir/include/linux/$i
+	cp -p $i $hdrdir/include/linux/
+    done
+    rm -f $hdrdir/security
+    cd ../../
+    tar -cf - security | ( cd $hdrdir ; tar -xf - )
+fi
+
 exit
EOF

# Start compilation.
debian/rules binary-headers || die "Failed to build kernel package."
debian/rules binary-debs flavours=ccs || die "Failed to build kernel package."

# Install header package for compiling additional modules.
dpkg -i /usr/src/linux-headers-*-ccs*.deb || die "Can't install packages."
cd /usr/src/linux-restricted-modules-2.6.28/ || die "Can't chdir to /usr/src/linux-restricted-modules-2.6.28/ ."
for i in `find debian/ -type f -name '*generic*'`; do cp -p $i `echo $i | sed -e 's/generic/ccs/g'`; done
touch debian/control.stub.in || die "Can't touch control."
debian/rules debian/control || die "Can't run control."
debian/rules binary-arch arch=i386 flavours=ccs || die "Failed to build kernel package."

# Generate meta packages.
cd /usr/src/
rm -fR linux-meta-*/
apt-get source linux-meta
cd linux-meta-*/
sed -e 's/generic/ccs/g' -- debian/control.d/generic > debian/ccs
rm -f debian/control.d/*
mv debian/ccs debian/control.d/ccs
debian/rules binary-arch
cd ../
rm -fR linux-meta-*/

exit 0
