#! /bin/sh
#
# This is a kernel build script for CentOS 4.8's 2.6.9 kernel.
#

die () {
    echo $1
    exit 1
}

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-2.6.9-89.35.1.EL.src.rpm ]
then
    wget http://ftp.riken.jp/Linux/centos/4.8/updates/SRPMS/kernel-2.6.9-89.35.1.EL.src.rpm || die "Can't download source package."
fi
rpm --checksig kernel-2.6.9-89.35.1.EL.src.rpm || die "Can't verify signature."
rpm -ivh kernel-2.6.9-89.35.1.EL.src.rpm || die "Can't install source package."

cd /usr/src/redhat/SOURCES/ || die "Can't chdir to /usr/src/redhat/SOURCES/ ."
if [ ! -r ccs-patch-1.7.2-20110121.tar.gz ]
then
    wget -O ccs-patch-1.7.2-20110121.tar.gz 'http://sourceforge.jp/frs/redir.php?f=/tomoyo/43375/ccs-patch-1.7.2-20110121.tar.gz' || die "Can't download patch."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p /usr/src/redhat/SPECS/kernel-2.6.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel-2.6.spec
+++ kernel-2.6.spec
@@ -27,7 +27,7 @@
 # that the kernel isn't the stock distribution kernel, for example by
 # adding some text to the end of the version number.
 #
-%define release 89.35.1.EL
+%define release 89.35.1.EL_tomoyo_1.7.2p4
 %define sublevel 9
 %define kversion 2.6.%{sublevel}
 %define rpmversion 2.6.%{sublevel}
@@ -140,6 +140,9 @@
 # to versions below the minimum
 #
 
+# TOMOYO Linux
+%define signmodules 0
+
 #
 # First the general kernel 2.6 required versions as per
 # Documentation/Changes
@@ -178,7 +181,7 @@
 %define __find_provides /usr/lib/rpm/redhat/find-kmod-provides.sh
 %define __find_requires %{nil}
 
-Name: kernel
+Name: ccs-kernel
 Group: System Environment/Kernel
 License: GPLv2
 Version: %{rpmversion}
@@ -5755,6 +5758,10 @@
 
 # END OF PATCH APPLICATIONS
 
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.7.2-20110121.tar.gz
+patch -sp1 < patches/ccs-patch-2.6.9-centos-4.8.diff
+
 cp %{SOURCE10} Documentation/
 
 mkdir configs
@@ -5766,6 +5773,9 @@
 for i in *.config 
 do 
 	mv $i .config 
+	# TOMOYO Linux
+	cat config.ccs >> .config
+	sed -i -e "s/^CONFIG_DEBUG_INFO=.*/# CONFIG_DEBUG_INFO is not set/" -- .config
 	make ARCH=`echo $i | cut -d"-" -f3 | cut -d"." -f1 | sed -e s/i.86/i386/ -e s/s390x/s390/ -e s/ppc64.series/ppc64/  ` nonint_oldconfig > /dev/null 
 	cp .config configs/$i 
 done
EOF
mv kernel-2.6.spec ccs-kernel.spec || die "Can't rename spec file."
echo ""
echo ""
echo ""
echo "Edit /tmp/ccs-kernel.spec if needed, and run"
echo "rpmbuild -bb /tmp/ccs-kernel.spec"
echo "to build kernel rpm packages."
echo ""
echo "I'll start 'rpmbuild -bb --target i586 /tmp/ccs-kernel.spec' in 30 seconds. Press Ctrl-C to stop."
sleep 30
patch << "EOF" || die "Can't patch spec file."
--- /tmp/ccs-kernel.spec
+++ /tmp/ccs-kernel.spec
@@ -4,14 +4,14 @@
 # What parts do we want to build?  We must build at least one kernel.
 # These are the kernels that are built IF the architecture allows it.
 
-%define buildup 1
+%define buildup 0
 %define buildsmp 1
 %define buildsource 0
-%define buildhugemem 1
-%define buildlargesmp 1
+%define buildhugemem 0
+%define buildlargesmp 0
 %define builddoc 0
-%define buildxen 1
-%define kabi 1
+%define buildxen 0
+%define kabi 0
 
 %define FC2 0
 %define FC3 0
EOF
exec rpmbuild -bb --target i586 /tmp/ccs-kernel.spec
exit 0
