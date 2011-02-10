#! /bin/sh
#
# This is a kernel build script for VineLinux 4.2's 2.6.16 kernel.
#

die () {
    echo $1
    exit 1
}

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-2.6.16-76.55vl4.src.rpm ]
then
    wget http://updates.vinelinux.org/Vine-4.2/updates/SRPMS/kernel-2.6.16-76.55vl4.src.rpm || die "Can't download source package."
fi
rpm --checksig kernel-2.6.16-76.55vl4.src.rpm || die "Can't verify signature."
rpm -ivh kernel-2.6.16-76.55vl4.src.rpm || die "Can't install source package."

cd /usr/src/vine/SOURCES/ || die "Can't chdir to /usr/src/vine/SOURCES/ ."
if [ ! -r ccs-patch-1.7.2-20110121.tar.gz ]
then
    wget -O ccs-patch-1.7.2-20110121.tar.gz 'http://sourceforge.jp/frs/redir.php?f=/tomoyo/43375/ccs-patch-1.7.2-20110121.tar.gz' || die "Can't download patch."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p /usr/src/vine/SPECS/kernel-2.6-vl.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel-2.6-vl.spec
+++ kernel-2.6-vl.spec
@@ -23,7 +23,7 @@
 %define sublevel 16
 %define kversion 2.6.%{sublevel}
 %define rpmversion 2.6.%{sublevel}
-%define release 76.55%{_dist_release}
+%define release 76.55%{_dist_release}_tomoyo_1.7.2p4
 
 %define make_target bzImage
 
@@ -100,6 +100,9 @@
 # to versions below the minimum
 #
 
+# TOMOYO Linux
+%define signmodules 0
+
 #
 # First the general kernel 2.6 required versions as per
 # Documentation/Changes
@@ -126,7 +129,7 @@
 #
 %define kernel_prereq  fileutils, modutils >= 3.2.2 , initscripts >= 5.83, mkinitrd >= 4.2.1.8-0vl2.1
 
-Name: kernel
+Name: ccs-kernel
 Group: System Environment/Kernel
 License: GPLv2
 Version: %{rpmversion}
@@ -1155,6 +1158,10 @@
 
 # END OF PATCH APPLICATIONS
 
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.7.2-20110121.tar.gz
+patch -sp1 < patches/ccs-patch-2.6.16-vine-linux-4.2.diff
+
 cp %{SOURCE10} Documentation/
 
 # put Vine logo
@@ -1175,6 +1182,9 @@
 for i in *.config
 do 
 	mv $i .config 
+	# TOMOYO Linux
+	cat config.ccs >> .config
+	sed -i -e "s/^CONFIG_DEBUG_INFO=.*/# CONFIG_DEBUG_INFO is not set/" -- .config
 	Arch=`head -1 .config | cut -b 3-`
 	echo "# $Arch" > configs/$i
 	cat .config >> configs/$i 
EOF
mv kernel-2.6-vl.spec ccs-kernel.spec || die "Can't rename spec file."
echo ""
echo ""
echo ""
echo "Edit /tmp/ccs-kernel.spec if needed, and run"
echo "rpmbuild -bb /tmp/ccs-kernel.spec"
echo "to build kernel rpm packages."
echo ""
echo "I'll start 'rpmbuild -bb --target i686 /tmp/ccs-kernel.spec' in 30 seconds. Press Ctrl-C to stop."
sleep 30
exec rpmbuild -bb --target i686 /tmp/ccs-kernel.spec
exit 0
