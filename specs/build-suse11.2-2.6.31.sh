#! /bin/sh
#
# This is a kernel build script for openSUSE 11.2's 2.6.31 kernel.
#

die () {
    echo $1
    exit 1
}

cd /usr/lib/rpm/ || die "Can't chdir to /usr/lib/rpm/ ."

if ! grep -q ccs-kernel find-supplements.ksyms
then
	patch << "EOF" || die "Can't patch find-supplements.ksyms ."
--- find-supplements.ksyms
+++ find-supplements.ksyms
@@ -7,6 +7,7 @@
 case "$1" in
 kernel-module-*)    ;; # Fedora kernel module package names start with
 		       # kernel-module.
+ccs-kernel*)      is_kernel_package=1 ;;
 kernel*)	   is_kernel_package=1 ;;
 esac
 
EOF
fi

if ! grep -q ccs-kernel find-requires.ksyms
then
	patch << "EOF" || die "Can't patch find-requires.ksyms ."
--- find-requires.ksyms
+++ find-requires.ksyms
@@ -5,6 +5,7 @@
 case "$1" in
 kernel-module-*)    ;; # Fedora kernel module package names start with
 		       # kernel-module.
+ccs-kernel*)       is_kernel_package=1 ;;
 kernel*)	    is_kernel_package=1 ;;
 esac
 
EOF
fi

if ! grep -q ccs-kernel find-provides.ksyms
then
	patch << "EOF" || die "Can't patch find-provides.ksyms ."
--- find-provides.ksyms
+++ find-provides.ksyms
@@ -5,6 +5,7 @@
 case "$1" in
 kernel-module-*)    ;; # Fedora kernel module package names start with
 		       # kernel-module.
+ccs-kernel-*)      kernel_flavor=${1#ccs-kernel-} ;;
 kernel*)	    kernel_flavor=${1#kernel-} ;;
 esac
 
EOF
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-source-2.6.31.14-0.6.1.src.rpm ]
then
    wget http://download.opensuse.org/update/11.2/rpm/src/kernel-source-2.6.31.14-0.6.1.src.rpm || die "Can't download source package."
fi
rpm --checksig kernel-source-2.6.31.14-0.6.1.src.rpm || die "Can't verify signature."
rpm -ivh kernel-source-2.6.31.14-0.6.1.src.rpm || die "Can't install source package."

if [ ! -r kernel-default-2.6.31.14-0.6.1.nosrc.rpm ]
then
    wget http://download.opensuse.org/update/11.2/rpm/src/kernel-default-2.6.31.14-0.6.1.nosrc.rpm || die "Can't download source package."
fi
rpm --checksig kernel-default-2.6.31.14-0.6.1.nosrc.rpm || die "Can't verify signature."
rpm -ivh kernel-default-2.6.31.14-0.6.1.nosrc.rpm || die "Can't install source package."

cd /usr/src/packages/SOURCES/ || die "Can't chdir to /usr/src/packages/SOURCES/ ."
if [ ! -r ccs-patch-1.7.2-20110121.tar.gz ]
then
    wget -O ccs-patch-1.7.2-20110121.tar.gz 'http://sourceforge.jp/frs/redir.php?f=/tomoyo/43375/ccs-patch-1.7.2-20110121.tar.gz' || die "Can't download patch."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p /usr/src/packages/SPECS/kernel-default.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel-default.spec
+++ kernel-default.spec
@@ -53,10 +53,10 @@
 %define install_vdso 0
 %endif
 
-Name:           kernel-default
+Name:           ccs-kernel-default
 Summary:        The Standard Kernel
 Version:        2.6.31.14
-Release:        0.6.1
+Release:        0.6.1_tomoyo_1.7.2p4
 %if %using_buildservice
 %else
 %endif
@@ -267,6 +267,10 @@
     sed 's:^:patch -s -F0 -E -p1 --no-backup-if-mismatch -i ../:' \
     >>../apply-patches.sh
 bash -ex ../apply-patches.sh
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.7.2-20110121.tar.gz
+patch -sp1 < patches/ccs-patch-2.6.31-suse-11.2.diff
+cat config.ccs >> ../config/%cpu_arch_flavor
 
 cd %kernel_build_dir
 
EOF
touch /usr/src/packages/SOURCES/IGNORE-KABI-BADNESS
sed -e 's:^Provides:#Provides:' -e 's:^Obsoletes:#Obsoletes:' -e 's:-n kernel:-n ccs-kernel:' kernel-default.spec > ccs-kernel.spec || die "Can't edit spec file."
echo ""
echo ""
echo ""
echo "Edit /tmp/ccs-kernel.spec if needed, and run"
echo "rpmbuild -bb /tmp/ccs-kernel.spec"
echo "to build kernel rpm packages."
echo ""
echo "I'll start 'rpmbuild -bb --target i586 /tmp/ccs-kernel.spec' in 30 seconds. Press Ctrl-C to stop."
sleep 30
exec rpmbuild -bb --target i586 /tmp/ccs-kernel.spec
exit 0
