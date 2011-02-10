#! /bin/sh
#
# This is a kernel build script for openSUSE 11.1's 2.6.27 kernel.
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
+ccs-kernel-*)      is_kernel_package=1 ;;
 kernel*)	    is_kernel_package=1 ;;
 esac
 
EOF
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-source-2.6.27.56-0.1.1.src.rpm ]
then
    wget http://download.opensuse.org/update/11.1/rpm/src/kernel-source-2.6.27.56-0.1.1.src.rpm || die "Can't download source package."
fi
rpm --checksig kernel-source-2.6.27.56-0.1.1.src.rpm || die "Can't verify signature."
rpm -ivh kernel-source-2.6.27.56-0.1.1.src.rpm || die "Can't install source package."

cd /usr/src/packages/SOURCES/ || die "Can't chdir to /usr/src/packages/SOURCES/ ."
if [ ! -r ccs-patch-1.7.2-20110121.tar.gz ]
then
    wget -O ccs-patch-1.7.2-20110121.tar.gz 'http://sourceforge.jp/frs/redir.php?f=/tomoyo/43375/ccs-patch-1.7.2-20110121.tar.gz' || die "Can't download patch."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p /usr/src/packages/SOURCES/kernel-default.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel-default.spec
+++ kernel-default.spec
@@ -63,13 +63,13 @@
 %if %build_vanilla || %build_kdump || %CONFIG_MODULES != "y"
 %define split_packages 0
 %else
-%define split_packages 1
+%define split_packages 0
 %endif
 
-Name:           kernel-default
+Name:           ccs-kernel-default
 Summary:        The Standard Kernel
 Version:        2.6.27.56
-Release:        0.1.1
+Release:        0.1.1_tomoyo_1.7.2p4
 License:        GPL v2 only
 Group:          System/Kernel
 Url:            http://www.kernel.org/
@@ -242,7 +242,7 @@
 
 # kABI change tolerance (default in maintenance should be 4, 6, 8 or 15,
 # 31 is the maximum; see scripts/kabi-checks)
-%define tolerate_kabi_changes 6
+%define tolerate_kabi_changes 31
 
 %description
 The standard kernel for both uniprocessor and multiprocessor systems.
@@ -342,6 +342,10 @@
 source .rpm-defs
 
 cd linux-2.6.27
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.7.2-20110121.tar.gz
+patch -sp1 < patches/ccs-patch-2.6.27-suse-11.1.diff
+cat config.ccs >> .config
 cp .config .config.orig
 %if %{tolerate_unknown_new_config_options}
 MAKE_ARGS="$MAKE_ARGS -k"
EOF
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
patch << "EOF" || die "Can't patch spec file."
--- /tmp/ccs-kernel.spec
+++ /tmp/ccs-kernel.spec
@@ -97,7 +97,7 @@
 #!BuildIgnore:  perl-Bootloader mkinitrd
 
 %if ! 0%{?opensuse_bs}
-BuildRequires:  kernel-dummy
+#BuildRequires:  kernel-dummy
 %endif
 %ifarch ia64
 # arch/ia64/scripts/unwcheck.py
EOF
exec rpmbuild -bb --target i586 /tmp/ccs-kernel.spec
exit 0
