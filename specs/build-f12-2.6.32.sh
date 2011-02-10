#! /bin/sh
#
# This is a kernel build script for Fedora 12's 2.6.32 kernel.
#

die () {
    echo $1
    exit 1
}

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-2.6.32.26-175.fc12.src.rpm ]
then
    wget http://ftp.riken.jp/Linux/fedora/updates/12/SRPMS/kernel-2.6.32.26-175.fc12.src.rpm || die "Can't download source package."
fi
rpm --checksig kernel-2.6.32.26-175.fc12.src.rpm || die "Can't verify signature."
rpm -ivh kernel-2.6.32.26-175.fc12.src.rpm || die "Can't install source package."

cd /root/rpmbuild/SOURCES/ || die "Can't chdir to /root/rpmbuild/SOURCES/ ."
if [ ! -r ccs-patch-1.7.2-20110121.tar.gz ]
then
    wget -O ccs-patch-1.7.2-20110121.tar.gz 'http://sourceforge.jp/frs/redir.php?f=/tomoyo/43375/ccs-patch-1.7.2-20110121.tar.gz' || die "Can't download patch."
fi

cd /root/rpmbuild/SPECS/ || die "Can't chdir to /root/rpmbuild/SPECS/ ."
cp -p kernel.spec ccs-kernel.spec || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- ccs-kernel.spec
+++ ccs-kernel.spec
@@ -22,7 +22,7 @@
 # appended to the full kernel version.
 #
 # (Uncomment the '#' and the first two spaces below to set buildid.)
-# % define buildid .local
+%define buildid _tomoyo_1.7.2p4
 ###################################################################
 
 # The buildid can also be specified on the rpmbuild command line
@@ -429,6 +429,11 @@
 # to versions below the minimum
 #
 
+# TOMOYO Linux
+%define with_modsign 0
+%define _enable_debug_packages 0
+%define with_debuginfo 0
+
 #
 # First the general kernel 2.6 required versions as per
 # Documentation/Changes
@@ -464,7 +469,7 @@
 # Packages that need to be installed before the kernel is, because the %post
 # scripts use them.
 #
-%define kernel_prereq  fileutils, module-init-tools, initscripts >= 8.11.1-1, kernel-firmware >= %{rpmversion}-%{pkg_release}, grubby >= 7.0.4-1
+%define kernel_prereq  fileutils, module-init-tools, initscripts >= 8.11.1-1, grubby >= 7.0.4-1
 %if %{with_dracut}
 %define initrd_prereq  dracut >= 002 xorg-x11-drv-ati-firmware
 %else
@@ -500,7 +505,7 @@
 AutoProv: yes\
 %{nil}
 
-Name: kernel%{?variant}
+Name: ccs-kernel%{?variant}
 Group: System Environment/Kernel
 License: GPLv2
 URL: http://www.kernel.org/
@@ -950,7 +955,7 @@
 Provides: kernel-devel-uname-r = %{KVERREL}%{?1:.%{1}}\
 AutoReqProv: no\
 Requires(pre): /usr/bin/find\
-%description -n kernel%{?variant}%{?1:-%{1}}-devel\
+%description -n ccs-kernel%{?variant}%{?1:-%{1}}-devel\
 This package provides kernel headers and makefiles sufficient to build modules\
 against the %{?2:%{2} }kernel package.\
 %{nil}
@@ -1568,6 +1573,10 @@
 # END OF PATCH APPLICATIONS ====================================================
 %endif
 
+# TOMOYO Linux
+tar -zxf %_sourcedir/ccs-patch-1.7.2-20110121.tar.gz
+patch -sp1 < patches/ccs-patch-2.6.32-fedora-12.diff
+
 # Any further pre-build tree manipulations happen here.
 
 chmod +x scripts/checkpatch.pl
@@ -1594,6 +1603,9 @@
 for i in *.config
 do
   mv $i .config
+  # TOMOYO Linux
+  cat config.ccs >> .config
+  sed -i -e 's:CONFIG_DEBUG_INFO=.*:# CONFIG_DEBUG_INFO is not set:' -- .config
   Arch=`head -1 .config | cut -b 3-`
   make ARCH=$Arch %{oldconfig_target} > /dev/null
   echo "# $Arch" > configs/$i
EOF
echo ""
echo ""
echo ""
echo "Edit /root/rpmbuild/SPECS/ccs-kernel.spec if needed, and run"
echo "rpmbuild -bb /root/rpmbuild/SPECS/ccs-kernel.spec"
echo "to build kernel rpm packages."
echo ""
echo "I'll start 'rpmbuild -bb --target i686 --with baseonly --without debug --without debuginfo /root/rpmbuild/SPECS/ccs-kernel.spec' in 30 seconds. Press Ctrl-C to stop."
sleep 30
patch << "EOF" || die "Can't patch spec file."
--- /root/rpmbuild/SPECS/ccs-kernel.spec
+++ /root/rpmbuild/SPECS/ccs-kernel.spec
@@ -224,7 +224,7 @@
 
 # kernel-PAE is only built on i686.
 %ifarch i686
-%define with_pae 1
+%define with_pae 0
 %else
 %define with_pae 0
 %endif
EOF
exec rpmbuild -bb --target i686 --with baseonly --without debug --without debuginfo /root/rpmbuild/SPECS/ccs-kernel.spec
exit 0
