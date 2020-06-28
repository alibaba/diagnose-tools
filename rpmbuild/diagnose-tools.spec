Name: diagnose-tools
Summary: linux diagnose tool
Version: 2.0
Release: rc1%{?dist}
packager: Baoyou Xie <baoyou.xie@linux.alibaba.com>
Group: linux/diagnose
License: Commercial
BuildRoot: %{_tmppath}/%{name}-%{version}-root

%description
linux diagnose tool
commit: 

%global __os_install_post %{nil}
%define debug_package %{nil}

%build

%install
mkdir -p $RPM_BUILD_ROOT/usr/diagnose-tools/
mkdir -p $RPM_BUILD_ROOT/usr/bin/
/bin/cp -rf /home/baoyou.xie/git/diagnose-tools/build/lib $RPM_BUILD_ROOT/usr/diagnose-tools/
/bin/cp -rf /home/baoyou.xie/git/diagnose-tools/build/bin $RPM_BUILD_ROOT/usr/diagnose-tools/
/bin/cp -rf /home/baoyou.xie/git/diagnose-tools/rpmbuild/../SOURCE/diagnose-tools/diagnose-tools $RPM_BUILD_ROOT/usr/bin/
/bin/cp -rf /home/baoyou.xie/git/diagnose-tools/rpmbuild/../prebuild/modules/* $RPM_BUILD_ROOT/usr/diagnose-tools/lib/
/bin/cp -rf /home/baoyou.xie/git/diagnose-tools/rpmbuild/../SOURCE/diagnose-tools/java_agent/libperfmap.so $RPM_BUILD_ROOT/usr/diagnose-tools/
/bin/cp -rf /home/baoyou.xie/git/diagnose-tools/rpmbuild/../SOURCE/perf-tools $RPM_BUILD_ROOT/usr/diagnose-tools/
/bin/cp -rf /home/baoyou.xie/git/diagnose-tools/rpmbuild/../SOURCE/script/diagnose-tools.sh $RPM_BUILD_ROOT/usr/diagnose-tools/
/bin/cp -rf /home/baoyou.xie/git/diagnose-tools/rpmbuild/../SOURCE/script/get_sys_call.sh $RPM_BUILD_ROOT/usr/diagnose-tools/
/bin/cp -rf /home/baoyou.xie/git/diagnose-tools/rpmbuild/../SOURCE/script/test.sh $RPM_BUILD_ROOT/usr/diagnose-tools/
/bin/cp -rf /home/baoyou.xie/git/diagnose-tools/rpmbuild/../SOURCE/script/flame-graph/ $RPM_BUILD_ROOT/usr/diagnose-tools/
/bin/cp -rf /home/baoyou.xie/git/diagnose-tools/rpmbuild/../documents/usage.docx $RPM_BUILD_ROOT/usr/diagnose-tools/usage.docx

%clean
rm -rf $RPM_BUILD_ROOT

%preun

/sbin/lsmod | grep diagnose > /dev/null
if [ 0 -eq 0 ]; then
	/sbin/rmmod diagnose
	exit 0
fi

%files
/usr/diagnose-tools
/usr/bin/diagnose-tools

%changelog
