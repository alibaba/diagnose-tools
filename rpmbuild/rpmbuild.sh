#!/bin/bash

build_rpm()
{
    local RPMBUILD_DIR="`readlink -f $BASE/../rpmbuild`"
    local BUILD_DIR=`readlink -f $BASE/../build`
    rm ${RPMBUILD_DIR}/BUILD -rf
    rm ${RPMBUILD_DIR}/RPMS -rf
    rm ${RPMBUILD_DIR}/SOURCES -rf
    rm ${RPMBUILD_DIR}/SPECS -rf
    rm ${RPMBUILD_DIR}/SRPMS -rf
    mkdir -p "${RPMBUILD_DIR}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
    mkdir -p $BUILD_DIR/lib/`uname -r`

cat > $RPMBUILD_DIR/diagnose-tools.spec <<EOF 
Name: diagnose-tools
Summary: linux diagnose tool
Version: ${RPM_VERSION}
Release: ${RPM_RELEASE}%{?dist}
packager: Baoyou Xie <baoyou.xie@linux.alibaba.com>
Group: linux/diagnose
License: Commercial
BuildRoot: %{_tmppath}/%{name}-%{version}-root

%description
linux diagnose tool
commit: $COMMIT_ID

%global __os_install_post %{nil}
%define debug_package %{nil}

%build

%install
mkdir -p \$RPM_BUILD_ROOT/usr/diagnose-tools/
mkdir -p \$RPM_BUILD_ROOT/usr/bin/
/bin/cp -rf $BUILD_DIR/lib \$RPM_BUILD_ROOT/usr/diagnose-tools/
/bin/cp -rf $BUILD_DIR/bin \$RPM_BUILD_ROOT/usr/diagnose-tools/
/bin/cp -rf $BASE/../SOURCE/diagnose-tools/diagnose-tools \$RPM_BUILD_ROOT/usr/bin/
/bin/cp -rf $BASE/../prebuild/modules/* \$RPM_BUILD_ROOT/usr/diagnose-tools/lib/
/bin/cp -rf $BASE/../SOURCE/diagnose-tools/java_agent/libperfmap.so \$RPM_BUILD_ROOT/usr/diagnose-tools/
/bin/cp -rf $BASE/../SOURCE/perf-tools \$RPM_BUILD_ROOT/usr/diagnose-tools/
/bin/cp -rf $BASE/../SOURCE/script/diagnose-tools.sh \$RPM_BUILD_ROOT/usr/diagnose-tools/
/bin/cp -rf $BASE/../SOURCE/script/get_sys_call.sh \$RPM_BUILD_ROOT/usr/diagnose-tools/
/bin/cp -rf $BASE/../SOURCE/script/test.sh \$RPM_BUILD_ROOT/usr/diagnose-tools/
/bin/cp -rf $BASE/../SOURCE/script/flame-graph/ \$RPM_BUILD_ROOT/usr/diagnose-tools/
/bin/cp -rf $BASE/../documents/usage.docx \$RPM_BUILD_ROOT/usr/diagnose-tools/usage.docx

%clean
rm -rf \$RPM_BUILD_ROOT

%preun

/sbin/lsmod | grep diagnose > /dev/null
if [ $? -eq 0 ]; then
	/sbin/rmmod diagnose
	exit 0
fi

%files
/usr/diagnose-tools
/usr/bin/diagnose-tools

%changelog
EOF

rpmbuild -bb $RPMBUILD_DIR/diagnose-tools.spec --define "%_topdir $RPMBUILD_DIR"
}

main()
{
    export BASE=`pwd`
    export RPM_VERSION=$1
    export RPM_RELEASE=$2

    local BUILD_DIR=`readlink -f $BASE/../build`
    mkdir -p $BUILD_DIR/bin

    build_rpm
}

echo "args1: $1 args2: $2 args3: $3 args4: $4"
main 2.1 release
