
CWD = $(shell pwd)
ARCH := $(shell uname -i)
UNAME_A := $(shell uname -a)
DEPS := $(shell pwd)/deps/

ifeq ($(JOBS),)
	JOBS := $(shell grep -c ^processor /proc/cpuinfo 2>/dev/null)
	ifeq ($(JOBS),)
		JOBS := 1
	endif
endif

all: module tools java_agent pkg
ifneq ($(findstring Ubuntu,$(UNAME_A) $(shell test -e /etc/os-release && head -1 /etc/os-release)),)
	dpkg -P diagnose-tools || echo "remove diagnose-tools error"
	cd rpmbuild; sudo dpkg -i diagnose-tools*.deb
else
	yum remove -y diagnose-tools
	yum localinstall -y rpmbuild/RPMS/x86_64/diagnose-tools-*.rpm
	diagnose-tools -v
endif

devel:
ifneq ($(findstring Ubuntu,$(UNAME_A) $(shell test -e /etc/os-release && head -1 /etc/os-release)),)
	#apt update
	apt -y install gcc
	apt -y install g++
	apt -y install libunwind8-dev
	apt -y install elfutils
	apt -y install libelf-dev
	apt -y install rpm
	apt -y install alien
	apt -y install bash-completion # git自动补全
	apt -y install --no-install-recommends openjdk-8-jdk
else
	yum install -y gcc
	yum install -y gcc-c++
	yum install -y libstdc++-static
	yum install -y glibc-static
	yum install -y zlib-devel
	yum install -y zlib-static
	yum install -y libunwind
	yum install -y libunwind-devel
	yum install -y elfutils-libelf-devel
	yum install -y java-1.7.0-openjdk-devel
	yum install -y rpm-build
	yum install -y xz-libs
	yum install -y xz-devel
endif
	sh ./vender/devel.sh

#ARM静态编译参数：-static-libgcc -static-libstdc++ -L`pwd` -L/usr/lib64 -lunwind-aarch64 -lunwind -lelf -llzma -lz

deps:
	cd $(DEPS)/elfutils; autoreconf -ivf; ./configure CFLAGS="-g -O2" --disable-debuginfod --enable-maintainer-mode --prefix=${DEPS}/; make install
	cd $(DEPS)/libunwind; ./autogen.sh; ./configure CFLAGS="-g -O2" --prefix=${DEPS}/; make install
	cd $(DEPS)/xz; ./autogen.sh; ./configure CFLAGS="-g -O2" --prefix=${DEPS}/; make install
	cd $(DEPS)/zlib; ./configure --prefix=${DEPS}/; make install

	cd SOURCE/diagnose-tools/java_agent; make
	sh ./vender/deps.sh

.PHONY: deps

module:
	cd SOURCE/module; make --jobs=${JOBS}
	mkdir -p build/lib/`uname -r`/
	/bin/cp -f SOURCE/module/diagnose.ko build/lib/`uname -r`/

tools:
	cd SOURCE/diagnose-tools; make clean; VENDER_LDFLAGS="-static -lunwind-x86_64 -lunwind -lelf -llzma -lz -L${DEPS}/lib -L${DEPS}/elfutils/libdwfl/" make --jobs=${JOBS}

java_agent:
	cd SOURCE/diagnose-tools/java_agent; make --jobs=${JOBS}

pkg:
	cd rpmbuild; sh rpmbuild.sh
	ls rpmbuild/RPMS/*/*
ifneq ($(findstring Ubuntu,$(UNAME_A) $(shell test -e /etc/os-release && head -1 /etc/os-release)),)
	#sudo dpkg-reconfigure dash !!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	cd rpmbuild; rm -f diagnose-tools*.deb
ifneq ($(findstring aarch64,$(ARCH)),)
	cd rpmbuild; sudo alien -d --target=arm64 ./RPMS/aarch64/diagnose-tools*.rpm
else
	cd rpmbuild; sudo alien -d ./RPMS/x86_64/diagnose-tools*.rpm
endif
endif

test:
	modprobe ext4
	insmod SOURCE/module/diagnose.ko || echo ""
	bash ./SOURCE/script/test.sh $(case)
	rmmod diagnose
	rm tmp.txt -f
	rm *.svg -f
	rm *.log -f
	rm *.raw -f

clean:
	cd SOURCE/module/; make clean
	cd SOURCE/diagnose-tools; rm -f $(TARGET) *.o libperfmap.so
	cd SOURCE/diagnose-tools; rm -f testcase/pi/*.o testcase/memcpy/*.o testcase/md5/*.o testcase/run_trace/*.o
	cd SOURCE/diagnose-tools; make -C java_agent clean
	sh ./vender/clean.sh

distclean:
	cd SOURCE/diagnose-tools; rm -f $(TARGET) *.o libperfmap.so
	cd SOURCE/diagnose-tools; rm -f testcase/pi/*.o testcase/memcpy/*.o testcase/md5/*.o testcase/run_trace/*.o
	cd SOURCE/diagnose-tools; make -C java_agent clean
	sh ./vender/distclean.sh
