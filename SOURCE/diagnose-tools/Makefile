CXX ?= g++
VENDER_LDFLAGS ?= 

arch=$(shell uname -i)
ifeq ($(arch),x86_64)
LDFLAGS = $(VENDER_LDFLAGS) -static-libgcc -static-libstdc++ -lgcc_eh -lunwind-x86_64 -lunwind -lelf \
	-L`pwd` -L/usr/lib64 -Wl,-allow-multiple-definition
else
LDFLAGS = $(VENDER_LDFLAGS) -static-libgcc -static-libstdc++ -L`pwd` -L/usr/lib64 -lunwind-aarch64 -lunwind -lelf -llzma -lz
endif

CXXFLAGS = -std=gnu++11 -c -O2 -I.. -I`pwd`/include -Wall -g -fno-omit-frame-pointer -Wno-unused-result
ifeq ($(arch),aarch64)
	CXXFLAGS += -DDIAG_ARM64
endif

CWD = $(shell pwd)

TARGET=diagnose-tools
SRCS = $(wildcard *.cc) $(wildcard testcase/pi/*.cc) $(wildcard testcase/memcpy/*.cc) \
	$(wildcard testcase/md5/*.cc) $(wildcard testcase/run_trace/*.cc)
OBJS=$(SRCS:.cc=.o)

all: $(TARGET)
	strip --strip-debug diagnose-tools

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) $(LDFLAGS) -o $@

deps:
	cd elfutils; autoreconf -ivf; ./configure CFLAGS="-g -O2" --disable-debuginfod --enable-maintainer-mode --prefix=$(PWD)/deps; make install
	cd libunwind; ./autogen.sh; ./configure CFLAGS="-g -O2" --prefix=$(PWD)/deps; make install
	cd xz; ./autogen.sh; ./configure CFLAGS="-g -O2" --prefix=$(PWD)/deps; make install
	cd zlib; ./configure --prefix=$(PWD)/deps; make install

.PHONY: deps

clean:
	rm -f $(TARGET) *.o libperfmap.so
	rm -f testcase/pi/*.o testcase/memcpy/*.o testcase/md5/*.o testcase/run_trace/*.o

distclean:
	rm -f $(TARGET) *.o libperfmap.so
	rm -f testcase/pi/*.o testcase/memcpy/*.o testcase/md5/*.o testcase/run_trace/*.o
	make -C elfutils clean
	make -C libunwind clean
	make -C xz clean

install:
	[ ! -z "$(DEST_DIR)" ] &&  mkdir -p $(DEST_DIR) && /bin/cp -f $(TARGET) $(DEST_DIR)
