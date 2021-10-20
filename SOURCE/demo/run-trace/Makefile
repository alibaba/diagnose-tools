CXX ?= g++

arch=$(shell uname -i)
ifeq ($(arch),x86_64)
LDFLAGS = -L`pwd` -L/usr/lib64 -Wl,-allow-multiple-definition
else
LDFLAGS = -L`pwd` -L/usr/lib64
endif

# -I`pwd`/../../ 引用uapi目录
CXXFLAGS = -std=gnu++11 -c -O2 -I. -I`pwd`/../../ -Wall -g -fno-omit-frame-pointer -Wno-unused-result
ifeq ($(arch),aarch64)
	CXXFLAGS += -DDIAG_ARM64
endif

CWD = $(shell pwd)

TARGET=run-truce
SRCS = $(wildcard *.cc) $(wildcard testcase/pi/*.cc) $(wildcard testcase/memcpy/*.cc) \
	$(wildcard testcase/md5/*.cc) $(wildcard testcase/run_trace/*.cc)
OBJS=$(SRCS:.cc=.o)

all: $(TARGET)
	strip --strip-debug run-truce

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) $(LDFLAGS) -o $@
