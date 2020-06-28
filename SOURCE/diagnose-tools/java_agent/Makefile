all: libperfmap.so

SRCS := perf-map-agent.c perf-map-file.c
OBJS := perf-map-agent.o perf-map-file.o

JAVA_1_7=$(shell ls /usr/lib/jvm/ | grep java-1.7.0-openjdk | head -1)
CFLAGS = -fPIC -static-libgcc -static-libstdc++ -Wall -O2 -I . -I /usr/lib/jvm/$(JAVA_1_7)/include/ -I /usr/lib/jvm/$(JAVA_1_7)/include/linux/ -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux
LDFLAGS = -O2 -shared -static-libgcc -static-libstdc++

libperfmap.so: $(OBJS)
	$(CC) $(LDFLAGS) $^ -o $@

clean:
	rm -f libperfmap.so *.o
