CFLAGS = 
uname = $(shell uname -a)
ifneq ($(findstring Darwin, $(uname)),)
  libpath = ../resources/lib/osx_x64/
  CFLAGS+=-I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/darwin
  TARGET=libaraqne_pcap.dylib
else ifneq ($(findstring x86_64, $(uname)),)
  libpath = ../resources/lib/linux_x86_64
  CFLAGS += -I$(JAVA_HOME)/include/ -I$(JAVA_HOME)/include/linux/
  TARGET=libaraqne_pcap.so
else ifneq ($(findstring i386, $(uname)),)
  libpath = ../resources/lib/linux_x86
  CFLAGS += -I$(JAVA_HOME)/include/ -I$(JAVA_HOME)/include/linux/
  TARGET=libaraqne_pcap.so
else ifneq ($(findstring i586, $(uname)),)
  libpath = ../resources/lib/linux_x86
  CFLAGS += -I$(JAVA_HOME)/include/ -I$(JAVA_HOME)/include/linux/
  TARGET=libaraqne_pcap.so
else ifneq ($(findstring i686, $(uname)),)
  libpath = ../resources/lib/linux_x86
  CFLAGS += -I$(JAVA_HOME)/include/ -I$(JAVA_HOME)/include/linux/
  TARGET=libaraqne_pcap.so
else
$(error Not supported on this architecture)
endif

libaraqne_pcap.so:
ifeq ($(JAVA_HOME),)
	$(error JAVA_HOME is not set)
else
	gcc araqne_pcap.c routingtable.c buffer.c -o $(libpath)/$(TARGET) -shared -Wall $(CFLAGS) -lpcap -lrt -fPIC
endif

clean:
	rm $(libpath)/$(TARGET)
