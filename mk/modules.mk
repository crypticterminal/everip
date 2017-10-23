MODULES   += dcmd
MODULES   += null
MODULES   += udp
MODULES   += udpd
MODULES   += treeoflife
MODULES   += web
MODULES   += dnet
MODULES   += wui

#ui
ifeq ($(OS),win32)
MODULES   += wincon
else
MODULES   += stdio
endif