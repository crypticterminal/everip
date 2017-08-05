MODULES   += dcmd
MODULES   += udp
MODULES   += eth
MODULES   += wui

#ui
ifeq ($(OS),win32)
MODULES   += wincon
else
MODULES   += stdio
endif