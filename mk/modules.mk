MODULES   += dcmd
MODULES   += null
MODULES   += udp
MODULES   += treeoflife
MODULES   += web

#ui
ifeq ($(OS),win32)
MODULES   += wincon
else
MODULES   += stdio
endif