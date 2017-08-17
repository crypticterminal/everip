MODULES   += dcmd
MODULES   += null
MODULES   += udp
MODULES   += treeoflife
#MODULES   += eth

#ui
ifeq ($(OS),win32)
MODULES   += wincon
else
MODULES   += stdio
endif