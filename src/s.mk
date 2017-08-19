#geofront
SRCS	+= geofront/conduits.c

#central dogma
SRCS	+= centraldogma/blake2s.c
SRCS	+= centraldogma/ledbat.c
SRCS	+= centraldogma/noise.c
SRCS	+= centraldogma/sign.c

#magi
SRCS	+= magi/core.c
SRCS	+= magi/melchior.c
SRCS	+= magi/eventdriver.c

#terminal dogma
ifeq ($(OS),darwin)
SRCS	+= terminaldogma/tun_darwin.c
endif
ifeq ($(OS),win32)
SRCS	+= terminaldogma/tun_win32.c
endif
ifeq ($(OS),linux)
SRCS	+= terminaldogma/tun_linux.c
endif

#misato (application)
SRCS	+= misato/everip.c
SRCS	+= misato/cmd.c
SRCS	+= misato/ui.c
SRCS	+= misato/module.c

#ritsuko (utilities)
SRCS	+= ritsuko/log.c
SRCS	+= ritsuko/net.c
SRCS	+= ritsuko/addr.c
SRCS	+= ritsuko/tai64.c

SRCS	+= ritsuko/bencode.c
SRCS	+= ritsuko/bencode_dec.c
SRCS	+= ritsuko/bencode_dec_od.c

ifeq ($(OS),darwin)
SRCS	+= ritsuko/net_darwin.c
endif
ifeq ($(OS),win32)
SRCS	+= ritsuko/net_win32.c
endif
ifeq ($(OS),linux)
SRCS	+= ritsuko/net_linux.c
endif

#tree of life
SRCS	+= treeoflife/atfield.c
SRCS	+= treeoflife/stack.c
# SRCS	+= treeoflife/treeoflife.c

ifneq ($(STATIC),)
SRCS	+= static.c
endif

APP_SRCS += main.c
