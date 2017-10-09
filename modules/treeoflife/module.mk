MOD		:= treeoflife
$(MOD)_SRCS	+= treeoflife.c

$(MOD)_SRCS	+= rpc.c
$(MOD)_SRCS	+= rpc_zone.c
$(MOD)_SRCS	+= rpc_child.c
$(MOD)_SRCS	+= rpc_dht.c

include mk/mod.mk
