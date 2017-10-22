/*
 * EVER/IP(R)
 * Copyright (c) 2017 kristopher tate & connectFree Corporation.
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * This project may be licensed under the terms of the ConnectFree Reference
 * Source License (CF-RSL). Corporate and Academic licensing terms are also
 * available. Please contact <licensing@connectfree.co.jp> for details.
 *
 * connectFree, the connectFree logo, and EVER/IP are registered trademarks
 * of connectFree Corporation in Japan and other countries. connectFree
 * trademarks and branding may not be used without express writen permission
 * of connectFree. Please remove all trademarks and branding before use.
 *
 * See the LICENSE file at the root of this project for complete information.
 *
 */

#include <re.h>
#include <everip.h>

#define HOP_LIMIT 3

struct this_module {

  uint8_t my_everip[EVERIP_ADDRESS_LENGTH];
  uint8_t my_public_key[NOISE_PUBLIC_KEY_LEN];

  /* conduit stuff */
  struct conduit *conduit;
  struct list peers;
  struct hash *peers_addr;

  /**/
  struct magi *magi;
};

static struct this_module *g_mod = NULL;

struct mod_peer {
  struct conduit_peer cp;
  struct this_module *ctx;

  uint8_t src[EVERIP_ADDRESS_LENGTH];

  struct le le_mod;
  struct le le_mod_addr;
};

static bool _peer_lookup_byeverip_h(struct le *le, void *arg)
{
  struct mod_peer *peer = le->data;
  return 0 == memcmp(peer->cp.everip_addr, (uint8_t *)arg, EVERIP_ADDRESS_LENGTH);
}

static struct mod_peer *_peer_lookup_byeverip( struct this_module *mod
                                         , const uint8_t everip[EVERIP_ADDRESS_LENGTH] )
{
  return list_ledata(hash_lookup( mod->peers_addr
                                , *(uint32_t *)(void *)everip
                                , &_peer_lookup_byeverip_h
                                , (void *)everip));
}

static void _peer_destructor(void *data)
{
  struct mod_peer *tp = data;

  /* x:start process cp */
  conduit_peer_deref(&tp->cp);
  /* x:end process cp */

  list_unlink(&tp->le_mod);
  list_unlink(&tp->le_mod_addr);
}

static int _peer_alloc( struct mod_peer **tpp
                      , struct this_module *mod
                      , const uint8_t everip[EVERIP_ADDRESS_LENGTH] )
{
  int err = 0;
  struct mod_peer *tp = NULL;

  if (!tpp || !mod || !everip)
    return EINVAL;

  tp = _peer_lookup_byeverip(mod, everip);

  if (tp) {
    *tpp = tp;
    err = EALREADY;
    goto out;
  }

  tp = mem_zalloc(sizeof(*tp), _peer_destructor);
  if (!tp)
    return ENOMEM;

  tp->ctx = mod;

  memcpy(tp->cp.everip_addr, everip, EVERIP_ADDRESS_LENGTH);

  list_append( &mod->peers, &tp->le_mod, tp);
  hash_append( mod->peers_addr
             , *(uint32_t *)(void *)everip
             , &tp->le_mod_addr
             , tp);

out:
  if (err && err != EALREADY) {
    tp = mem_deref(tp);
  } else {
    tp->cp.conduit = mod->conduit;
    err = conduit_peer_initiate( &tp->cp
                               , NULL /* no key */
                               , false /* no handshake */
                               );
    *tpp = tp;
  }
  return err;
}

/**/

struct tmp_send {
  struct mbuf *mb;
  const uint8_t *eip_dont_fwd;
};

#if 0
static bool _conduits_conduit_peer_apply_h( const struct conduit_peer *cp
                                          , void *arg )
{
  struct tmp_send *s = arg;
  struct mbuf *mb_clone = NULL;

  if (s->eip_dont_fwd && !memcmp(s->eip_dont_fwd, cp->everip_addr, EVERIP_ADDRESS_LENGTH))
    goto out;

  if ( (cp->conduit->flags & CONDUIT_FLAG_VIRTUAL)
    || cp->conduit == g_mod->conduit )
    goto out;

  mb_clone = mbuf_clone(s->mb);
  conduit_peer_encrypted_send( cp
                             , FRAME_TYPE_DNET
                             , mb_clone );
  mb_clone = mem_deref( mb_clone );

out:
  return false;
}
#endif

static bool _magi_node_apply_h(const struct magi_e2e_event *event, void *arg)
{
  struct tmp_send *s = arg;
  struct mbuf *mb_clone = NULL;
  struct conduit_peer *cp_selected = NULL;
  struct conduits_conduit_peer_search_criteria criteria;

  memset(&criteria, 0, sizeof(criteria));

  if (event->status != MAGI_NODE_STATUS_OPERATIONAL)
    goto out;

  if (s->eip_dont_fwd && !memcmp(s->eip_dont_fwd, event->everip_addr, EVERIP_ADDRESS_LENGTH))
    goto out;

  criteria.ex.conduitv = g_mod->conduit;
  criteria.ex.conduitc = 1;

  cp_selected = conduits_conduit_peer_search( everip_conduits()
                                            , &criteria
                                            , false /* no netsearch */
                                            , event->everip_addr );

  if (!cp_selected)
    goto out;

  mb_clone = mbuf_clone(s->mb);
  conduit_peer_encrypted_send( cp_selected
                             , FRAME_TYPE_DNET
                             , mb_clone );
  mb_clone = mem_deref( mb_clone );

out:
  return false;
}

static
int _conduit_search( const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH]
                   , void *arg )
{
  size_t pos_top;
  struct mbuf *mb = NULL;
  struct this_module *mod = arg;

  error("[DNET] _conduit_search\n");
  /*struct mod_peer *mp = NULL;*/

/*  mp = _peer_lookup_byeverip(mod, everip_addr);

  if (mb) {

  }*/

  mb = mbuf_alloc(EVER_OUTWARD_MBE_LENGTH*2);
  mb->pos = EVER_OUTWARD_MBE_POS;
  mb->end = EVER_OUTWARD_MBE_POS;

  mbuf_advance(mb, -(ssize_t)(1+1+EVERIP_ADDRESS_LENGTH+EVERIP_ADDRESS_LENGTH));
  pos_top = mb->pos;

  mbuf_write_u8(mb, 0); /* 0 == SEARCH */

  mbuf_write_u8(mb, HOP_LIMIT); /* HOP */

  /* everip address DST */
  mbuf_write_mem(mb, everip_addr, EVERIP_ADDRESS_LENGTH);

  /* everip address SRC */
  mbuf_write_mem(mb, mod->my_everip, EVERIP_ADDRESS_LENGTH);

  {
    struct tmp_send s;
    
    mbuf_set_pos(mb, pos_top);

    s.mb = mb;
    s.eip_dont_fwd = everip_addr;
    magi_node_apply(everip_magi(), &_magi_node_apply_h, &s);
    
  }

  mb = mem_deref( mb );

  return 0;
}

static
int _conduit_sendto_virtual( struct conduit_peer *peer
                           , struct mbuf *mb
                           , void *arg )
{
  int err = 0;
  size_t pos_top;
  struct tmp_send s;
  struct mod_peer *p = NULL;
  struct this_module *mod = arg;
  struct conduit_peer *cp_selected = NULL;
  struct conduits_conduit_peer_search_criteria criteria;

  memset(&criteria, 0, sizeof(criteria));

  p = container_of(peer, struct mod_peer, cp);

  error("[DNET] _conduit_sendto_virtual\n");

  if (!p || !mod)
    return EINVAL;

  s.mb = mb;
  s.eip_dont_fwd = peer->everip_addr;

  mbuf_advance(mb, -(ssize_t)(1+1+EVERIP_ADDRESS_LENGTH+EVERIP_ADDRESS_LENGTH));

  pos_top = mb->pos;

  mbuf_write_u8(mb, 2); /* 2 == PACKET */

  mbuf_write_u8(mb, HOP_LIMIT); /* HOP */

  /* everip address DST */
  mbuf_write_mem(mb, peer->everip_addr, EVERIP_ADDRESS_LENGTH);

  /* everip address SRC */
  mbuf_write_mem(mb, mod->my_everip, EVERIP_ADDRESS_LENGTH);

  /* write-out */
  mbuf_set_pos(mb, pos_top);

  criteria.ex.conduitv = g_mod->conduit;
  criteria.ex.conduitc = 1;

  cp_selected = conduits_conduit_peer_search( everip_conduits()
                                            , &criteria
                                            , false /* no netsearch */
                                            , peer->everip_addr );

  if (cp_selected) {
    conduit_peer_encrypted_send( cp_selected
                               , FRAME_TYPE_DNET
                               , mb );
  }
#if 1
  else {
    s.mb = mb;
    s.eip_dont_fwd = NULL;
    magi_node_apply(everip_magi(), &_magi_node_apply_h, &s);
  }
#endif

  return err;
}

int dnet_conduit_incoming( struct conduit_peer *cp, struct mbuf *mb )
{
  int err = 0;
  size_t pos_top;
  struct mod_peer *p = NULL;

  uint8_t in__type;
  uint8_t in__hop;
  uint8_t in__everip_dst[EVERIP_ADDRESS_LENGTH];
  uint8_t in__everip_src[EVERIP_ADDRESS_LENGTH];

  /*
  [EVERIP_DST(16)][EVERIP_SRC(16)]
  */

  if (!g_mod)
    return 0;

  if (mbuf_get_left(mb) < (1+1+EVERIP_ADDRESS_LENGTH+EVERIP_ADDRESS_LENGTH))
    goto out; /* eproto */

  pos_top = mb->pos;

  in__type = mbuf_read_u8(mb);

  in__hop = mbuf_read_u8(mb);

  if (!in__hop || in__hop - 1 == 0)
    goto out;

  mbuf_advance(mb, -1);
  mbuf_write_u8(mb, --in__hop);

  mbuf_read_mem(mb, in__everip_dst, EVERIP_ADDRESS_LENGTH);
  if (in__everip_dst[0] != 0xFC)
    goto out;

  mbuf_read_mem(mb, in__everip_src, EVERIP_ADDRESS_LENGTH);
  if (in__everip_src[0] != 0xFC)
    goto out;

#if 1
  warning( "[DNET][ROUTE][T:%u] [%W] -> [%W]\n"
       , in__type
       , in__everip_src, (size_t)EVERIP_ADDRESS_LENGTH
       , in__everip_dst, (size_t)EVERIP_ADDRESS_LENGTH
       );
#endif

  /* determine if we need to forward or eat the packet */
  if ( !memcmp(g_mod->my_everip, in__everip_dst, EVERIP_ADDRESS_LENGTH)) {
    /*warning("[DNET] THATS ME!\n");*/
    if (in__type == 0) {
      /* SEARCH (looking for us) */
      {
        struct mbuf *mb_reply = NULL;

        mb_reply = mbuf_outward_alloc(1+1+EVERIP_ADDRESS_LENGTH+EVERIP_ADDRESS_LENGTH+NOISE_PUBLIC_KEY_LEN);

        pos_top = mb_reply->pos;

        mbuf_write_u8(mb_reply, 1); /* 1 == FOUND */

        mbuf_write_u8(mb_reply, HOP_LIMIT); /* hop */

        /* everip address DST */
        mbuf_write_mem(mb_reply, in__everip_src, EVERIP_ADDRESS_LENGTH);

        /* everip address SRC */
        mbuf_write_mem(mb_reply, g_mod->my_everip, EVERIP_ADDRESS_LENGTH);

        /* public key */
        mbuf_write_mem(mb_reply, g_mod->my_public_key, NOISE_PUBLIC_KEY_LEN);

        mbuf_set_pos(mb_reply, pos_top);

        conduit_peer_encrypted_send( cp
                                   , FRAME_TYPE_DNET
                                   , mb_reply );

        mb_reply = mem_deref( mb_reply );

        goto out;
      }
    } else if (in__type == 1) {
      /* FOUND (setup session!) */
      {
        /*  */
        if (mbuf_get_left(mb) < NOISE_PUBLIC_KEY_LEN)
          goto out; /* eproto */

        /*p = mem_deref( p );*/
        _peer_alloc( &p
                   , g_mod
                   , in__everip_src );
        if (!p) {
          error("[DNET] no p;\n");
          return 0;
        }

        /* initiate peer */
        conduit_peer_initiate( &p->cp
                             , mbuf_buf(mb)
                             , true );

      }
      goto out;
    }

    err = _peer_alloc(&p, g_mod, in__everip_src);
    if (err && err != EALREADY) {
      if (err)
        goto out;
    }

    err = conduit_incoming(g_mod->conduit, &p->cp, mb);

    if (err) {
      if (err != EALREADY) {
        p = mem_deref( p );
      }
    } else {
      memcpy(p->src, in__everip_src, EVERIP_ADDRESS_LENGTH);
    }
    goto out;
  }
  else if (in__hop > 1)
  { /* forwardable */
    struct tmp_send s;
    struct conduit_peer *cp_selected = NULL;
    struct conduits_conduit_peer_search_criteria criteria;

    memset(&criteria, 0, sizeof(criteria));

    mbuf_set_pos(mb, pos_top);

    criteria.ex.conduitv = g_mod->conduit;
    criteria.ex.conduitc = 1;

    cp_selected = conduits_conduit_peer_search( everip_conduits()
                                              , &criteria
                                              , false /* no netsearch */
                                              , in__everip_dst );
    if (cp_selected && cp_selected != cp) {
      conduit_peer_encrypted_send( cp_selected
                                 , FRAME_TYPE_DNET
                                 , mb );
    } else {
      s.mb = mb;
      s.eip_dont_fwd = cp->everip_addr;
      magi_node_apply(everip_magi(), &_magi_node_apply_h, &s);
    }   
  }

out:
  return 0;
}

static void module_destructor(void *data)
{
  struct this_module *mod = data;

  hash_flush(mod->peers_addr);
  mod->peers_addr = mem_deref( g_mod->peers_addr );

  mod->magi = mem_deref( mod->magi );

  mod->conduit = conduits_unregister( mod->conduit );
  /* are we still holding onto it? */
  if (mod->conduit)
    mod->conduit = mem_deref( mod->conduit );

}

static int module_init(void)
{
  int err = 0;

  g_mod = mem_zalloc(sizeof(*g_mod), module_destructor);
  if (!g_mod)
    return ENOMEM;

  everip_addr_copy(g_mod->my_everip);

  if (!everip_noise() || !everip_magi())
    return EINVAL;

  /* reference magi */
  g_mod->magi = everip_magi();
  mem_ref( g_mod->magi );

  memcpy(g_mod->my_public_key, everip_noise()->si.public, NOISE_PUBLIC_KEY_LEN);

  hash_alloc(&g_mod->peers_addr, 16);

  conduits_register( &g_mod->conduit
                   , everip_conduits()
                   , CONDUIT_FLAG_VIRTUAL | CONDUIT_FLAG_SECONDARY
                   , "DNET"
                   , "D-NET"
                   );

  if (!g_mod->conduit) {
    err = ENOMEM;
    goto out;
  }

  mem_ref(g_mod->conduit);

  conduit_register_search_handler( g_mod->conduit
                                 , _conduit_search
                                 , g_mod );

  conduit_register_send_handler( g_mod->conduit
                               , _conduit_sendto_virtual
                               , g_mod);


out:
  return err;
}

static int module_close(void)
{
  g_mod = mem_deref(g_mod);
  return 0;
}

const struct mod_export DECL_EXPORTS(dnet) = {
  "dnet",
  "conduit",
  module_init,
  module_close
};
