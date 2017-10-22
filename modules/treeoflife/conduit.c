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

#include "tol.h"

/**/

static bool tol_peer_lookup_byeverip_h(struct le *le, void *arg)
{
  struct tol_peer *peer = le->data;
  return 0 == memcmp(peer->cp.everip_addr, (uint8_t *)arg, EVERIP_ADDRESS_LENGTH);
}

struct tol_peer *tol_peer_lookup_byeverip( struct this_module *mod
                                         , const uint8_t everip[EVERIP_ADDRESS_LENGTH] )
{
  return list_ledata(hash_lookup( mod->peers_addr
                                , *(uint32_t *)(void *)everip
                                , &tol_peer_lookup_byeverip_h
                                , (void *)everip));
}

static void tol_peer_destructor(void *data)
{
  struct tol_peer *tp = data;

  /* x:start process cp */
  conduit_peer_deref(&tp->cp);
  /* x:end process cp */

  list_unlink(&tp->le_mod);
  list_unlink(&tp->le_mod_addr);
}

int tol_peer_alloc( struct tol_peer **tpp
                  , struct this_module *mod
                  , const uint8_t everip[EVERIP_ADDRESS_LENGTH] )
{
  int err = 0;
  struct tol_peer *tp = NULL;

  if (!tpp || !mod || !everip)
    return EINVAL;

  tp = tol_peer_lookup_byeverip(mod, everip);

  if (tp) {
    *tpp = tp;
    return EALREADY;
  }

  tp = mem_zalloc(sizeof(*tp), tol_peer_destructor);
  if (!tp)
    return ENOMEM;

  tp->ctx = mod;

  memcpy(tp->cp.everip_addr, everip, EVERIP_ADDRESS_LENGTH);
  tp->cp.conduit = mod->conduit;

  err = conduit_peer_initiate( &tp->cp
                             , NULL /* no key */
                             , false /* no handshake */
                             );
  if (err)
    goto out;

  list_append( &mod->peers, &tp->le_mod, tp);
  hash_append( mod->peers_addr
             , *(uint32_t *)(void *)everip
             , &tp->le_mod_addr
             , tp);

out:
  if (err) {
    tp = mem_deref(tp);
  } else {
    *tpp = tp;
  }
  return err;
}

/**/

int tol_conduit_debug(struct re_printf *pf, void *arg)
{
  int err = 0;
  const struct tol_zone *zone;
  struct this_module *mod = arg;

  /*err |= re_hprintf(pf, "→ EVERIP:[%W]\n", tol_c->my_everip, EVERIP_ADDRESS_LENGTH);*/

  for (int i = 0; i < TOL_ZONE_COUNT; ++i)
  {
    zone = &mod->zone[i];
    err |= re_hprintf(pf, "→ ZONE[%i][ROOTID:%W]\n", i, zone->root, EVERIP_ADDRESS_LENGTH);
    if (zone->parent) {
      err |= re_hprintf(pf, "→ ZONE[%i][PARENT:%W]\n", i, zone->parent->everip, EVERIP_ADDRESS_LENGTH);
    }
    err |= re_hprintf(pf, "→ ZONE[%i][HEIGHT:%u]\n", i, zone->binlen);
    err |= re_hprintf(pf, "→ ZONE[%i][COORDS:%u;%H]\n", i, zone->binlen, stack_debug, zone->binrep);

#if 0
    LIST_FOREACH(&zone->nodes_all, le) {
      peer = le->data;
      if (!peer->z[i].is_my_child)
        continue;
      err |= re_hprintf(pf, "→ ZONE[%i][CHILD:%W][%u@%H]\n", i, peer->cp.everip_addr, EVERIP_ADDRESS_LENGTH, peer->z[i].binlen, stack_debug, peer->z[i].binrep);
    }

    LIST_FOREACH(&zone->nodes_all, le) {
      peer = le->data;
      if (peer->z[i].is_my_child || !peer->is_onehop)
        continue;
      err |= re_hprintf(pf, "→ ZONE[%i][LOCAL:%W][%u@%H]\n", i, peer->cp.everip_addr, EVERIP_ADDRESS_LENGTH, peer->z[i].binlen, stack_debug, peer->z[i].binrep);
    }

    /* dhti */
    LIST_FOREACH(&zone->dhti_all, le) {
      dhti = le->data;
      err |= re_hprintf(pf, "→ ZONE[%i][DHASH:%W][%u@%H][LEFT:%u]\n", i, dhti->everip_addr, EVERIP_ADDRESS_LENGTH, dhti->binlen, stack_debug, dhti->binrep, tmr_get_expire(&dhti->tmr));
    }
#endif

  }

  return err;
}

int tol_conduit_search( const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH]
                      , void *arg )
{
  struct le *le;
  struct tol_dhti *dhti = NULL;
  struct tol_peer *tp = NULL;
  struct this_module *mod = arg;
  struct tol_zone *zone = &mod->zone[0];

  if (!everip_addr || !mod)
    return EINVAL;

  if (!zone->active) {
    error( "[TREE] tol_conduit_search :: zone not active!\n");
    return 0;
  }
  error("treeoflife: _conduit_search !!\n");

  /* is it inside of our dht? */
  LIST_FOREACH(&zone->dhti_all, le) {
    dhti = le->data;
    if (!memcmp(dhti->everip_addr, everip_addr, EVERIP_ADDRESS_LENGTH)) {
      break;
    }
    dhti = NULL;
  }

  if (dhti) {
    info("FOUND KEY: %W\n", dhti->public_key, NOISE_PUBLIC_KEY_LEN);
    info("FOUND ROUTE: %H\n", stack_debug, dhti->binrep);

    /* create new peer */
    tol_peer_alloc( &tp
                  , mod
                  , dhti->everip_addr );
    if (!tp) {
      error("[TREE] no tp;\n");
      return 0;
    }

    tp->zoneid = 0;
    tp->binlen = dhti->binlen;
    memcpy(tp->binrep, dhti->binrep, TOL_ROUTE_LENGTH);

    /* initiate peer */
    conduit_peer_initiate( &tp->cp
                         , dhti->public_key
                         , true );

    if (zone->parent) {
      /* we can re-request this later */
      /* x:todo this should be refreshed anyways if we get a network change? */
      dhti = mem_deref(dhti);
    }
    return 0;
  }

  if (!zone->parent)
    return 0;

  tol_command_send_dht_aquire( zone->parent->everip
                             , everip_addr
                             , 0
                             , zone->root
                             , zone->binrep
                             , zone->binlen );

  return 0;
}

int tol_conduit_sendto_virtual( struct conduit_peer *peer
                              , struct mbuf *mb
                              , void *arg )
{
  int err = 0;
  size_t pos_top;
  struct tol_peer *tp = NULL;
  struct tol_zone *zone = NULL;
  struct this_module *mod = arg;
  uint8_t everip_addr_route[EVERIP_ADDRESS_LENGTH];

  tp = container_of(peer, struct tol_peer, cp);

  if (!tp || !mod)
    return EINVAL;

  zone = &mod->zone[0];

  if (!zone->active) {
    error( "[TREE] tol_conduit_sendto_virtual :: zone not active!\n");
    goto out;
  }

  warning( "VIRTUAL REQUEST TO [%W]@[%H] from [%H]\n"
       , peer->everip_addr
       , EVERIP_ADDRESS_LENGTH
       , stack_debug
       , tp->binrep
       , stack_debug
       , zone->binrep
       );

  if (tol_everip_for_route( mod
                          , tp->binrep
                          , everip_addr_route ))
    goto out;

  warning( "ROUTING REQUEST VIA [%W]\n"
       , everip_addr_route
       , EVERIP_ADDRESS_LENGTH );

  /* form packet for request */
  /*
  [VERSION(1)][EVERIP_DST(16)][EVERIP_SRC(16)][ZONEID(1)][ROOTID(16)][DST_BINLEN(1)]
  [DST_BINROUTE(ROUTE_LENGTH)][SRC_BINLEN(1)][SRC_BINROUTE(ROUTE_LENGTH)]
  */

  mbuf_advance(mb, -(ssize_t)(1+EVERIP_ADDRESS_LENGTH+EVERIP_ADDRESS_LENGTH+1+EVERIP_ADDRESS_LENGTH+1+TOL_ROUTE_LENGTH+1+TOL_ROUTE_LENGTH));

  pos_top = mb->pos;

  /* version 1 */
  mbuf_write_u8(mb, TOL_VERSION_ID);

  /* everip address DST */
  mbuf_write_mem(mb, peer->everip_addr, EVERIP_ADDRESS_LENGTH);

  /* everip address SRC */
  mbuf_write_mem(mb, mod->my_everip, EVERIP_ADDRESS_LENGTH);

  /* zone */
  mbuf_write_u8(mb, 0); /* zone 0 only for now */

  /* root id */
  mbuf_write_mem(mb, zone->root, EVERIP_ADDRESS_LENGTH);

  /* dst */
  mbuf_write_u8(mb, tp->binlen);
  mbuf_write_mem(mb, tp->binrep, TOL_ROUTE_LENGTH);

  /* src */
  mbuf_write_u8(mb, zone->binlen);
  mbuf_write_mem(mb, zone->binrep, TOL_ROUTE_LENGTH);

  mbuf_set_pos(mb, pos_top);

  {
    struct conduit_peer *cp_selected = NULL;
    struct conduits_conduit_peer_search_criteria criteria;
    memset(&criteria, 0, sizeof(criteria));

    criteria.ex.conduitv = peer->conduit;
    criteria.ex.conduitc = 1;

    cp_selected = conduits_conduit_peer_search( everip_conduits()
                                              , &criteria
                                              , false /* no netsearch */
                                              , everip_addr_route );
    if (!cp_selected)
      goto out;

    conduit_peer_encrypted_send( cp_selected
                               , FRAME_TYPE_TREEOFLIFE
                               , mb );
  }

out:
  return err;
}

int tol_conduit_incoming( struct this_module *mod, struct conduit_peer *cp, struct mbuf *mb )
{
  int err = 0;
  size_t pos_top;
  uint8_t in__ver;
  uint8_t in__zoneid;
  uint8_t *in__rootidp;
  uint8_t in__everip_dst[EVERIP_ADDRESS_LENGTH];
  uint8_t in__everip_src[EVERIP_ADDRESS_LENGTH];
  uint8_t in__dst_binlen;
  uint8_t in__dst_binrep[TOL_ROUTE_LENGTH];
  uint8_t in__src_binlen;
  uint8_t in__src_binrep[TOL_ROUTE_LENGTH];

  struct tol_zone *zone = NULL;
  struct tol_peer *tp = NULL;
  uint8_t everip_addr_route[EVERIP_ADDRESS_LENGTH] = {0};

  if (!mod)
    return EINVAL;

  /*error("tol: [%u][%W]\n", mbuf_get_left(mb), mbuf_buf(mb), mbuf_get_left(mb));*/

  /*
  [VERSION(1)][EVERIP_DST(16)][EVERIP_SRC(16)][ZONEID(1)][ROOTID(16)][DST_BINLEN(1)]
  [DST_BINROUTE(ROUTE_LENGTH)][SRC_BINLEN(1)][SRC_BINROUTE(ROUTE_LENGTH)]
  */

  if (mbuf_get_left(mb) < (1+EVERIP_ADDRESS_LENGTH+EVERIP_ADDRESS_LENGTH+1+EVERIP_ADDRESS_LENGTH+1+TOL_ROUTE_LENGTH+1+TOL_ROUTE_LENGTH))
    goto out; /* eproto */

  pos_top = mb->pos;

  in__ver = mbuf_read_u8(mb);

  if (in__ver != TOL_VERSION_ID)
    goto out;

  mbuf_read_mem(mb, in__everip_dst, EVERIP_ADDRESS_LENGTH);
  if (in__everip_dst[0] != 0xFC)
    goto out;

  mbuf_read_mem(mb, in__everip_src, EVERIP_ADDRESS_LENGTH);
  if (in__everip_src[0] != 0xFC)
    goto out;

  in__zoneid = mbuf_read_u8(mb);
  if (in__zoneid >= TOL_ZONE_COUNT)
    goto out;

  zone = &mod->zone[in__zoneid];

  /* rootid */
  in__rootidp = mbuf_buf(mb);
  mbuf_advance(mb, EVERIP_ADDRESS_LENGTH);

  in__dst_binlen = mbuf_read_u8(mb);
  mbuf_read_mem(mb, in__dst_binrep, TOL_ROUTE_LENGTH);

  in__src_binlen = mbuf_read_u8(mb);
  mbuf_read_mem(mb, in__src_binrep, TOL_ROUTE_LENGTH);

#if 1
  warning( "[TREE][ROUTE][v%u] [%W][%u@%H] -> [%W][%u@%H] ? %u@%H\n"
       , in__ver
       , in__everip_src, (size_t)EVERIP_ADDRESS_LENGTH
       , in__src_binlen, stack_debug, in__src_binrep
       , in__everip_dst, (size_t)EVERIP_ADDRESS_LENGTH
       , in__dst_binlen, stack_debug, in__dst_binrep
       , zone->binlen, stack_debug, zone->binrep
       );
#endif

  if (memcmp(zone->root, in__rootidp, EVERIP_ADDRESS_LENGTH)) {
    warning("[TREE] DROP; Packet from invalid rootid\n");
    goto out;
  }

  /* determine if we need to forward or eat the packet */
  if ( !memcmp(mod->my_everip, in__everip_dst, EVERIP_ADDRESS_LENGTH)) {

    err = tol_peer_alloc(&tp, mod, in__everip_src);
    if (err != EALREADY) {
      if (err)
        goto out;
      /* new peer, so binlen/rep from packet */
      tp->zoneid = in__zoneid;
      tp->binlen = in__src_binlen;
      memcpy(tp->binrep, in__src_binrep, TOL_ROUTE_LENGTH);
    }

    err = conduit_incoming(mod->conduit, &tp->cp, mb);

    if (err) {
      if (err != EALREADY) {
        tp = mem_deref( tp );
      }
    } else {
      /* update peer if need be */
      tp->zoneid = in__zoneid;
      tp->binlen = in__src_binlen;
      memcpy(tp->binrep, in__src_binrep, TOL_ROUTE_LENGTH);
    }
    goto out;
  }
  else
  { /* forwardable */
    struct conduit_peer *cp_selected = NULL;
    struct conduits_conduit_peer_search_criteria criteria;
    memset(&criteria, 0, sizeof(criteria));

    criteria.ex.conduitv = mod->conduit;
    criteria.ex.conduitc = 1;

    cp_selected = conduits_conduit_peer_search( everip_conduits()
                                              , &criteria
                                              , false /* no netsearch */
                                              , in__everip_dst );

    if (!cp_selected) {

      if (tol_everip_for_route(mod, in__dst_binrep, everip_addr_route))
        goto out;

      warning( "ROUTING REQUEST VIA [%W]\n"
             , everip_addr_route
             , EVERIP_ADDRESS_LENGTH );

      cp_selected = conduits_conduit_peer_search( everip_conduits()
                                                , &criteria
                                                , false /* no netsearch */
                                                , everip_addr_route );

      if (!cp_selected) {
        goto out;
      }
    }

    mbuf_set_pos(mb, pos_top);

    conduit_peer_encrypted_send( cp_selected
                               , FRAME_TYPE_TREEOFLIFE
                               , mb );

  }

out:
  return 0;
}



