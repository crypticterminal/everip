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

#define TOL_ZONE_COUNT 1
#define TOL_ROUTE_LENGTH 16 /* 128 bytes */

struct treeoflife_peer;
struct treeoflife_csock;

struct treeoflife_zone {
  uint8_t root[EVERIP_ADDRESS_LENGTH];
  struct treeoflife_peer *parent;
  uint32_t height;

  uint8_t binlen;
  uint8_t binrep[TOL_ROUTE_LENGTH];

  struct list nodes_all;
};

struct treeoflife_peer {
  struct conduit_peer cp;

  struct treeoflife_csock *ctx;

  struct le le_peer;
  struct le le_zone[TOL_ZONE_COUNT];
  struct le le_idx_addr;

  bool is_onehop;

  /* zone */
  struct {
    uint8_t binlen;
    uint8_t binrep[TOL_ROUTE_LENGTH];
    bool is_my_child;
    uint16_t child_id;
    bool child_id_chosen;
  } z[TOL_ZONE_COUNT];
};

struct treeoflife_csock {
  struct conduit *conduit;

  struct list peers;
  struct hash *peers_addr;

  uint8_t my_everip[EVERIP_ADDRESS_LENGTH];
  struct treeoflife_zone zone[TOL_ZONE_COUNT];

  uint16_t child_counter;

};

static struct treeoflife_csock *g_tol = NULL;

static
int treeoflife_everip_for_route( struct treeoflife_csock *tol_c
                               , uint8_t routelen
                               , uint8_t route[ROUTE_LENGTH]
                               , uint8_t everip_addr[EVERIP_ADDRESS_LENGTH])
{
  int places;
  struct le *le;
  struct treeoflife_zone *zone;
  struct treeoflife_peer *peer = NULL;
  struct treeoflife_peer *peer_chosen = NULL;

  int local_diff = 0;
  int temp_diff = 0;
  int chosen_diff = 0;

  for (int i = 0; i < ZONE_COUNT; ++i) {
    zone = &tol_c->zone[i];

    local_diff = stack_linf_diff(route, zone->binrep, &places);

    info("LOCAL DIFF = %d[PLACES=%d]\n", local_diff, places);

    LIST_FOREACH(&zone->nodes_all, le) {
      peer = le->data;
      if (!peer->is_onehop)
        continue;
      temp_diff = stack_linf_diff(route, peer->z[i].binrep, &places);
      if (temp_diff == 0 && !memcmp(route, peer->z[i].binrep, ROUTE_LENGTH)) {
        memcpy(everip_addr, peer->cp.everip_addr, EVERIP_ADDRESS_LENGTH);
        return 0;
      }
      info("TEMP DIFF = %d[PLACES=%d]\n", temp_diff, places);
      if (temp_diff < local_diff) {
        if (!peer_chosen || temp_diff < chosen_diff) {
          peer_chosen = peer;
          chosen_diff = temp_diff;
        }
      }
    }
  }

  if (peer_chosen) {
    memcpy(everip_addr, peer->cp.everip_addr, EVERIP_ADDRESS_LENGTH);
    return 0;
  }

  return EADDRNOTAVAIL;
}

static uint16_t treeoflife_get_childid(struct treeoflife_csock *tol_c)
{
  uint16_t out;
  out = tol_c->child_counter;
  tol_c->child_counter = ++tol_c->child_counter % 127; /* lock to 127 for now */
  return out;
}

static void _treeoflife_command_child_cb( enum MAGI_MELCHIOR_RETURN_STATUS status
                                        , struct odict *od_sent
                                        , struct odict *od_recv
                                        , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH]
                                        , uint64_t timediff
                                        , void *userdata )
{
  if (status != MAGI_MELCHIOR_RETURN_STATUS_OK) {
    return; /* ignore for now */
  }

  info("I AM THE PARENT\n");

  return;
}

static int treeoflife_peer_send_aschild( uint16_t zoneid
                                       , struct treeoflife_peer *peer )
{
  int err = 0;
  struct odict *od = NULL;
  const struct treeoflife_zone *zone;

  if (!peer || !peer->z[zoneid].is_my_child)
    return EINVAL;

  if (zoneid >= TOL_ZONE_COUNT)
    return EINVAL;

  zone = &peer->ctx->zone[zoneid];

  /* okay, send address push */
  odict_alloc(&od, 8);

  odict_entry_add( od, "zoneid", ODICT_INT, zoneid);

  /* parent */
  odict_entry_add( od
                 , "parent_br"
                 , ODICT_STRING
                 , &(struct pl){ .p=(const char *)zone->binrep
                               , .l=ROUTE_LENGTH});

  odict_entry_add( od, "parent_bl", ODICT_INT, zone->binlen);

  /* child */
  if (!peer->z[zoneid].child_id_chosen) {
    peer->z[zoneid].child_id_chosen = true;
    peer->z[zoneid].child_id = treeoflife_get_childid(peer->ctx);
  }

  memcpy(peer->z[zoneid].binrep, zone->binrep, ROUTE_LENGTH);
  peer->z[zoneid].binlen = stack_layer_add( peer->z[zoneid].binrep
                                          , peer->z[zoneid].child_id );

  odict_entry_add( od
                 , "child_br"
                 , ODICT_STRING
                 , &(struct pl){ .p=(const char *)peer->z[zoneid].binrep
                               , .l=ROUTE_LENGTH});

  odict_entry_add( od, "child_bl", ODICT_INT, peer->z[zoneid].binlen);

  err = magi_melchior_send( everip_magi_melchior()
                          , od
                          , &(struct pl)PL("tree.child")
                          , peer->cp.everip_addr
                          , 5000
                          , false /* is not routable */
                          , _treeoflife_command_child_cb
                          , peer->ctx );

  od = mem_deref(od);

  return 0;
}

/* x:s update */

static void _treeoflife_command_update_cb( enum MAGI_MELCHIOR_RETURN_STATUS status
                                        , struct odict *od_sent
                                        , struct odict *od_recv
                                        , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH]
                                        , uint64_t timediff
                                        , void *userdata )
{
  /* we could use this in the future as a pickup for node health... */
  return;
}

static int treeoflife_peer_send_update( uint16_t zoneid
                                      , struct treeoflife_peer *peer )
{
  int err = 0;
  struct odict *od = NULL;
  const struct treeoflife_zone *zone;

  if (!peer || !peer->is_onehop)
    return EINVAL;

  if (zoneid >= TOL_ZONE_COUNT)
    return EINVAL;

  zone = &peer->ctx->zone[zoneid];

  /* okay, send address push */
  odict_alloc(&od, 8);

  odict_entry_add( od, "zoneid", ODICT_INT, zoneid);

  /* parent */
  odict_entry_add( od
                 , "br"
                 , ODICT_STRING
                 , &(struct pl){ .p=(const char *)zone->binrep
                               , .l=ROUTE_LENGTH});

  odict_entry_add( od, "bl", ODICT_INT, zone->binlen);

  err = magi_melchior_send( everip_magi_melchior()
                          , od
                          , &(struct pl)PL("tree.update")
                          , peer->cp.everip_addr
                          , 5000
                          , false /* is not routable */
                          , _treeoflife_command_update_cb
                          , peer->ctx );

  od = mem_deref(od);

  return 0;
}

/* x:e update */

static bool _treeoflife_peer_lookup_addr(struct le *le, void *arg)
{
  struct treeoflife_peer *peer = le->data;
  return 0 == memcmp(peer->cp.everip_addr, (uint8_t *)arg, EVERIP_ADDRESS_LENGTH);
}

static inline
struct treeoflife_peer *_treeoflife_peer_lookup( struct treeoflife_csock *tol_c
                                               , const uint8_t my_everip[EVERIP_ADDRESS_LENGTH] )
{
  return list_ledata(hash_lookup( tol_c->peers_addr
                                , *(uint32_t *)(void *)my_everip
                                , _treeoflife_peer_lookup_addr
                                , (void *)my_everip));
}

static void peer_destructor(void *data)
{
  struct treeoflife_peer *peer = data;

  list_unlink(&peer->le_peer);
  list_unlink(&peer->le_idx_addr);

  for (int i = 0; i < TOL_ZONE_COUNT; ++i)
  {
    if (peer->ctx->zone[i].parent == peer) {
      peer->ctx->zone[i].parent = NULL;
    }
    list_unlink(&peer->le_zone[i]);
  }

}

static int _treeoflife_peer_create( struct treeoflife_peer **peerp
                                  , struct treeoflife_csock *tol_c
                                  , const uint8_t my_everip[EVERIP_ADDRESS_LENGTH] )
{
  struct treeoflife_peer *peer = NULL;

  if (!peerp || !tol_c || !my_everip)
    return EINVAL;

  peer = _treeoflife_peer_lookup(tol_c, my_everip);

  if (peer) {
    *peerp = peer;
    return EALREADY;
  }

  peer = mem_zalloc(sizeof(*peer), peer_destructor);
  if (!peer)
    return ENOMEM;

  peer->ctx = tol_c;

  memcpy(peer->cp.everip_addr, my_everip, EVERIP_ADDRESS_LENGTH);
  peer->cp.conduit = tol_c->conduit;

  list_append(&tol_c->peers, &peer->le_peer, peer);
  hash_append( tol_c->peers_addr
             , *(uint32_t *)(void *)my_everip
             , &peer->le_idx_addr
             , peer);

  *peerp = peer;

  return 0;
}

static bool _peer_debug(struct le *le, void *arg)
{
  struct re_printf *pf = arg;
  return false;
}

static int _conduit_debug(struct re_printf *pf, void *arg)
{
  int err = 0;
  struct le *le;
  const struct treeoflife_zone *zone;
  struct treeoflife_peer *peer = NULL;
  struct treeoflife_csock *tol_c = arg;

  err |= re_hprintf(pf, "→ EVERIP:[%W]\n", tol_c->my_everip, EVERIP_ADDRESS_LENGTH);

  for (int i = 0; i < TOL_ZONE_COUNT; ++i)
  {
    zone = &tol_c->zone[i];
    err |= re_hprintf(pf, "→ ZONE[%i][ROOTID:%W]\n", i, zone->root, EVERIP_ADDRESS_LENGTH);
    if (zone->parent) {
      err |= re_hprintf(pf, "→ ZONE[%i][PARENT:%W]\n", i, zone->parent->cp.everip_addr, EVERIP_ADDRESS_LENGTH);
    }
    err |= re_hprintf(pf, "→ ZONE[%i][HEIGHT:%u]\n", i, zone->height);
    err |= re_hprintf(pf, "→ ZONE[%i][COORDS:%u;%H]\n", i, zone->binlen, stack_debug, zone->binrep);

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

  }

  return err;
}

static int _peer_create( struct conduit_peer **peerp
                       , struct pl *key
                       , struct pl *host
                       , void *arg )
{

  (void)key;
  (void)host;
  (void)arg;

  *peerp = NULL;

  return 0;
}

static int treeoflife_command_cb_update( struct treeoflife_csock *tol_c
                                       , struct magi_melchior_rpc *rpc )
{
  int err = 0;
  const struct odict_entry *ode;
  struct treeoflife_peer *peer = NULL;
  struct treeoflife_zone *zone = NULL;

  uint16_t tmp_zoneid;
  uint8_t *tmp_br;
  uint16_t tmp_bl;

  if (!tol_c || !rpc)
    return EINVAL;

  /* we should already have the peer */
  peer = _treeoflife_peer_lookup(tol_c, rpc->everip_addr);
  if (!peer)
    return EPROTO;

  /* make sure that we already ack that this is a onehop */
  if (!peer->is_onehop)
    return EPROTO;

  /*
    [X] zoneid
    [X] br
    [X] bl
  */

  ode = odict_lookup(rpc->in, "zoneid");
  if (!ode || ode->type != ODICT_INT) {
    err = EPROTO;
    goto out;
  }

  tmp_zoneid = (uint16_t)ode->u.integer;

  if (tmp_zoneid >= TOL_ZONE_COUNT) {
    err = EPROTO;
    goto out;
  }

  zone = &tol_c->zone[tmp_zoneid];

  ode = odict_lookup(rpc->in, "br");
  if (!ode || ode->type != ODICT_STRING) {
    err = EPROTO;
    goto out;
  }

  if (ode->u.pl.l != TOL_ROUTE_LENGTH) {
    err = EPROTO;
    goto out;
  }

  tmp_br = (uint8_t *)ode->u.pl.p;

  ode = odict_lookup(rpc->in, "bl");
  if (!ode || ode->type != ODICT_INT) {
    err = EPROTO;
    goto out;
  }

  tmp_bl = (uint16_t)ode->u.integer;

  /**/

  info("UPDATE COORDS FOR [%W->%H]\n", rpc->everip_addr, EVERIP_ADDRESS_LENGTH, stack_debug, tmp_br);
  peer->z[tmp_zoneid].binlen = tmp_bl;
  memcpy(peer->z[tmp_zoneid].binrep, tmp_br, TOL_ROUTE_LENGTH);

out:
  return err;
}

static int treeoflife_command_cb_child( struct treeoflife_csock *tol_c
                                      , struct magi_melchior_rpc *rpc )
{
  int err = 0;
  struct le *le;
  const struct odict_entry *ode;
  struct treeoflife_peer *peer = NULL;
  struct treeoflife_zone *zone = NULL;

  uint16_t tmp_zoneid;
  uint8_t *tmp_parent_br;
  uint16_t tmp_parent_bl;
  uint8_t *tmp_child_br;
  uint16_t tmp_child_bl;

  info("I AM THE CHILD\n");

  if (!tol_c || !rpc)
    return EINVAL;

  /* we should already have the peer */
  peer = _treeoflife_peer_lookup(tol_c, rpc->everip_addr);
  if (!peer)
    return EPROTO;

  /* here we need to set our coord from the parent */

  /*
    [X] zoneid
    [X] parent_br
    [X] parent_bl
    [X] child_br
    [X] child_bl
  */

  ode = odict_lookup(rpc->in, "zoneid");
  if (!ode || ode->type != ODICT_INT) {
    err = EPROTO;
    goto out;
  }

  tmp_zoneid = (uint16_t)ode->u.integer;

  if (tmp_zoneid >= TOL_ZONE_COUNT) {
    err = EPROTO;
    goto out;
  }

  zone = &tol_c->zone[tmp_zoneid];

  /* check that we actually recieved this message from our parrent */
  if (zone->parent != peer)
    return EPROTO;

  ode = odict_lookup(rpc->in, "parent_br");
  if (!ode || ode->type != ODICT_STRING) {
    err = EPROTO;
    goto out;
  }

  if (ode->u.pl.l != TOL_ROUTE_LENGTH) {
    err = EPROTO;
    goto out;
  }

  tmp_parent_br = (uint8_t *)ode->u.pl.p;

  ode = odict_lookup(rpc->in, "parent_bl");
  if (!ode || ode->type != ODICT_INT) {
    err = EPROTO;
    goto out;
  }

  tmp_parent_bl = (uint16_t)ode->u.integer;

  ode = odict_lookup(rpc->in, "child_br");
  if (!ode || ode->type != ODICT_STRING) {
    err = EPROTO;
    goto out;
  }

  if (ode->u.pl.l != TOL_ROUTE_LENGTH) {
    err = EPROTO;
    goto out;
  }

  tmp_child_br = (uint8_t *)ode->u.pl.p;

  ode = odict_lookup(rpc->in, "child_bl");
  if (!ode || ode->type != ODICT_INT) {
    err = EPROTO;
    goto out;
  }

  tmp_child_bl = (uint16_t)ode->u.integer;

  /**/

  info("ZONE[%u]BINREP[%H]\n", tmp_zoneid, stack_debug, tmp_parent_br);
  zone->parent->z[tmp_zoneid].binlen = tmp_parent_bl;
  memcpy(zone->parent->z[tmp_zoneid].binrep, tmp_parent_br, TOL_ROUTE_LENGTH);

  info("MY BINREP[%H]\n", stack_debug, tmp_child_br);
  zone->binlen = tmp_child_bl;
  memcpy(zone->binrep, tmp_child_br, TOL_ROUTE_LENGTH);

  /* notify children, if we have any! */
  {
    struct treeoflife_peer *_p;
    LIST_FOREACH(&zone->nodes_all, le) {
      _p = le->data;
      if (_p->z[tmp_zoneid].is_my_child) {
        treeoflife_peer_send_aschild(tmp_zoneid, _p);
      } else if (_p->is_onehop) {
        treeoflife_peer_send_update(tmp_zoneid, _p);
      }
    }
  }

out:
  return err;
}

static void _treeoflife_command_zone_cb( enum MAGI_MELCHIOR_RETURN_STATUS status
                                       , struct odict *od_sent
                                       , struct odict *od_recv
                                       , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH]
                                       , uint64_t timediff
                                       , void *userdata )
{
  int err = 0;
  struct odict *od = NULL;
  const struct odict_entry *ode;
  struct treeoflife_peer *peer = NULL;
  struct treeoflife_csock *tol_c = userdata;
  struct treeoflife_zone *zone = &tol_c->zone[0];

  if (status != MAGI_MELCHIOR_RETURN_STATUS_OK) {
    return; /* ignore for now */
  }

  ode = odict_lookup(od_recv, "am_child");
  if (!ode || ode->type != ODICT_INT) {
    goto out;
  }

  /* lookup or create peer */
  err = _treeoflife_peer_create(&peer, tol_c, everip_addr);
  if (err == EALREADY)
    err = 0;
  if (err)
    goto out;

  list_unlink(&peer->le_zone[0]);
  list_append(&zone->nodes_all, &peer->le_zone[0], peer);

  if ( ode->u.integer ) {
    info("TREE: [%W] is my child!\n", everip_addr, EVERIP_ADDRESS_LENGTH);

    peer->z[0].is_my_child = true;

    err = treeoflife_peer_send_aschild( 0, peer );
    if (err)
      goto out;

  } else {
    info("TREE: [%W] is NOT my child!\n", everip_addr, EVERIP_ADDRESS_LENGTH);
    peer->z[0].is_my_child = false;
  }

out:
  od = mem_deref(od);
  return;
}

static int treeoflife_command_send_zone( struct treeoflife_csock *tol_c
                                       , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH] )
{
  int err = 0;
  struct odict *od = NULL;

  odict_alloc(&od, 8);

  odict_entry_add( od, "zone", ODICT_INT, 0);
  odict_entry_add( od
                 , "root"
                 , ODICT_STRING
                 , &(struct pl){ .p=(const char *)tol_c->zone[0].root
                               , .l=EVERIP_ADDRESS_LENGTH});

  if (tol_c->zone[0].parent) {
    odict_entry_add( od
                   , "parent"
                   , ODICT_STRING
                   , &(struct pl){ .p=(const char *)tol_c->zone[0].parent->cp.everip_addr
                                 , .l=EVERIP_ADDRESS_LENGTH});
  } else {
    odict_entry_add( od
                   , "parent"
                   , ODICT_STRING
                   , &(struct pl){ .p="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                 , .l=EVERIP_ADDRESS_LENGTH});
  }

  odict_entry_add(od, "height", ODICT_INT, tol_c->zone[0].height);

  err = magi_melchior_send( everip_magi_melchior()
                          , od
                          , &(struct pl)PL("tree.zone")
                          , everip_addr
                          , 5000
                          , false /* is not routable */
                          , _treeoflife_command_zone_cb
                          , tol_c );

  od = mem_deref(od);

  return err;
}

/* IN: zone, parent, height, root */
static int treeoflife_command_cb_zone( struct treeoflife_csock *tol_c
                                     , struct magi_melchior_rpc *rpc )
{
  int err = 0;
  uint16_t weight = 1;
  struct treeoflife_peer *peer = NULL;
  struct treeoflife_zone *zone = &tol_c->zone[0];

  uint8_t *tmp_rootp;
  uint16_t tmp_height;
  uint8_t *tmp_parentp;

  int rootcmp;
  const struct odict_entry *ode;

  /* get all of our items */
  ode = odict_lookup(rpc->in, "zone");
  if (!ode || ode->type != ODICT_INT) {
    err = EPROTO;
    goto out;
  }

  if (ode->u.integer != 0) {
    err = EPROTO;
    goto out;
  }

  ode = odict_lookup(rpc->in, "height");
  if (!ode || ode->type != ODICT_INT) {
    err = EPROTO;
    goto out;
  }

  tmp_height = (uint16_t)ode->u.integer;

  ode = odict_lookup(rpc->in, "root");
  if (!ode || ode->type != ODICT_STRING) {
    err = EPROTO;
    goto out;
  }

  /* root must be same as everip address */
  if (ode->u.pl.l != EVERIP_ADDRESS_LENGTH) {
    err = EPROTO;
    goto out;
  } 

  tmp_rootp = (uint8_t *)ode->u.pl.p;

  ode = odict_lookup(rpc->in, "parent");
  if (!ode || ode->type != ODICT_STRING) {
    err = EPROTO;
    goto out;
  }

  /* parent must be same as everip address */
  if (ode->u.pl.l != EVERIP_ADDRESS_LENGTH) {
    err = EPROTO;
    goto out;
  } 

  tmp_parentp = (uint8_t *)ode->u.pl.p;  

  /* begin calculation */
  /*we_are_set_parent = !memcmp(tmp_parentp, tol_c->my_everip, EVERIP_ADDRESS_LENGTH);*/
  rootcmp = memcmp(tmp_rootp, zone->root, EVERIP_ADDRESS_LENGTH);

  /* lookup or create peer */
  err = _treeoflife_peer_create(&peer, tol_c, rpc->everip_addr);
  if (err == EALREADY)
    err = 0;
  if (err)
    goto out;

  peer->is_onehop = true;

  /* join chain check: */
  if ( (rootcmp > 0) || (!rootcmp && tmp_height + weight < zone->height) )
  {
    memcpy(zone->root, tmp_rootp, EVERIP_ADDRESS_LENGTH);
    zone->height = tmp_height + weight;

    if (zone->parent) {
      /* do destruct here? */
    }

    zone->parent = peer;

    odict_entry_add(rpc->out, "am_child", ODICT_INT, 1);

    /*memcpy(zone->parent, rpc->everip_addr, EVERIP_ADDRESS_LENGTH);*/
    /* we should update parents here.. */
  } else {
    bool you_are_my_parent = false;
    if (zone->parent && !memcmp( zone->parent->cp.everip_addr
                               , rpc->everip_addr
                               , EVERIP_ADDRESS_LENGTH)) {
      you_are_my_parent = true;
    }
    odict_entry_add(rpc->out, "am_child", ODICT_INT, you_are_my_parent ? 1 : 0);
  }

out:
  return err;
}

static int treeoflife_command_callback( struct magi_melchior_rpc *rpc
                                      , struct pl *method
                                      , void *arg )
{
  struct treeoflife_csock *tol_c = arg;

  if (!rpc || !tol_c || !method)
    return EINVAL;

  info("treeoflife_command_callback: [%b]\n", method->p, method->l);

  switch (method->l) {
    case 4:
      /* zone */
      if (!memcmp(method->p, "zone", 4))
      {
        return treeoflife_command_cb_zone(tol_c, rpc);
      }
    case 5:
      /* child */
      if (!memcmp(method->p, "child", 5))
      {
        return treeoflife_command_cb_child(tol_c, rpc);
      }
    case 6:
      /* update */
      if (!memcmp(method->p, "update", 6))
      {
        return treeoflife_command_cb_update(tol_c, rpc);
      }
    default:
      return EPROTO;
  }
  /* failsafe */
  return EPROTO;
}

static int magi_event_watcher_h( enum MAGI_EVENTDRIVER_WATCH type
                               , void *data
                               , void *arg )
{
  struct magi_e2e_event *event = data;
  struct treeoflife_csock *tol_c = arg;

  if (!tol_c || !event || type != MAGI_EVENTDRIVER_WATCH_E2E)
    return 0;

  switch (event->status) {
    case MAGI_NODE_STATUS_OFFLINE:
    case MAGI_NODE_STATUS_SEARCHING:
      debug("TREEOFLIFE: node [%W] has gone offline!\n", event->everip_addr, EVERIP_ADDRESS_LENGTH);
      break;
    case MAGI_NODE_STATUS_OPERATIONAL:
      debug("TREEOFLIFE: node [%W] is now operational!\n", event->everip_addr, EVERIP_ADDRESS_LENGTH);
      treeoflife_command_send_zone(tol_c, event->everip_addr);
      break;
    default:
      break;
  }

  return 0;
}

static void treeoflife_destructor(void *data)
{
  struct treeoflife_csock *tol_c = data;
  hash_flush( tol_c->peers_addr );
  tol_c->peers_addr = mem_deref( tol_c->peers_addr );

}

static int module_init(void)
{
  int err = 0;
  struct conduit *conduit = NULL;

  g_tol = mem_zalloc(sizeof(*g_tol), treeoflife_destructor);
  if (!g_tol)
    return ENOMEM;

  hash_alloc(&g_tol->peers_addr, 16);

  everip_addr_copy(g_tol->my_everip);

  for (int i = 0; i < TOL_ZONE_COUNT; ++i)
  {
    memcpy(g_tol->zone[i].root, g_tol->my_everip, EVERIP_ADDRESS_LENGTH);
    g_tol->zone[i].binlen = 1;
    memset(g_tol->zone[i].binrep, 0, TOL_ROUTE_LENGTH);
  }

  /* register with the system */
  err = magi_melchior_register( everip_magi_melchior()
                              , (void *)"tree"
                              , treeoflife_command_callback
                              , g_tol );
  if (err) {
    error("treeoflife: magi_melchior_register\n");
    goto out;
  }

  conduits_register( &conduit
                   , everip_conduits()
                   , CONDUIT_FLAG_VIRTUAL
                   , "TREE"
                   , "Tree of Life"
                   );

  if (!conduit)
    return ENOMEM;

  conduit_register_peer_create( conduit
                              , _peer_create
                              , NULL);

  conduit_register_debug_handler( conduit
                                , _conduit_debug
                                , g_tol );


  err = magi_eventdriver_handler_register( everip_eventdriver()
                                         , MAGI_EVENTDRIVER_WATCH_E2E
                                         , magi_event_watcher_h
                                         , g_tol );
  if (err) {
    error("treeoflife: magi_eventdriver_handler_register\n");
    goto out;
  }

  g_tol->conduit = conduit;

out:
  if (err) {
    g_tol = mem_deref(g_tol);
  }
  return err;
}

static int module_close(void)
{
  g_tol = mem_deref(g_tol);
  return 0;
}

const struct mod_export DECL_EXPORTS(treeoflife) = {
  "treeoflife",
  "conduit",
  module_init,
  module_close
};
