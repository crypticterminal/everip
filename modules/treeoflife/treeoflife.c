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

  struct le le_peer;
  struct le le_zone[TOL_ZONE_COUNT];
  struct le le_idx_addr;

  uint8_t binlen;
  uint8_t binrep[TOL_ROUTE_LENGTH];

};

struct treeoflife_csock {
  struct conduit *conduit;

  struct list peers;
  struct hash *peers_addr;

  uint8_t my_everip[EVERIP_ADDRESS_LENGTH];
  struct treeoflife_zone zone[TOL_ZONE_COUNT];
};

static struct treeoflife_csock *g_tol = NULL;

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
  const struct treeoflife_zone *zone;
  struct treeoflife_csock *tol_c = arg;

  err |= re_hprintf(pf, "→ EVER[IP][%W]\n", tol_c->my_everip, EVERIP_ADDRESS_LENGTH);

  for (int i = 0; i < ZONE_COUNT; ++i)
  {
    zone = &tol_c->zone[i];
    err |= re_hprintf(pf, "→ ZONE[%i][ROOTID:%W]\n", i, zone->root, EVERIP_ADDRESS_LENGTH);
    if (zone->parent) {
      err |= re_hprintf(pf, "→ ZONE[%i][PARENT:%W]\n", i, zone->parent->cp.everip_addr, EVERIP_ADDRESS_LENGTH);
    }
    err |= re_hprintf(pf, "→ ZONE[%i][HEIGHT:%u]\n", i, zone->height);
#if 0
    if (zone->parent) {
      err |= re_hprintf(pf, "  PARENT[%W]\n", zone->parent->key, EVERIP_ADDRESS_LENGTH);
      err |= re_hprintf(pf, "        [%u@%H]\n", zone->parent->binlen, stack_debug, zone->parent->binrep);
    }
#endif
    err |= re_hprintf(pf, "→ ZONE[%i][COORDS:%u;%H]\n", i, zone->binlen, stack_debug, zone->binrep);
  }

  /*re_hprintf(pf, "→ {Tree of Life has no Peers}\n");*/

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

/* IN: */
static int treeoflife_command_cb_child( struct treeoflife_csock *tol_c
                                     , struct magi_melchior_rpc *rpc )
{
  int err = 0;
  uint16_t weight = 0;
  struct treeoflife_peer *peer = NULL;
  struct treeoflife_zone *zone = &tol_c->zone[0];

  info("I AM THE CHILD\n");

  err = _treeoflife_peer_create(&peer, tol_c, everip_addr);
  if (err == EALREADY)
    err = 0;
  if (err)
    goto out;

  /* check that we actually recieved this message from our parrent */
  if (zone->parent != peer)
    return EPROTO;

  /* here we need to set our coord from the parent */

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

  if ( ode->u.integer ) {
    info("TREE: [%W] is my child!\n", everip_addr, EVERIP_ADDRESS_LENGTH);

    /* okay, send address push */
    odict_alloc(&od, 8);
    err = magi_melchior_send( everip_magi_melchior()
                            , od
                            , &(struct pl)PL("tree.child")
                            , everip_addr
                            , 5000
                            , false /* is not routable */
                            , _treeoflife_command_child_cb
                            , tol_c );

    od = mem_deref(od);

  } else {
    info("TREE: [%W] is NOT my child!\n", everip_addr, EVERIP_ADDRESS_LENGTH);
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

  odict_entry_add(od, "zone", ODICT_INT, 0);
  odict_entry_add(od, "root", ODICT_STRING, &(struct pl){.p=(const char *)tol_c->zone[0].root,.l=EVERIP_ADDRESS_LENGTH});
  if (tol_c->zone[0].parent) {
    odict_entry_add(od, "parent", ODICT_STRING, &(struct pl){.p=(const char *)tol_c->zone[0].parent->cp.everip_addr,.l=EVERIP_ADDRESS_LENGTH});
  } else {
    odict_entry_add(od, "parent", ODICT_STRING, &(struct pl){.p="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",.l=EVERIP_ADDRESS_LENGTH});
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
  uint16_t weight = 0;
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
