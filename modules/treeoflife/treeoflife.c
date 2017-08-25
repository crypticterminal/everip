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

#define TOL_DHT_TIMEOUT_MS 15000

#define TOL_VERSION_ID 1U

struct treeoflife_peer;
struct treeoflife_csock;

struct treeoflife_dhti {
  struct le le;
  uint8_t binlen;
  uint8_t binrep[TOL_ROUTE_LENGTH];
  uint8_t everip_addr[EVERIP_ADDRESS_LENGTH];
  uint8_t public_key[NOISE_PUBLIC_KEY_LEN];

  struct tmr tmr;
};

struct treeoflife_zone {
  uint8_t root[EVERIP_ADDRESS_LENGTH];
  struct treeoflife_peer *parent;
  uint8_t height;

  uint8_t binlen;
  uint8_t binrep[TOL_ROUTE_LENGTH];

  struct list nodes_all;

  struct list dhti_all;
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
  uint8_t my_public_key[NOISE_PUBLIC_KEY_LEN];

  struct treeoflife_zone zone[TOL_ZONE_COUNT];

  uint16_t child_counter;

};

static struct treeoflife_csock *g_tol = NULL;

static bool _are_you_my_parent( struct treeoflife_zone *zone
                              , const uint8_t remote_root[EVERIP_ADDRESS_LENGTH]
                              , const uint8_t remote_everip[EVERIP_ADDRESS_LENGTH]
                              , uint8_t height )
{
  uint8_t weight = 1;
  int rootcmp;

  if (!zone || !remote_root)
    return false;

  /* begin calculation */
  rootcmp = memcmp(remote_root, zone->root, EVERIP_ADDRESS_LENGTH);

  if ( (rootcmp > 0) || (!rootcmp && height + weight <= zone->height) )
  {
    return true;
  } else {
    bool you_are_my_parent = false;
    if (zone->parent && !memcmp( zone->parent->cp.everip_addr
                               , remote_everip
                               , EVERIP_ADDRESS_LENGTH)) {
      you_are_my_parent = true;
    }
    return you_are_my_parent;
  }
  /*@UNREACHABLE@*/
  return false;
}

static void treeoflife_dhti_destructor(void *data)
{
  struct treeoflife_dhti *dhti = data;
  list_unlink(&dhti->le);
  tmr_cancel(&dhti->tmr);
}

static void treeoflife_dhti_tmr_cb(void *data)
{
  struct treeoflife_dhti *dhti = data;
  dhti = mem_deref( dhti );
}

static int treeoflife_dhti_add_or_update( struct treeoflife_zone *zone 
                                        , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH]
                                        , const uint8_t public_key[NOISE_PUBLIC_KEY_LEN]
                                        , uint8_t binrep[TOL_ROUTE_LENGTH]
                                        , uint8_t binlen )
{
  int err = 0;
  struct le *le;
  bool dhti_already_exists = false;
  struct treeoflife_dhti *dhti;

  LIST_FOREACH(&zone->dhti_all, le) {
    dhti = le->data;
    if (!memcmp(dhti->everip_addr, everip_addr, EVERIP_ADDRESS_LENGTH)) {
      dhti_already_exists = true;
      break;
    }
  }

  if (!dhti_already_exists) {
    /* create dhti here */
    dhti = mem_zalloc(sizeof(*dhti), treeoflife_dhti_destructor);
    if (!dhti) {
      err = ENOMEM;
      goto out;
    }
    memcpy(dhti->everip_addr, everip_addr, EVERIP_ADDRESS_LENGTH);
    memcpy(dhti->public_key, public_key, NOISE_PUBLIC_KEY_LEN);
    list_append(&zone->dhti_all, &dhti->le, dhti);
  }

  /* update binrep */
  dhti->binlen = binlen;
  memcpy(dhti->binrep, binrep, TOL_ROUTE_LENGTH);

  /* update timer here */
  //tmr_start(&dhti->tmr, TOL_DHT_TIMEOUT_MS, treeoflife_dhti_tmr_cb, dhti);

out:
  return err;
}

static
int treeoflife_peer_dht_notify_send( const uint8_t everip_forward[EVERIP_ADDRESS_LENGTH]
                                   , const uint8_t everip_record[EVERIP_ADDRESS_LENGTH]
                                   , const uint8_t public_key[NOISE_PUBLIC_KEY_LEN]
                                   , uint16_t zoneid
                                   , uint8_t root[EVERIP_ADDRESS_LENGTH]
                                   , uint8_t binrep[TOL_ROUTE_LENGTH]
                                   , uint8_t binlen )
{
  struct odict *od_dht = NULL;

  odict_alloc(&od_dht, 8);

  odict_entry_add( od_dht, "mode", ODICT_STRING, &(struct pl)PL("notify"));

  odict_entry_add( od_dht, "zoneid", ODICT_INT, zoneid);

  odict_entry_add( od_dht
                 , "everip"
                 , ODICT_STRING
                 , &(struct pl){ .p=(const char *)everip_record
                               , .l=EVERIP_ADDRESS_LENGTH});

  odict_entry_add( od_dht
                 , "pubkey"
                 , ODICT_STRING
                 , &(struct pl){ .p=(const char *)public_key
                               , .l=NOISE_PUBLIC_KEY_LEN});

  odict_entry_add( od_dht
                 , "root"
                 , ODICT_STRING
                 , &(struct pl){ .p=(const char *)root
                               , .l=EVERIP_ADDRESS_LENGTH});

  odict_entry_add( od_dht
                 , "br"
                 , ODICT_STRING
                 , &(struct pl){ .p=(const char *)binrep
                               , .l=TOL_ROUTE_LENGTH});

  odict_entry_add( od_dht, "bl", ODICT_INT, binlen);

  magi_melchior_send( everip_magi_melchior()
                    , od_dht
                    , &(struct pl)PL("tree.dht")
                    , everip_forward
                    , 1 /* don't mind if we timeout soon */
                    , false /* is not routable */
                    , NULL /* do not expect reply */
                    , NULL );

  od_dht = mem_deref( od_dht );

  return 0;
}

static
int treeoflife_peer_dht_aquire_send( const uint8_t everip_forward[EVERIP_ADDRESS_LENGTH]
                                   , const uint8_t everip_aquire[EVERIP_ADDRESS_LENGTH]
                                   , uint16_t zoneid
                                   , uint8_t root[EVERIP_ADDRESS_LENGTH]
                                   , uint8_t from_binrep[TOL_ROUTE_LENGTH]
                                   , uint8_t from_binlen )
{
  struct odict *od_dht = NULL;

  odict_alloc(&od_dht, 8);

  odict_entry_add( od_dht, "mode", ODICT_STRING, &(struct pl)PL("aquire"));

  odict_entry_add( od_dht, "zoneid", ODICT_INT, zoneid);

  odict_entry_add( od_dht
                 , "everip"
                 , ODICT_STRING
                 , &(struct pl){ .p=(const char *)everip_aquire
                               , .l=EVERIP_ADDRESS_LENGTH});

  odict_entry_add( od_dht
                 , "root"
                 , ODICT_STRING
                 , &(struct pl){ .p=(const char *)root
                               , .l=EVERIP_ADDRESS_LENGTH});

  odict_entry_add( od_dht
                 , "fbr"
                 , ODICT_STRING
                 , &(struct pl){ .p=(const char *)from_binrep
                               , .l=TOL_ROUTE_LENGTH});

  odict_entry_add( od_dht, "fbl", ODICT_INT, from_binlen);

  magi_melchior_send( everip_magi_melchior()
                    , od_dht
                    , &(struct pl)PL("tree.dht")
                    , everip_forward
                    , 1 /* don't mind if we timeout soon */
                    , false /* is not routable */
                    , NULL /* do not expect reply */
                    , NULL );

  od_dht = mem_deref( od_dht );

  return 0;
}

static
int treeoflife_peer_dht_found_send( const uint8_t everip_forward[EVERIP_ADDRESS_LENGTH]
                                  , const uint8_t everip_aquire[EVERIP_ADDRESS_LENGTH]
                                  , const uint8_t public_key[NOISE_PUBLIC_KEY_LEN]
                                  , uint16_t zoneid
                                  , uint8_t root[EVERIP_ADDRESS_LENGTH]
                                  , uint8_t from_binrep[TOL_ROUTE_LENGTH]
                                  , uint8_t from_binlen
                                  , uint8_t record_binrep[TOL_ROUTE_LENGTH]
                                  , uint8_t record_binlen )
{
  struct odict *od_dht = NULL;

  odict_alloc(&od_dht, 8);

  odict_entry_add( od_dht, "mode", ODICT_STRING, &(struct pl)PL("found"));

  odict_entry_add( od_dht, "zoneid", ODICT_INT, zoneid);

  odict_entry_add( od_dht
                 , "everip"
                 , ODICT_STRING
                 , &(struct pl){ .p=(const char *)everip_aquire
                               , .l=EVERIP_ADDRESS_LENGTH});

  odict_entry_add( od_dht
                 , "pubkey"
                 , ODICT_STRING
                 , &(struct pl){ .p=(const char *)public_key
                               , .l=NOISE_PUBLIC_KEY_LEN});

  odict_entry_add( od_dht
                 , "root"
                 , ODICT_STRING
                 , &(struct pl){ .p=(const char *)root
                               , .l=EVERIP_ADDRESS_LENGTH});

  odict_entry_add( od_dht
                 , "fbr"
                 , ODICT_STRING
                 , &(struct pl){ .p=(const char *)from_binrep
                               , .l=TOL_ROUTE_LENGTH});

  odict_entry_add( od_dht, "fbl", ODICT_INT, from_binlen);

  odict_entry_add( od_dht
                 , "br"
                 , ODICT_STRING
                 , &(struct pl){ .p=(const char *)record_binrep
                               , .l=TOL_ROUTE_LENGTH});

  odict_entry_add( od_dht, "bl", ODICT_INT, record_binlen);

  magi_melchior_send( everip_magi_melchior()
                    , od_dht
                    , &(struct pl)PL("tree.dht")
                    , everip_forward
                    , 1 /* don't mind if we timeout soon */
                    , false /* is not routable */
                    , NULL /* do not expect reply */
                    , NULL );

  od_dht = mem_deref( od_dht );

  return 0;
}

static
int treeoflife_everip_for_route( struct treeoflife_csock *tol_c
                               , uint8_t route[TOL_ROUTE_LENGTH]
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
      info( "TRYING NODE [%W]{%H}[%s|%u]\n"
          , peer->cp.everip_addr, EVERIP_ADDRESS_LENGTH
          , stack_debug, peer->z[i].binrep
          , peer->is_onehop ? "OH" : "NH"
          , peer->z[i].binlen);
      if (!peer->is_onehop || !peer->z[i].binlen)
        continue;
      temp_diff = stack_linf_diff(route, peer->z[i].binrep, &places);
      if (temp_diff == 0 && !memcmp(route, peer->z[i].binrep, TOL_ROUTE_LENGTH)) {
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
                               , .l=TOL_ROUTE_LENGTH});

  odict_entry_add( od, "parent_bl", ODICT_INT, zone->binlen);

  /* child */
  if (!peer->z[zoneid].child_id_chosen) {
    peer->z[zoneid].child_id_chosen = true;
    peer->z[zoneid].child_id = treeoflife_get_childid(peer->ctx);
  }

  memcpy(peer->z[zoneid].binrep, zone->binrep, TOL_ROUTE_LENGTH);
  peer->z[zoneid].binlen = stack_layer_add( peer->z[zoneid].binrep
                                          , peer->z[zoneid].child_id );

  odict_entry_add( od
                 , "child_br"
                 , ODICT_STRING
                 , &(struct pl){ .p=(const char *)peer->z[zoneid].binrep
                               , .l=TOL_ROUTE_LENGTH});

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

  if (peer == zone->parent)
    return EINVAL;

  /* okay, send address push */
  odict_alloc(&od, 8);

  odict_entry_add( od, "zoneid", ODICT_INT, zoneid);

  /* parent */
  odict_entry_add( od
                 , "br"
                 , ODICT_STRING
                 , &(struct pl){ .p=(const char *)zone->binrep
                               , .l=TOL_ROUTE_LENGTH});

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

static void treeoflife_peer_destructor(void *data)
{
  struct treeoflife_peer *peer = data;

  /* x:start process cp */
  conduit_peer_deref(&peer->cp);
  /* x:end process cp */

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

  peer = mem_zalloc(sizeof(*peer), treeoflife_peer_destructor);
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

static int _conduit_debug(struct re_printf *pf, void *arg)
{
  int err = 0;
  struct le *le;
  const struct treeoflife_zone *zone;
  struct treeoflife_dhti *dhti = NULL;
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

    /* dhti */
    LIST_FOREACH(&zone->dhti_all, le) {
      dhti = le->data;
      err |= re_hprintf(pf, "→ ZONE[%i][DHASH:%W][%u@%H][LEFT:%u]\n", i, dhti->everip_addr, EVERIP_ADDRESS_LENGTH, dhti->binlen, stack_debug, dhti->binrep, tmr_get_expire(&dhti->tmr));
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

static int treeoflife_command_cb_dht( struct treeoflife_csock *tol_c
                                    , struct magi_melchior_rpc *rpc )
{
  int err = 0;
  const struct odict_entry *ode;
  struct treeoflife_zone *zone = NULL;

  uint16_t tmp_zoneid;
  uint8_t *tmp_rootp;

  uint8_t *tmp_everip_record;

  if (!tol_c || !rpc)
    return EINVAL;

  rpc->out = NULL; /* they're not expecting anything back */

  /*
    [X] zoneid
    [X] root
    [X] br
    [X] bl

    [X] mode

  */

  ode = odict_lookup(rpc->in, "zoneid");
  if (!ode || ode->type != ODICT_INT) {
    goto out;
  }

  tmp_zoneid = ode->u.integer;

  if (tmp_zoneid >= TOL_ZONE_COUNT) {
    err = EPROTO;
    goto out;
  }

  zone = &tol_c->zone[tmp_zoneid];

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

  /* if we are not the same root on the same zone, ignore! */
  if (memcmp(zone->root, tmp_rootp, EVERIP_ADDRESS_LENGTH)) {
    err = EPROTO;
    goto out;
  }

  ode = odict_lookup(rpc->in, "everip");
  if (!ode || ode->type != ODICT_STRING) {
    err = EPROTO;
    goto out;
  }

  /* root must be same as everip address */
  if (ode->u.pl.l != EVERIP_ADDRESS_LENGTH) {
    err = EPROTO;
    goto out;
  } 

  tmp_everip_record = (uint8_t *)ode->u.pl.p;

  ode = odict_lookup(rpc->in, "mode");
  if (!ode || ode->type != ODICT_STRING) {
    err = EPROTO;
    goto out;
  }

  /* mode switch */
  switch (ode->u.pl.l) {
    case 5:
      /* found */
      if (!memcmp(ode->u.pl.p, "found", 5))
      {
        uint8_t *tmp_br;
        uint16_t tmp_bl;
        uint8_t *tmp_fbr;  
        uint16_t tmp_fbl;
        uint8_t *tmp_pubkey;
        uint8_t everip_addr_route[EVERIP_ADDRESS_LENGTH];

        ode = odict_lookup(rpc->in, "pubkey");
        if (!ode || ode->type != ODICT_STRING) {
          err = EPROTO;
          goto out;
        }

        /* root must be same as everip address */
        if (ode->u.pl.l != NOISE_PUBLIC_KEY_LEN) {
          err = EPROTO;
          goto out;
        } 

        tmp_pubkey = (uint8_t *)ode->u.pl.p;

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

        ode = odict_lookup(rpc->in, "fbr");
        if (!ode || ode->type != ODICT_STRING) {
          err = EPROTO;
          goto out;
        }

        if (ode->u.pl.l != TOL_ROUTE_LENGTH) {
          err = EPROTO;
          goto out;
        }

        tmp_fbr = (uint8_t *)ode->u.pl.p;

        ode = odict_lookup(rpc->in, "fbl");
        if (!ode || ode->type != ODICT_INT) {
          err = EPROTO;
          goto out;
        }

        tmp_fbl = (uint16_t)ode->u.integer;

        /* search for entry, and if found -- update */
        err = treeoflife_dhti_add_or_update( zone
                                           , tmp_everip_record
                                           , tmp_pubkey
                                           , tmp_br
                                           , tmp_bl );
        if (err)
          goto out;

        if (treeoflife_everip_for_route( tol_c
                                       , tmp_fbr
                                       , everip_addr_route ))
          goto out;

        treeoflife_peer_dht_found_send( everip_addr_route
                                      , tmp_everip_record
                                      , tmp_pubkey
                                      , tmp_zoneid
                                      , tmp_rootp
                                      , tmp_fbr /* from */
                                      , tmp_fbl /* from */
                                      , tmp_br /* record */
                                      , tmp_bl /* record */
                                      );

      }
      break;
    case 6:
      /* notify, aquire */
      if (!memcmp(ode->u.pl.p, "notify", 6))
      {
        uint8_t *tmp_br;
        uint16_t tmp_bl;
        uint8_t *tmp_pubkey;

        ode = odict_lookup(rpc->in, "pubkey");
        if (!ode || ode->type != ODICT_STRING) {
          err = EPROTO;
          goto out;
        }

        /* root must be same as everip address */
        if (ode->u.pl.l != NOISE_PUBLIC_KEY_LEN) {
          err = EPROTO;
          goto out;
        } 

        tmp_pubkey = (uint8_t *)ode->u.pl.p;

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

        /* okay, save it here */
        err = treeoflife_dhti_add_or_update( zone 
                                           , tmp_everip_record
                                           , tmp_pubkey
                                           , tmp_br
                                           , tmp_bl );
        if (err)
          goto out;

        /* forward! */
        {
          struct le *le;
          struct treeoflife_peer *peer = NULL;

          if (zone->parent) {
            /* easy path */

            if (!memcmp( zone->parent->cp.everip_addr
                       , rpc->everip_addr
                       , EVERIP_ADDRESS_LENGTH)) {
              /* we already came from there! */
              goto out;
            }

            (void)treeoflife_peer_dht_notify_send( zone->parent->cp.everip_addr
                                                 , tmp_everip_record
                                                 , tmp_pubkey
                                                 , tmp_zoneid
                                                 , tmp_rootp
                                                 , tmp_br
                                                 , tmp_bl );
          }
          else {/* no parent, we shelve off to all local peers */
            LIST_FOREACH(&zone->nodes_all, le) {
              peer = le->data;
              if (!peer->is_onehop)
                continue;
              if (!memcmp( peer->cp.everip_addr
                         , rpc->everip_addr
                         , EVERIP_ADDRESS_LENGTH)) {
                continue;
              }
              (void)treeoflife_peer_dht_notify_send( peer->cp.everip_addr
                                                   , tmp_everip_record
                                                   , tmp_pubkey
                                                   , tmp_zoneid
                                                   , tmp_rootp
                                                   , tmp_br
                                                   , tmp_bl );
            }
          }
        }

        error("DHT NOTIFY!!!\n");
      }
      else if (!memcmp(ode->u.pl.p, "aquire", 6))
      {
        uint8_t *tmp_fbr;  
        uint16_t tmp_fbl;
        ode = odict_lookup(rpc->in, "fbr");
        if (!ode || ode->type != ODICT_STRING) {
          err = EPROTO;
          goto out;
        }

        if (ode->u.pl.l != TOL_ROUTE_LENGTH) {
          err = EPROTO;
          goto out;
        }

        tmp_fbr = (uint8_t *)ode->u.pl.p;

        ode = odict_lookup(rpc->in, "fbl");
        if (!ode || ode->type != ODICT_INT) {
          err = EPROTO;
          goto out;
        }

        tmp_fbl = (uint16_t)ode->u.integer;

        /* search for record */
        {
          struct le *le;
          uint8_t everip_addr_route[EVERIP_ADDRESS_LENGTH];
          struct treeoflife_dhti *dhti;

          LIST_FOREACH(&zone->dhti_all, le) {
            dhti = le->data;
            /* if we have record, send it back */
            if (!memcmp(dhti->everip_addr, tmp_everip_record, EVERIP_ADDRESS_LENGTH)) {
              if (treeoflife_everip_for_route( tol_c
                                             , tmp_fbr
                                             , everip_addr_route ))
                goto out;

              treeoflife_peer_dht_found_send( everip_addr_route
                                            , dhti->everip_addr
                                            , dhti->public_key
                                            , tmp_zoneid
                                            , tmp_rootp
                                            , tmp_fbr /* from */
                                            , tmp_fbl /* from */
                                            , dhti->binrep /* record */
                                            , dhti->binlen /* record */
                                            );

              /* do not forward; goto out */
              goto out;
            }
          }
        }

        /* if not found, forward on! */
        error("DHT AQUIRE!!!\n");
      } else {
        err = EPROTO;
        goto out;
      }
      break;
    default:
      err = EPROTO;
      goto out;
  }

out:
  return err;
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

  /* updates can only and should only come from nodes that are not our child */
  if (peer->z[tmp_zoneid].is_my_child)
    return EPROTO;

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
      } else if (_p->is_onehop && _p != zone->parent) {
        treeoflife_peer_send_update(tmp_zoneid, _p);
      }
    }
  }

  { /* x:s dht */

    /*
       for dht notify, always send to parent;
       if we have no parent, assume that we are root,
       and that we are connected to leaves.
     */
    if (!zone->parent)
      goto out;

    (void)treeoflife_peer_dht_notify_send( zone->parent->cp.everip_addr
                                         , tol_c->my_everip
                                         , tol_c->my_public_key
                                         , tmp_zoneid
                                         , zone->root
                                         , zone->binrep
                                         , zone->binlen );
    /* x:e dht */
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
  struct treeoflife_zone *zone = NULL;

  uint16_t tmp__i_am_your_child = 0;
  uint16_t tmp__zoneid = 0;
  uint8_t tmp__height = 0;
  uint8_t *tmp__rootp;

  bool calc__are_you_my_parent = false;

  if (status != MAGI_MELCHIOR_RETURN_STATUS_OK) {
    return; /* ignore for now */
  }

  ode = odict_lookup(od_recv, "am_child");
  if (!ode || ode->type != ODICT_INT) {
    goto out;
  }

  tmp__i_am_your_child = ode->u.integer;

  ode = odict_lookup(od_recv, "zoneid");
  if (!ode || ode->type != ODICT_INT) {
    goto out;
  }

  tmp__zoneid = ode->u.integer;

  ode = odict_lookup(od_recv, "height");
  if (!ode || ode->type != ODICT_INT) {
    err = EPROTO;
    goto out;
  }

  tmp__height = (uint8_t)ode->u.integer;

  if (tmp__zoneid >= TOL_ZONE_COUNT) {
    goto out;
  }

  zone = &tol_c->zone[tmp__zoneid];

  ode = odict_lookup(od_recv, "root");
  if (!ode || ode->type != ODICT_STRING) {
    goto out;
  }

  /* root must be same as everip address */
  if (ode->u.pl.l != EVERIP_ADDRESS_LENGTH) {
    goto out;
  } 

  tmp__rootp = (uint8_t *)ode->u.pl.p;

  /**/
  calc__are_you_my_parent = _are_you_my_parent( zone
                                              , tmp__rootp
                                              , everip_addr
                                              , tmp__height );

  /* sanity check */
  if (calc__are_you_my_parent) {
    if (tmp__i_am_your_child)
      goto out;
  } else {
    /* event if this peer is our child or not, */
    /* the child should be setting itself to us as a root */
    if (memcmp(zone->root, tmp__rootp, EVERIP_ADDRESS_LENGTH))
      goto out;
  }

  /* lookup or create peer */
  err = _treeoflife_peer_create(&peer, tol_c, everip_addr);
  if (err == EALREADY)
    err = 0;
  if (err)
    goto out;

  peer->is_onehop = true;

  if (calc__are_you_my_parent) {
    if (zone->parent) {
      /* do destruct here? */
    }
    zone->parent = peer;
  }

  list_unlink(&peer->le_zone[tmp__zoneid]);
  list_append(&zone->nodes_all, &peer->le_zone[tmp__zoneid], peer);

  if ( tmp__i_am_your_child ) {
    info("TREE: [%W] is my child!\n", everip_addr, EVERIP_ADDRESS_LENGTH);

    peer->z[tmp__zoneid].is_my_child = true;

    err = treeoflife_peer_send_aschild( tmp__zoneid, peer );
    if (err)
      goto out;

  } else {
    info("TREE: [%W] is NOT my child!\n", everip_addr, EVERIP_ADDRESS_LENGTH);
    peer->z[tmp__zoneid].is_my_child = false;
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

  odict_entry_add( od, "zoneid", ODICT_INT, 0);
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
  struct treeoflife_zone *zone = NULL;

  uint16_t tmp_zoneid;

  uint8_t *tmp_rootp;
  uint16_t tmp_height;
  uint8_t *tmp_parentp;

  const struct odict_entry *ode;

  /* get all of our items */
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

  /* join chain check: */
  if (_are_you_my_parent( zone
                        , tmp_rootp
                        , rpc->everip_addr
                        , tmp_height ))
  {
    memcpy(zone->root, tmp_rootp, EVERIP_ADDRESS_LENGTH);
    zone->height = tmp_height + weight;
    odict_entry_add( rpc->out, "am_child", ODICT_INT, 1);
  }
  else {
    odict_entry_add( rpc->out, "am_child", ODICT_INT, 0);
  }

  odict_entry_add(rpc->out, "zoneid", ODICT_INT, tmp_zoneid);

  odict_entry_add(rpc->out, "height", ODICT_INT, zone->height);

  odict_entry_add( rpc->out
                 , "root"
                 , ODICT_STRING
                 , &(struct pl){ .p=(const char *)zone->root
                               , .l=EVERIP_ADDRESS_LENGTH});

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
    case 3:
      /* dht */
      if (!memcmp(method->p, "dht", 3))
      {
        return treeoflife_command_cb_dht(tol_c, rpc);
      }
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

int treeoflife_ledbat_recv( struct mbuf *mb )
{
  error("tol: [%u][%W]\n", mbuf_get_left(_mb), mbuf_buf(_mb), mbuf_get_left());
  return 0;
}

static int _conduit_search( const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH]
                          , void *arg )
{
  struct le *le;
  struct treeoflife_dhti *dhti = NULL;
  struct treeoflife_peer *peer = NULL;
  struct treeoflife_csock *tol_c = arg;
  struct treeoflife_zone *zone = &tol_c->zone[0];

  if (!everip_addr || !tol_c)
    return EINVAL;

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
    _treeoflife_peer_create( &peer
                           , tol_c
                           , dhti->everip_addr );
    if (!peer)
      return 0;

    memcpy(peer->z[0].binrep, dhti->binrep, TOL_ROUTE_LENGTH);
    peer->z[0].binlen = dhti->binlen;

    /* initiate peer */
    conduit_peer_initiate( &peer->cp
                         , tol_c->conduit
                         , dhti->public_key
                         , true );
    return 0;
  }

  if (!zone->parent)
    return 0;

  treeoflife_peer_dht_aquire_send( zone->parent->cp.everip_addr
                                 , everip_addr
                                 , 0
                                 , zone->root
                                 , zone->binrep
                                 , zone->binlen );

  return 0;
}

static int magi_event_watcher_h( enum MAGI_EVENTDRIVER_WATCH type
                               , void *data
                               , void *arg )
{
  struct treeoflife_peer *peer = NULL;
  struct magi_e2e_event *event = data;
  struct treeoflife_csock *tol_c = arg;

  if (!tol_c || !event || type != MAGI_EVENTDRIVER_WATCH_E2E)
    return 0;

  switch (event->status) {
    case MAGI_NODE_STATUS_OFFLINE:
    case MAGI_NODE_STATUS_SEARCHING:
      debug("TREEOFLIFE: node [%W] has gone offline!\n", event->everip_addr, EVERIP_ADDRESS_LENGTH);
      peer = _treeoflife_peer_lookup(tol_c, event->everip_addr);
      peer = mem_deref(peer);
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

static int _sendto_virtual( struct conduit_peer *peer
                          , struct mbuf *mb
                          , void *arg )
{
  int err = 0;
  size_t pos_top;
  struct magi_node *mnode = NULL;
  struct treeoflife_peer *tp = NULL;
  struct treeoflife_zone *zone = NULL;
  struct treeoflife_csock *tol_c = arg;
  uint8_t everip_addr_route[EVERIP_ADDRESS_LENGTH];

  tp = container_of(peer, struct treeoflife_peer, cp);

  if (!tp || !tol_c)
    return EINVAL;

  info( "VIRTUAL REQUEST TO [%W]@[%H]\n"
      , peer->everip_addr
      , EVERIP_ADDRESS_LENGTH
      , stack_debug
      , tp->z[0].binrep);

  zone = &tol_c->zone[0];

  if (treeoflife_everip_for_route( tol_c
                                 , tp->z[0].binrep
                                 , everip_addr_route ))
    goto out;

  info( "ROUTING REQUEST VIA [%W]\n"
      , everip_addr_route
      , EVERIP_ADDRESS_LENGTH );

  mnode = magi_node_lookup_by_eipaddr(everip_magi(), everip_addr_route );

  if (!mnode) {
    error("_sendto_virtual: hmm, no magi record!\n");
    goto out;
  } else {
    info("FOUND MNODE\n");
  }

  /* form packet for request */
  /*[VERSION(1)][DST_BINLEN(1)][DST_BINROUTE(ROUTE_LENGTH)][SRC_BINLEN(1)][SRC_BINROUTE(ROUTE_LENGTH)]*/

  pos_top = mb->pos;

  mbuf_advance(mb, -(ssize_t)(1+1+TOL_ROUTE_LENGTH+1+TOL_ROUTE_LENGTH));

  /* version 1 */
  mbuf_write_u8(mb, TOL_VERSION_ID);

  /* dst */
  mbuf_write_mem(mb, tp->z[0].binrep, TOL_ROUTE_LENGTH);
  mbuf_write_u8(mb, tp->z[0].binlen);

  /* src */
  mbuf_write_mem(mb, zone->binrep, TOL_ROUTE_LENGTH);
  mbuf_write_u8(mb, zone->binlen);

  mbuf_set_pos(mb, pos_top);

  /* send packet via ledbat */
  magi_node_ledbat_send(mnode, mb, MAGI_LEDBAT_PORT_TREEOFLIFE);

out:
  return err;
}

static void treeoflife_destructor(void *data)
{
  struct treeoflife_csock *tol_c = data;
  hash_flush( tol_c->peers_addr );
  tol_c->peers_addr = mem_deref( tol_c->peers_addr );
  for (int i = 0; i < TOL_ZONE_COUNT; ++i)
  {
    list_flush(&tol_c->zone[i].dhti_all);
  }
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

  if (!everip_noise())
    return EINVAL;

  memcpy(g_tol->my_public_key, everip_noise()->si.public, NOISE_PUBLIC_KEY_LEN);

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

  conduit_register_send_handler( conduit
                               , _sendto_virtual
                               , g_tol);

  conduit_register_debug_handler( conduit
                                , _conduit_debug
                                , g_tol );

  conduit_register_search_handler( conduit
                                 , _conduit_search
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
