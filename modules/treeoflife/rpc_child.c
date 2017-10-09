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

static void _tol_cb_command_child( enum MAGI_MELCHIOR_RETURN_STATUS status
                                 , struct odict *od_sent
                                 , struct odict *od_recv
                                 , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH]
                                 , uint64_t timediff
                                 , void *userdata )
{
  if (status != MAGI_MELCHIOR_RETURN_STATUS_OK) {
    return; /* ignore for now */
  }

  /*info("I AM THE PARENT\n");*/

  return;
}

int tol_command_send_child( struct tol_neighbor *tn
                          , uint8_t zoneid )
{
  int err = 0;
  struct odict *od = NULL;
  const struct tol_zone *zone;
  struct this_module *mod = container_of( tn->le_mod.list
                                        , struct this_module
                                        , all_neighbors );

  if (!tn || !mod || zoneid >= TOL_ZONE_COUNT)
    return EINVAL;

  zone = &mod->zone[zoneid];

  /* okay, send address push */
  odict_alloc(&od, 8);

  odict_entry_add( od, "zoneid", ODICT_INT, (int64_t)zoneid);

  odict_entry_add( od
                 , "root"
                 , ODICT_STRING
                 , &(struct pl){ .p=(const char *)mod->zone[0].root
                               , .l=EVERIP_ADDRESS_LENGTH});
  /* parent */
  odict_entry_add( od
                 , "parent_br"
                 , ODICT_STRING
                 , &(struct pl){ .p=(const char *)zone->binrep
                               , .l=TOL_ROUTE_LENGTH});

  odict_entry_add( od, "parent_bl", ODICT_INT, (int64_t)zone->binlen);

  /* child */
  if (!tn->z[zoneid].child_id_chosen) {
    tn->z[zoneid].child_id_chosen = true;
    tn->z[zoneid].child_id = tol_get_childid(mod);
  }

  memcpy(tn->z[zoneid].binrep, zone->binrep, TOL_ROUTE_LENGTH);
  tn->z[zoneid].binlen = stack_layer_add( tn->z[zoneid].binrep
                                        , tn->z[zoneid].child_id );

  odict_entry_add( od
                 , "child_br"
                 , ODICT_STRING
                 , &(struct pl){ .p=(const char *)tn->z[zoneid].binrep
                               , .l=TOL_ROUTE_LENGTH});

  odict_entry_add( od, "child_bl", ODICT_INT, (int64_t)tn->z[zoneid].binlen);

  err = magi_melchior_send( everip_magi_melchior()
                          , od
                          , &(struct pl)PL("tree.child")
                          , tn->everip
                          , 5000
                          , false /* is not routable */
                          , _tol_cb_command_child
                          , mod );

  od = mem_deref(od);

  return 0;
}

int tol_command_cb_child( struct this_module *mod
                        , struct magi_melchior_rpc *rpc )
{
  int err = 0;
  const struct odict_entry *ode;
  struct tol_neighbor *tn = NULL;
  struct tol_zone *zone = NULL;

  uint8_t *tmp_rootp;
  uint16_t tmp_zoneid;
  uint8_t *tmp_parent_br;
  uint16_t tmp_parent_bl;
  uint8_t *tmp_child_br;
  uint16_t tmp_child_bl;

  /*info("[TREE] I AM THE CHILD\n");*/

  if (!mod || !rpc)
    return EINVAL;

  /* we should already have the peer */
  tn = tol_neighbor_find_byeverip(mod, rpc->everip_addr);
  if (!tn)
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

  zone = &mod->zone[tmp_zoneid];

  /* check that we actually recieved this message from our parrent */
  if (zone->parent != tn)
    return EPROTO;

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
  if (memcmp(zone->root, tmp_rootp, EVERIP_ADDRESS_LENGTH)) {
    error("[TREE] child information from invalid root\n");
    err = EPROTO;
    goto out;
  }

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

  zone->active = true;

  /* notify children, if we have any! */
  {
    struct le *le;
    struct tol_neighbor *_tn;
    LIST_FOREACH(&zone->children, le) {
      _tn = le->data;
      tol_command_send_child(_tn, tmp_zoneid);
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

    (void)tol_command_send_dht_notify( zone->parent->everip
                                     , mod->my_everip
                                     , mod->my_public_key
                                     , tmp_zoneid
                                     , zone->root
                                     , zone->binrep
                                     , zone->binlen );

    /* x:e dht */
  }

out:
  return err;
}

