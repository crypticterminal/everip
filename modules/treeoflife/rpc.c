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

static bool _are_you_my_parent( struct tol_zone *zone
                              , const uint8_t remote_root[EVERIP_ADDRESS_LENGTH]
                              , const uint8_t remote_everip[EVERIP_ADDRESS_LENGTH]
                              , uint16_t binlen )
{
  int rootcmp;

  if (!zone || !remote_root)
    return false;

  /* begin calculation */
  rootcmp = memcmp(remote_root, zone->root, EVERIP_ADDRESS_LENGTH);
  return ((rootcmp > 0) || (!rootcmp && (binlen + 1 < zone->binlen)));
}

/* call-out */

static void _tol_cb_command_zone( enum MAGI_MELCHIOR_RETURN_STATUS status
                                       , struct odict *od_sent
                                       , struct odict *od_recv
                                       , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH]
                                       , uint64_t timediff
                                       , void *userdata )
{

  if (status != MAGI_MELCHIOR_RETURN_STATUS_OK) {
    error("[TREE] _treeoflife_command_zone_cb\n");
    return; /* ignore for now */
  }

}

int tol_command_send_zone( struct this_module *mod
                         , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH] )
{
  int err = 0;
  struct odict *od = NULL;

  odict_alloc(&od, 8);

  odict_entry_add( od, "zoneid", ODICT_INT, (int64_t)0);
  odict_entry_add( od
                 , "root"
                 , ODICT_STRING
                 , &(struct pl){ .p=(const char *)mod->zone[0].root
                               , .l=EVERIP_ADDRESS_LENGTH});

  if (mod->zone[0].parent) {
    odict_entry_add( od
                   , "parent"
                   , ODICT_STRING
                   , &(struct pl){ .p=(const char *)mod->zone[0].parent->everip
                                 , .l=EVERIP_ADDRESS_LENGTH});
  } else {
    odict_entry_add( od
                   , "parent"
                   , ODICT_STRING
                   , &(struct pl){ .p="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                 , .l=EVERIP_ADDRESS_LENGTH});
  }

  odict_entry_add(od, "binlen", ODICT_INT, (int64_t)mod->zone[0].binlen);

  err = magi_melchior_send( everip_magi_melchior()
                          , od
                          , &(struct pl)PL("tree.zone")
                          , everip_addr
                          , 5000
                          , false /* is not routable */
                          , _tol_cb_command_zone
                          , mod );

  od = mem_deref(od);

  return err;
}

/* call-in */

/* IN: zone, parent, height, root */
static int tol_command_cb_zone( struct this_module *mod
                              , struct magi_melchior_rpc *rpc )
{
  int err = 0;
  struct tol_zone *zone = NULL;
  struct tol_neighbor *tn = NULL;

  uint16_t tmp_zoneid;

  uint8_t *tmp_rootp;
  uint16_t tmp_binlen;
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

  zone = &mod->zone[tmp_zoneid];

  ode = odict_lookup(rpc->in, "binlen");
  if (!ode || ode->type != ODICT_INT) {
    err = EPROTO;
    goto out;
  }

  tmp_binlen = (uint16_t)ode->u.integer;

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

  /* create or find neighbor node */
  err = tol_neighbor_alloc(&tn, mod, rpc->everip_addr);
  if (err && err != EALREADY)
    goto out;

  /*tn->z[tmp_zoneid]*/
  
  if (_are_you_my_parent(zone, tmp_rootp, rpc->everip_addr, tmp_binlen))
  {
    zone->parent = tn;
    zone->binlen_calc = tmp_binlen + 1;
    memcpy(zone->root, tmp_rootp, EVERIP_ADDRESS_LENGTH);
    error("[TREE] I AM CHILD of %W!\n", tn->everip, EVERIP_ADDRESS_LENGTH);
  }

  list_unlink(&tn->z[tmp_zoneid].le_child);
  if (!memcmp(mod->my_everip, tmp_parentp, EVERIP_ADDRESS_LENGTH)) {
    list_append(&zone->children, &tn->z[tmp_zoneid].le_child, tn);
    error("[TREE] I AM PARENT of %W!\n", tn->everip, EVERIP_ADDRESS_LENGTH);
  }

#if 0
  /* join chain check: */
  if (_are_you_my_parent( zone
                        , tmp_rootp
                        , rpc->everip_addr
                        , tmp_height ))
  {
    memcpy(zone->root, tmp_rootp, EVERIP_ADDRESS_LENGTH);
    zone->height = tmp_height + weight;
    odict_entry_add( rpc->out, "am_child", ODICT_INT, (int64_t)1);

    /* flush all dhti on change of root/parent */
    for (int i = 0; i < TOL_ZONE_COUNT; ++i)
    {
      list_flush(&tol_c->zone[i].dhti_all);
    }

  }
  else {
    odict_entry_add( rpc->out, "am_child", ODICT_INT, (int64_t)0);
  }

  odict_entry_add(rpc->out, "zoneid", ODICT_INT, (int64_t)tmp_zoneid);

  odict_entry_add(rpc->out, "height", ODICT_INT, (int64_t)zone->height);

  odict_entry_add( rpc->out
                 , "root"
                 , ODICT_STRING
                 , &(struct pl){ .p=(const char *)zone->root
                               , .l=EVERIP_ADDRESS_LENGTH});

#endif

out:
  return err;
}


int tol_command_callback( struct magi_melchior_rpc *rpc
                        , struct pl *method
                        , void *arg )
{
  struct this_module *mod = arg;

  if (!rpc || !mod || !method)
    return EINVAL;

  error( "[TREE] treeoflife_command_callback: [%r] from %w\n"
      , method
      , rpc->everip_addr, EVERIP_ADDRESS_LENGTH
      );

  switch (method->l) {
//    case 3:
//      /* dht */
//      if (!memcmp(method->p, "dht", 3))
//      {
//        return treeoflife_command_cb_dht(tol_c, rpc);
//      }
    case 4:
      /* zone */
      if (!memcmp(method->p, "zone", 4))
      {
        return tol_command_cb_zone(mod, rpc);
      }
//    case 5:
//      /* child */
//      if (!memcmp(method->p, "child", 5))
//      {
//        return treeoflife_command_cb_child(tol_c, rpc);
//      }
//    case 6:
//      /* update */
//      if (!memcmp(method->p, "update", 6))
//      {
//        return treeoflife_command_cb_update(tol_c, rpc);
//      }
    default:
      return EPROTO;
  }
  /* failsafe */
  return EPROTO;
}
