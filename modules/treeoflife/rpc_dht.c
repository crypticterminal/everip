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

static void tol_dhti_destructor(void *data)
{
  struct tol_dhti *dhti = data;
  list_unlink(&dhti->le);
  tmr_cancel(&dhti->tmr);
}

static void tol_dhti_tmr_cb(void *data)
{
  struct tol_dhti *dhti = data;
  dhti = mem_deref( dhti );
}

static int tol_dhti_add_or_update( struct tol_zone *zone 
                                 , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH]
                                 , const uint8_t public_key[NOISE_PUBLIC_KEY_LEN]
                                 , uint8_t binrep[TOL_ROUTE_LENGTH]
                                 , uint8_t binlen )
{
  int err = 0;
  struct le *le;
  bool dhti_already_exists = false;
  struct tol_dhti *dhti;

  LIST_FOREACH(&zone->dhti_all, le) {
    dhti = le->data;
    if (!memcmp(dhti->everip_addr, everip_addr, EVERIP_ADDRESS_LENGTH)) {
      dhti_already_exists = true;
      break;
    }
  }

  if (!dhti_already_exists) {
    /* create dhti here */
    dhti = mem_zalloc(sizeof(*dhti), tol_dhti_destructor);
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
  tmr_start(&dhti->tmr, TOL_DHT_TIMEOUT_MS, tol_dhti_tmr_cb, dhti);

out:
  return err;
}

/**/

int tol_command_send_dht_notify( const uint8_t everip_forward[EVERIP_ADDRESS_LENGTH]
                               , const uint8_t everip_record[EVERIP_ADDRESS_LENGTH]
                               , const uint8_t public_key[NOISE_PUBLIC_KEY_LEN]
                               , uint8_t zoneid
                               , uint8_t root[EVERIP_ADDRESS_LENGTH]
                               , uint8_t binrep[TOL_ROUTE_LENGTH]
                               , uint8_t binlen )
{
  struct odict *od_dht = NULL;

  odict_alloc(&od_dht, 8);

  odict_entry_add( od_dht, "mode", ODICT_STRING, &(struct pl)PL("notify"));

  odict_entry_add( od_dht, "zoneid", ODICT_INT, (int64_t)zoneid);

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

  odict_entry_add( od_dht, "bl", ODICT_INT, (int64_t)binlen);

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

int tol_command_send_dht_found( const uint8_t everip_forward[EVERIP_ADDRESS_LENGTH]
                              , const uint8_t everip_aquire[EVERIP_ADDRESS_LENGTH]
                              , const uint8_t public_key[NOISE_PUBLIC_KEY_LEN]
                              , uint8_t zoneid
                              , uint8_t root[EVERIP_ADDRESS_LENGTH]
                              , uint8_t from_binrep[TOL_ROUTE_LENGTH]
                              , uint8_t from_binlen
                              , uint8_t record_binrep[TOL_ROUTE_LENGTH]
                              , uint8_t record_binlen )
{
  struct odict *od_dht = NULL;

  odict_alloc(&od_dht, 8);

  odict_entry_add( od_dht, "mode", ODICT_STRING, &(struct pl)PL("found"));

  odict_entry_add( od_dht, "zoneid", ODICT_INT, (int64_t)zoneid);

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

  odict_entry_add( od_dht, "fbl", ODICT_INT, (int64_t)from_binlen);

  odict_entry_add( od_dht
                 , "br"
                 , ODICT_STRING
                 , &(struct pl){ .p=(const char *)record_binrep
                               , .l=TOL_ROUTE_LENGTH});

  odict_entry_add( od_dht, "bl", ODICT_INT, (int64_t)record_binlen);

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

int tol_command_send_dht_aquire( const uint8_t everip_forward[EVERIP_ADDRESS_LENGTH]
                               , const uint8_t everip_aquire[EVERIP_ADDRESS_LENGTH]
                               , uint8_t zoneid
                               , uint8_t root[EVERIP_ADDRESS_LENGTH]
                               , uint8_t from_binrep[TOL_ROUTE_LENGTH]
                               , uint8_t from_binlen )
{
  struct odict *od_dht = NULL;

  odict_alloc(&od_dht, 8);

  odict_entry_add( od_dht, "mode", ODICT_STRING, &(struct pl)PL("aquire"));

  odict_entry_add( od_dht, "zoneid", ODICT_INT, (int64_t)zoneid);

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

  odict_entry_add( od_dht, "fbl", ODICT_INT, (int64_t)from_binlen);

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


int tol_command_cb_dht( struct this_module *mod
                      , struct magi_melchior_rpc *rpc )
{
  int err = 0;
  const struct odict_entry *ode;
  struct tol_zone *zone = NULL;

  uint16_t tmp_zoneid;
  uint8_t *tmp_rootp;

  uint8_t *tmp_everip_record;

  if (!mod || !rpc) {
    error("[TREE][DHT] EINVAL\n");
    return EINVAL;
  }

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
    error("[TREE][DHT] no zoneid\n");
    goto out;
  }

  tmp_zoneid = (uint16_t)ode->u.integer;

  if (tmp_zoneid >= TOL_ZONE_COUNT) {
    err = EPROTO;
    goto out;
  }

  zone = &mod->zone[tmp_zoneid];

  ode = odict_lookup(rpc->in, "root");
  if (!ode || ode->type != ODICT_STRING) {
    error("[TREE][DHT] no root\n");
    err = EPROTO;
    goto out;
  }

  /* root must be same as everip address */
  if (ode->u.pl.l != EVERIP_ADDRESS_LENGTH) {
    error("[TREE][DHT] bad root length\n");
    err = EPROTO;
    goto out;
  } 

  tmp_rootp = (uint8_t *)ode->u.pl.p;

  /* if we are not the same root on the same zone, ignore! */
  if (memcmp(zone->root, tmp_rootp, EVERIP_ADDRESS_LENGTH)) {
    error("[TREE][DHT] bad root\n");
    err = EPROTO;
    goto out;
  }

  ode = odict_lookup(rpc->in, "everip");
  if (!ode || ode->type != ODICT_STRING) {
    error("[TREE][DHT] no everip\n");
    err = EPROTO;
    goto out;
  }

  /* check length of everip address */
  if (ode->u.pl.l != EVERIP_ADDRESS_LENGTH) {
    err = EPROTO;
    goto out;
  } 

  tmp_everip_record = (uint8_t *)ode->u.pl.p;

  ode = odict_lookup(rpc->in, "mode");
  if (!ode || ode->type != ODICT_STRING) {
    error("[TREE][DHT] no mode\n");
    err = EPROTO;
    goto out;
  }

  debug("[TREE][DHT] %r\n", &ode->u.pl);

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


#if 0
/* X:MEMO ignore caching for now */

        /* search for entry, and if found -- update */
        err = tol_dhti_add_or_update( zone
                                    , tmp_everip_record
                                    , tmp_pubkey
                                    , tmp_br
                                    , tmp_bl );
        if (err)
          goto out;
#endif

        /* forward */

        if (tol_everip_for_route( mod
                                , tmp_fbr
                                , everip_addr_route ))
          goto out;

        tol_command_send_dht_found( everip_addr_route
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

        if (!zone->parent) { /* only save if we are parent */
          /* in the future, allow leaves to store as well */
          /* okay, save it here */
          err = tol_dhti_add_or_update( zone 
                                      , tmp_everip_record
                                      , tmp_pubkey
                                      , tmp_br
                                      , tmp_bl );
          if (err)
            goto out;
        }

        /* forward! */
        {
          /*struct le *le;
          struct tol_neighbor *tn = NULL;*/

          if (zone->parent) {
            /* easy path */

            if (!memcmp( zone->parent->everip
                       , rpc->everip_addr
                       , EVERIP_ADDRESS_LENGTH)) {
              /* we already came from there! */
              goto out;
            }

            (void)tol_command_send_dht_notify( zone->parent->everip
                                             , tmp_everip_record
                                             , tmp_pubkey
                                             , tmp_zoneid
                                             , tmp_rootp
                                             , tmp_br
                                             , tmp_bl );
          }
          else
          {
#if 0
            /* no parent, we shelve off to all local peers */
            LIST_FOREACH(&zone->nodes_all, le) {
              tn = le->data;

              if (!memcmp( tn->everip
                         , rpc->everip_addr
                         , EVERIP_ADDRESS_LENGTH)) {
                continue;
              }
              (void)tol_command_send_dht_notify( peer->cp.everip_addr
                                               , tmp_everip_record
                                               , tmp_pubkey
                                               , tmp_zoneid
                                               , tmp_rootp
                                               , tmp_br
                                               , tmp_bl );
            }
#endif
          }
        }

        /*error("DHT NOTIFY!!!\n");*/
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
          struct tol_dhti *dhti = NULL;

          /* is it us? */
          if (!memcmp(mod->my_everip, tmp_everip_record, EVERIP_ADDRESS_LENGTH)) {
            if (tol_everip_for_route( mod
                                    , tmp_fbr
                                    , everip_addr_route )) {
              goto out;
            }
            tol_command_send_dht_found( everip_addr_route
                                      , mod->my_everip
                                      , mod->my_public_key
                                      , tmp_zoneid
                                      , tmp_rootp
                                      , tmp_fbr /* from */
                                      , tmp_fbl /* from */
                                      , mod->zone[tmp_zoneid].binrep /* record */
                                      , mod->zone[tmp_zoneid].binlen /* record */
                                      );

            /* do not forward; goto out */
            goto out;
          }

          LIST_FOREACH(&zone->dhti_all, le) {
            dhti = le->data;
            /* if we have record, send it back */
            if (!memcmp(dhti->everip_addr, tmp_everip_record, EVERIP_ADDRESS_LENGTH)) {
              if (tol_everip_for_route( mod
                                      , tmp_fbr
                                      , everip_addr_route )) {
                goto out;
              }

              tol_command_send_dht_found( everip_addr_route
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

        /*error("DHT AQUIRE!!!\n");*/

        /* if not found, forward on! */
        if (!zone->parent)
          goto out;

        tol_command_send_dht_aquire( zone->parent->everip
                                   , tmp_everip_record
                                   , tmp_zoneid
                                   , tmp_rootp
                                   , tmp_fbr
                                   , tmp_fbl
                                   );

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

