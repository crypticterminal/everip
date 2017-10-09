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

static struct this_module *g_mod = NULL;

/**/

int tol_everip_for_route( struct this_module *mod
                        , const uint8_t route[TOL_ROUTE_LENGTH]
                        , uint8_t everip_addr[EVERIP_ADDRESS_LENGTH])
{
  int places;
  struct le *le;
  struct tol_zone *zone;
  struct tol_neighbor *tn = NULL;
  struct tol_neighbor *tn_chosen = NULL;

  int local_diff = 0;
  int temp_diff = 0;
  int chosen_diff = 0;

  for (int i = 0; i < ZONE_COUNT; ++i) {
    zone = &mod->zone[i];

    if (!zone->active) {
      error( "[TREE] tol_everip_for_route :: zone not active!\n");
      continue;
    }

    info("SEARCHING FOR [%H]\n", stack_debug, route);

    local_diff = stack_linf_diff(route, zone->binrep, &places);

    info("LOCAL DIFF[%H] = %d[PLACES=%d]\n", stack_debug, zone->binrep, local_diff, places);

    LIST_FOREACH(&mod->all_neighbors, le) {
      tn = le->data;
      info( "TRYING NODE [%W]{%H}[%u]\n"
           , tn->everip, EVERIP_ADDRESS_LENGTH
           , stack_debug, tn->z[i].binrep
           , tn->z[i].binlen);
      if (!tn->z[i].binlen) {
        info("[TREE] SKIP SKIP\n");
        continue;
      }
      temp_diff = stack_linf_diff(route, tn->z[i].binrep, &places);
      if (temp_diff == 0 && !memcmp(route, tn->z[i].binrep, TOL_ROUTE_LENGTH)) {
        memcpy(everip_addr, tn->everip, EVERIP_ADDRESS_LENGTH);
        return 0;
      }
      info("TEMP DIFF = %d[PLACES=%d]\n", temp_diff, places);
      if (temp_diff < local_diff) {
        if (!tn_chosen || (temp_diff + 1) < chosen_diff) {
          tn_chosen = tn;
          chosen_diff = temp_diff;
        }
      }
    }
  }

  if (tn_chosen) {
    info("I CHOSE [%H][%W]\n", stack_debug, tn_chosen->z[0].binrep, tn_chosen->everip, EVERIP_ADDRESS_LENGTH);
    memcpy(everip_addr, tn_chosen->everip, EVERIP_ADDRESS_LENGTH);
    return 0;
  }

  return EADDRNOTAVAIL;
}

/**/

int treeoflife_ledbat_recv( struct mbuf *mb )
{
  /* trampoline */
  if (!g_mod)
    return 0;
  return tol_conduit_incoming(g_mod, mb);
}

uint16_t tol_get_childid(struct this_module *mod)
{
  uint16_t out;
  out = mod->child_counter;
  mod->child_counter = ++mod->child_counter % 127; /* lock to 127 for now */
  return out;
}

/**/

struct tol_neighbor *
tol_neighbor_find_byeverip( struct this_module *mod
                          , const uint8_t everip[EVERIP_ADDRESS_LENGTH] )
{
  struct le *le;
  struct tol_neighbor *tn;
  LIST_FOREACH(&mod->all_neighbors, le) {
    tn = le->data;
    if (!memcmp(tn->everip, everip, EVERIP_ADDRESS_LENGTH))
      return tn;
  }
  return NULL;
}

static void tol_neighbor_destructor(void *data)
{
  struct tol_neighbor *tn = data;
  struct this_module *mod = container_of(tn->le_mod.list, struct this_module, all_neighbors);

  list_unlink(&tn->le_mod);

  for (int i = 0; i < TOL_ZONE_COUNT; ++i)
  {
    if (mod && mod->zone[i].parent == tn) {
      tol_zone_reset(mod, &mod->zone[i]);
    }
    list_unlink(&tn->z[i].le_child);
  }

}

int tol_neighbor_alloc( struct tol_neighbor **tnp
                      , struct this_module *mod
                      , const uint8_t everip[EVERIP_ADDRESS_LENGTH] )
{
  int err = 0;
  struct tol_neighbor *tn = NULL;

  if (!tnp || !mod || !everip)
    return EINVAL;

  tn = tol_neighbor_find_byeverip(mod, everip);
  if (tn) {
    *tnp = tn;
    return EALREADY;
  }

  tn = mem_zalloc(sizeof(*tn), tol_neighbor_destructor);
  if (!tn)
    return ENOMEM;

  memcpy(tn->everip, everip, EVERIP_ADDRESS_LENGTH);

  list_append(&mod->all_neighbors, &tn->le_mod, tn);

  if (err) {
    tn = mem_deref(tn);
  } else {
    *tnp = tn;
  }
  return err;
}

/**/

static bool tol_magi_node_apply_h(const struct magi_e2e_event *event, void *arg)
{
  struct this_module *mod = arg;
  /*error("[TREE] magi_node_apply_h\n");*/

  if (event->status != MAGI_NODE_STATUS_OPERATIONAL)
    goto out;

  /*
   * check if we have a conduit peer here... 
   * and if we do, cut out
   */
  if (tol_peer_lookup_byeverip(mod, event->everip_addr))
    goto out;

  tol_command_send_zone(mod, event->everip_addr);

out:
  return false;
}

static void tol_maintain_tmr_cb(void *data)
{
  struct this_module *mod = data;

  /*treeoflife_command_send_zone(tol_c, peer->cp.everip_addr);*/

  /*error("[TREE] tol_maintain_tmr_cb\n");*/

  /*
   * get list from magi, but only actually send to nodes
   * that we have not issued as conduit_peers;
   */

  magi_node_apply(everip_magi(), &tol_magi_node_apply_h, mod);

  tmr_start( &mod->tmr_maintain
           , TOL_MAINTAIN_MS
           , &tol_maintain_tmr_cb
           , mod
           );
}

static void tol_maintain_children_tmr_cb(void *data)
{
  struct le *le;
  struct tol_neighbor *tn;
  uint32_t child_count = 0;
  struct tol_zone *zone = NULL;
  struct this_module *mod = data;

  /*error("[TREE] tol_maintain_children_tmr_cb\n");*/

  for (int i = 0; i < TOL_ZONE_COUNT; ++i)
  {
    zone = &mod->zone[i];
    child_count = list_count(&zone->children);
    if (child_count != zone->child_refresh_count) {
      info( "[TREE] child refresh change [%u->%u] in zone %u!\n"
          , zone->child_refresh_count
          , child_count
          , i);
      zone->child_refresh_count = child_count;
      /* do child push */
      LIST_FOREACH(&zone->children, le) {
        tn = le->data;
        tol_command_send_child(tn, i);
      }
    }
  }

  tmr_start( &mod->tmr_maintain_children
           , TOL_MAINTAIN_CHILDREN_MS
           , &tol_maintain_children_tmr_cb
           , mod
           );
}

static int magi_event_watcher_h( enum MAGI_EVENTDRIVER_WATCH type
                               , void *data
                               , void *arg )
{
  struct tol_neighbor *tn = NULL;
  struct magi_e2e_event *event = data;
  struct this_module *mod = arg;

  if (!mod || !event || type != MAGI_EVENTDRIVER_WATCH_E2E)
    return 0;

  tn = tol_neighbor_find_byeverip(mod, event->everip_addr);
  /*peer = tol_peer_lookup_byeverip(mod, event->everip_addr);*/

  switch (event->status) {
    case MAGI_NODE_STATUS_REMOVAL:
    case MAGI_NODE_STATUS_OFFLINE:
      error("TREEOFLIFE: node [%W] has gone offline!\n", event->everip_addr, EVERIP_ADDRESS_LENGTH);
      tn = mem_deref(tn);
      /*peer = mem_deref(peer);*/
      break;
//    case MAGI_NODE_STATUS_OPERATIONAL:
//      error("TREEOFLIFE: node [%W] is now operational!\n", event->everip_addr, EVERIP_ADDRESS_LENGTH);
//      break;
    default:
      break;
  }

  return 0;
}

int tol_zone_reset(struct this_module *mod, struct tol_zone *zone)
{
  uint16_t neighbor_count = 0;

  error("[TREE] tol_zone_reset\n");

  if (!mod || !zone)
    return EINVAL;

  /* first two bytes represent number of connected nodes in big endian */
  neighbor_count = (uint16_t)list_count(&mod->all_neighbors);
  neighbor_count = arch_htobe16(neighbor_count);
  memcpy(zone->root, mod->my_everip, EVERIP_ADDRESS_LENGTH);
  memcpy(zone->root, &neighbor_count, 2);
  zone->binlen = 1;
  memset(zone->binrep, 0, TOL_ROUTE_LENGTH);

  zone->parent = NULL;

  list_clear(&zone->children);
  list_flush(&mod->peers);
  list_flush(&zone->dhti_all);

  zone->active = true;

  return 0;
}

static void module_destructor(void *data)
{
  struct this_module *mod = data;

  list_flush(&mod->all_neighbors);

  mod->conduit = mem_deref( mod->conduit );

  hash_flush(mod->peers_addr);
  mod->peers_addr = mem_deref( g_mod->peers_addr );

  tmr_cancel(&mod->tmr_maintain);
  tmr_cancel(&mod->tmr_maintain_children);
}

static int module_init(void)
{
  int err = 0;

  g_mod = mem_zalloc(sizeof(*g_mod), module_destructor);
  if (!g_mod)
    return ENOMEM;

  everip_addr_copy(g_mod->my_everip);

  if (!everip_noise())
    return EINVAL;

  memcpy(g_mod->my_public_key, everip_noise()->si.public, NOISE_PUBLIC_KEY_LEN);

  for (int i = 0; i < TOL_ZONE_COUNT; ++i)
  {
    (void)tol_zone_reset(g_mod, &g_mod->zone[i]);
  }

  hash_alloc(&g_mod->peers_addr, 16);

  /* register with the system */
  err = magi_melchior_register( everip_magi_melchior()
                              , (void *)"tree"
                              , tol_command_callback
                              , g_mod );
  if (err) {
    error("treeoflife: magi_melchior_register\n");
    goto out;
  }

  err = magi_eventdriver_handler_register( everip_eventdriver()
                                         , MAGI_EVENTDRIVER_WATCH_E2E
                                         , magi_event_watcher_h
                                         , g_mod );
  if (err) {
    error("treeoflife: magi_eventdriver_handler_register\n");
    goto out;
  }

  conduits_register( &g_mod->conduit
                   , everip_conduits()
                   , CONDUIT_FLAG_VIRTUAL | CONDUIT_FLAG_SECONDARY
                   , "TREE"
                   , "Tree of Life"
                   );

  if (!g_mod->conduit) {
    err = ENOMEM;
    goto out;
  }

  conduit_register_debug_handler( g_mod->conduit
                                , tol_conduit_debug
                                , g_mod );

  conduit_register_search_handler( g_mod->conduit
                                 , tol_conduit_search
                                 , g_mod );

  conduit_register_send_handler( g_mod->conduit
                               , tol_conduit_sendto_virtual
                               , g_mod);

  mem_ref( g_mod->conduit );

  /* timer for maintain */

  tmr_init( &g_mod->tmr_maintain );
  tmr_start( &g_mod->tmr_maintain
           , TOL_MAINTAIN_MS
           , &tol_maintain_tmr_cb
           , g_mod
           );

  tmr_init( &g_mod->tmr_maintain_children );
  tmr_start( &g_mod->tmr_maintain_children
           , TOL_MAINTAIN_CHILDREN_MS
           , &tol_maintain_children_tmr_cb
           , g_mod
           );

out:
  if (err) {
    g_mod = mem_deref(g_mod);
  }
  return err;
}

static int module_close(void)
{
  g_mod = mem_deref(g_mod);
  return 0;
}

const struct mod_export DECL_EXPORTS(treeoflife) = {
  "treeoflife",
  "conduit",
  module_init,
  module_close
};
