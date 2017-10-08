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

  for (int i = 0; i < TOL_ZONE_COUNT; ++i)
  {
    if (mod && mod->zone[i].parent == tn) {
      mod->zone[i].parent = NULL;
    }
    list_unlink(&tn->z[i].le_child);
  }    

  list_unlink(&tn->le_mod);
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

out:
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
  error("[TREE] magi_node_apply_h\n");

  if (event->status != MAGI_NODE_STATUS_OPERATIONAL)
    goto out;

  /* check if we have a conduit peer here... */

  tol_command_send_zone(mod, event->everip_addr);

out:
  return false;
}

static void tol_maintain_tmr_cb(void *data)
{
  struct this_module *mod = data;

  /*treeoflife_command_send_zone(tol_c, peer->cp.everip_addr);*/

  error("[TREE] tol_maintain_tmr_cb\n");

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
  uint32_t child_count = 0;
  struct tol_zone *zone = NULL;
  struct this_module *mod = data;

  error("[TREE] tol_maintain_children_tmr_cb\n");

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
    }
  }

  tmr_start( &mod->tmr_maintain_children
           , TOL_MAINTAIN_CHILDREN_MS
           , &tol_maintain_children_tmr_cb
           , mod
           );
}

static void module_destructor(void *data)
{
  struct this_module *mod = data;

  list_flush(&mod->all_neighbors);

  g_mod->conduit = mem_deref( g_mod->conduit );

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
    memcpy(g_mod->zone[i].root, g_mod->my_everip, EVERIP_ADDRESS_LENGTH);
    g_mod->zone[i].binlen = 1;
    memset(g_mod->zone[i].binrep, 0, TOL_ROUTE_LENGTH);
  }

  /* register with the system */
  err = magi_melchior_register( everip_magi_melchior()
                              , (void *)"tree"
                              , tol_command_callback
                              , g_mod );
  if (err) {
    error("treeoflife: magi_melchior_register\n");
    goto out;
  }

#if 0
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

  conduit_register_search_handler( g_mod->conduit
                                 , _conduit_search
                                 , g_mod );

  mem_ref( g_mod->conduit );
#endif

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
