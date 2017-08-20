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

struct treeoflife_csock {
  struct conduit *conduit;
  struct list peers;
  struct hash *peers_addr;
#if 0

  parents
  children

#endif
};

static struct treeoflife_csock *g_tol = NULL;

static bool _peer_debug(struct le *le, void *arg)
{
  struct re_printf *pf = arg;
  return false;
}

static int _conduit_debug(struct re_printf *pf, void *arg)
{
  int err = 0;
  struct treeoflife_csock *tol_c = arg;

  re_hprintf(pf, " {Tree of Life has no Peers}\n");

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

  hash_alloc(&g_tol->peers_addr, 8);

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
