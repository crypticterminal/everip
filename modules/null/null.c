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

static struct conduit_peer *cp = NULL;

static int _peer_create( struct conduit_peer **peerp
                       , struct pl *key
                       , struct pl *host
                       , void *arg)
{

  (void)key;
  (void)host;
  (void)arg;

  *peerp = cp;

  return 0;
}

static int module_init(void)
{
  struct conduit *conduit = NULL;

  conduits_register( &conduit
                   , everip_conduits()
                   , CONDUIT_FLAG_VIRTUAL
                   , "NULL"
                   , "Virtual Conduit"
                   );

  if (!conduit)
    return ENOMEM;

  cp = mem_zalloc(sizeof(*cp), NULL);
  if (!cp)
    return ENOMEM;

  conduit_register_peer_create( conduit
                              , _peer_create
                              , NULL);

  return 0;
}


static int module_close(void)
{
  cp = mem_deref(cp);
  return 0;
}


const struct mod_export DECL_EXPORTS(null) = {
  "null",
  "conduit",
  module_init,
  module_close
};
