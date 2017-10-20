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

/*
 * UDP DIRECT
 */

#include <re.h>
#include <everip.h>

#define UDPD_DEFAULT_PORT 1988

struct this_module;

struct this_module {
  struct sa bound;
  struct udp_sock *us;
  struct conduit *conduit;
  struct hash *peers;
};

struct udpd_peer {
  struct conduit_peer cp;
  struct le le;
  struct sa sa;
};

static struct this_module *g_mod = NULL;

/* ----------- debug code ----------- */

static bool _peer_debug(struct le *le, void *arg)
{
  struct re_printf *pf = arg;
  struct udpd_peer *up = le->data;
  re_hprintf(pf, "→ %J %H\n", &up->sa, conduit_peer_debug, &up->cp);
  return false;
}

static int _conduit_debug(struct re_printf *pf, void *arg)
{
  int err = 0;
  struct this_module *mod = arg;
  hash_apply(mod->peers, _peer_debug, pf);
  return err;
}

static bool _peer_handler(struct le *le, void *arg)
{
  struct udpd_peer *up = le->data;
  return sa_cmp(&up->sa, (const struct sa *)arg, SA_ALL);
}

static void udp_peer_destructor(void *data)
{
  struct udpd_peer *up = data;
  /* x:start process cp */
  conduit_peer_deref(&up->cp);
  /* x:end process cp */
  list_unlink(&up->le);
}

static int _peer_create( struct conduit_peer **peerp
                       , struct pl *key
                       , struct pl *host
                       , void *arg)
{
  struct sa laddr;
  struct udpd_peer *up = NULL;
  struct this_module *mod = arg;

  if (!key || !host)
    return EINVAL;

  debug("[UDPD] _peer_create\n");

  (void)key;

  if (sa_decode(&laddr, host->p, host->l)) {
    if (sa_set(&laddr, host, UDPD_DEFAULT_PORT)) {
      error("[UDPD] Error: Invalid IP Address <%r>\n", host);
      return EINVAL;
    }
  }

  up = list_ledata(hash_lookup( mod->peers
                              , sa_hash(&laddr, SA_ALL)
                              , _peer_handler
                              , &laddr));

  if (!up) {
    up = mem_zalloc(sizeof(*up), udp_peer_destructor);
    if (!up)
      return ENOMEM;
    sa_cpy(&up->sa, &laddr);
    up->cp.conduit = mod->conduit;
    hash_append(mod->peers, sa_hash(&laddr, SA_ALL), &up->le, up);
  }

  debug("[UDPD] registering %J on UDP;\n", &up->sa);

  *peerp = &up->cp;

  return 0;
}

static void _recv_handler(const struct sa *src, struct mbuf *mb, void *arg)
{
  int err = 0;
  struct this_module *mod = arg;
  struct udpd_peer *up = NULL;
  bool new_peer = false;

  up = list_ledata(hash_lookup( mod->peers
                              , sa_hash(src, SA_ALL)
                              , _peer_handler
                              , (void *)src));

  if (!up) {
    up = mem_zalloc(sizeof(*up), udp_peer_destructor);
    if (!up)
      return;
    new_peer = true;
    sa_cpy(&up->sa, src);
    up->cp.conduit = mod->conduit;

    err = conduit_peer_initiate( &up->cp
                               , NULL /* no key */
                               , false /* no handshake */
                               );

    hash_append(mod->peers, sa_hash(src, SA_ALL), &up->le, up);
  }

  err = conduit_incoming(mod->conduit, &up->cp, mb);

  if (err && err != EALREADY) {
    up = mem_deref( up );
  }
}

static int _sendto_outside( struct conduit_peer *peer
                          , struct mbuf *mb
                          , void *arg )
{
  int err = 0;
  struct udpd_peer *up = NULL;
  struct this_module *mod = arg;

  if (!peer || !mod)
    return EINVAL;

  up = container_of(peer, struct udpd_peer, cp);

  (void)udp_send(mod->us, &up->sa, mb);

  return err;
}

static void module_destructor(void *data)
{
  struct this_module *mod = data;

  hash_flush( mod->peers );
  mod->peers = mem_deref( mod->peers );

  mod->us = mem_deref( mod->us );

  mod->conduit = conduits_unregister( mod->conduit );
  /* are we still holding onto it? */
  if (mod->conduit)
    mod->conduit = mem_deref( mod->conduit );
}

static int module_init(void)
{
  int err = 0;

  g_mod = mem_zalloc(sizeof(*g_mod), module_destructor);
  if (!g_mod)
    return ENOMEM;

  err = hash_alloc(&g_mod->peers, 16);
  if (err)
    goto out;

  err = sa_set_str( &g_mod->bound
                  , "0.0.0.0"
                  , everip_udpport_get() ? everip_udpport_get() : 0
                  );
  if (err)
    goto out;

  err = udp_listen_advanced( &g_mod->us
                           , &g_mod->bound
                           , _recv_handler
                           , true
                           , g_mod);
  if (err) {
    error("[udp] listen error (%m)\n", err);
    goto out;
  }

  udp_rxsz_set(g_mod->us, EVER_OUTWARD_MBE_LENGTH * 2); /* MTU 1500 max */
  udp_rxbuf_presz_set(g_mod->us, EVER_OUTWARD_MBE_POS);

  udp_sockbuf_set(g_mod->us, 24000);

  conduits_register( &g_mod->conduit
                   , everip_conduits()
                   , CONDUIT_FLAG_NONE
                   , "UDPD"
                   , "UDP DIRECT Driver"
                   );

  if (!g_mod->conduit) {
    err = ENOMEM;
    goto out;
  }

  mem_ref(g_mod->conduit);

  conduit_register_debug_handler( g_mod->conduit
                                , _conduit_debug
                                , g_mod );

  conduit_register_send_handler( g_mod->conduit
                               , _sendto_outside
                               , g_mod);

  conduit_register_peer_create( g_mod->conduit
                              , _peer_create
                              , g_mod);

out:
  if (err) {
    g_mod = mem_deref(g_mod);
  } else {
    info("[UDPD] UDP/IP4 registered on %J\n", &g_mod->bound);
  }
  return err;
}

static int module_close(void)
{
  g_mod = mem_deref(g_mod);
  return 0;
}

const struct mod_export DECL_EXPORTS(udpd) = {
  "udpd",
  "conduit",
  module_init,
  module_close
};
