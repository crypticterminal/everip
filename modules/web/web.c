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

/**
 * 
 * CONDUIT/WEBSOCKET
 * 
 * [説明]
 * A conduit for Websocket based connectivity.
 * 
 * [役割]
 * The Websocket conduit provides layer-3 connectivity for EVER/IP packets
 * over TCP/IP on HTTP port 80. Websocket does not support local node discovery
 * because it is meant to connect nodes together over the global internet
 * specifically. Websocket supports virtual node discovery, which means that if
 * another node is connected to the websocket network, the two nodes should be
 * able to search and find each other.
 * 
 * [特徴]
 * Websocket can be useful because it is based on TCP/IP and HTTP, which is
 * predominately the most unfiltered combination in the world. This means that
 * nodes have a higher chance of seeing one another and becoming connected.
 * 
 * [Input/Output]
 * The Websocket conduit sends and receives Noise-Encrypted packets
 * between the OS/network and the Noise module over TCP/IP and the HTTP port 80.
 * 
**/

#include <re.h>
#include <everip.h>

struct this_module;

struct ws_client {
  struct le le;
  struct dnsc *dnsc;
  struct websock *ws;
  struct http_cli *http;
  struct websock_conn *wc;

  struct this_module *ctx;

  uint64_t last_jiffy;

  struct tmr tmr_kick;

  char uri[256];

};

struct wsc_peer {
  struct conduit_peer cp;
  struct le le;
  struct this_module *mod;
  uint8_t everip_addr[EVERIP_ADDRESS_LENGTH];
};

struct this_module {
  struct conduit *conduit;

  struct hash *peers;

  struct list ws_clients;
  struct tmr tmr_maintain;
};

static struct this_module *g_mod = NULL;

#define WEBSOCKET_V "v1"
#define WEB_RECONNECT_TIMEOUT_MS 4000
#define WEBSOCKET_MAINTAIN_TMR_MS 1000

static const char g_useragent[] = "ConnectFree(R) EVER/IP(R) v" EVERIP_VERSION;

static void module_wsc_tmr_retry_h( void *arg );
static int wsc_alloc( struct ws_client **wscp
                    , struct this_module *mod
                    , const struct sa *bind
                    , uint64_t ms_to_activation );

/* -- debug stuff -- */

static bool _wsc_debug(struct le *le, void *arg)
{
  struct re_printf *pf = arg;
  struct ws_client *wsc = le->data;
  re_hprintf(pf, "→ %J [%u]\n", http_client_bound(wsc->http), wsc->last_jiffy);
  return false;
}

static int _conduit_debug(struct re_printf *pf, void *arg)
{
  int err = 0;
  struct this_module *mod = arg;

  list_apply(&mod->ws_clients, true, _wsc_debug, pf);

  return err;
}

/* ---- wsc peer layer ----- */

static bool wsc_peer_hash_h(struct le *le, void *arg)
{
  struct wsc_peer *wp = le->data;
  return !memcmp(wp->everip_addr, (const uint8_t *)arg, EVERIP_ADDRESS_LENGTH);
}

static void wsc_peer_destructor(void *data)
{
  struct wsc_peer *wp = data;
  /* x:start process cp */
  conduit_peer_deref(&wp->cp);
  /* x:end process cp */
  list_unlink(&wp->le);

  /*error("wsc_peer_destructor\n");*/

}

static int wsc_peer_alloc( struct wsc_peer **wpp
                         , struct this_module *mod
                         , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH]
                         , uint8_t *new_peer
                         )
{
  int err = 0;
  struct wsc_peer *wp = NULL;

  if (!mod || !everip_addr)
    return EINVAL;

  wp = list_ledata(hash_lookup( mod->peers
                              , *(uint32_t *)(void *)everip_addr
                              , wsc_peer_hash_h
                              , (void *)everip_addr ));

  if (wp) {
    *new_peer = 0;
    *wpp = wp;
    return err;
  }

  wp = mem_zalloc(sizeof(*wp), wsc_peer_destructor);
  if (!wp)
    return ENOMEM;

  *new_peer = 1;

  wp->cp.conduit = mod->conduit;
  wp->mod = mod;
  memcpy(wp->everip_addr, everip_addr, EVERIP_ADDRESS_LENGTH);
  hash_append(mod->peers, *(uint32_t *)(void *)everip_addr, &wp->le, wp);

  *wpp = wp;

  return err;
}

/* ---- websocket client layer ----- */

static int wsc_send_register( struct ws_client *wsc )
{
  int err = 0;
  struct mbuf *mb = NULL;
  uint8_t public_sign_key[32];
  struct noise_engine *ne = NULL;

  if (!wsc || !wsc->wc)
    return EINVAL;

  ne = everip_noise();
  if (!ne)
    return EINVAL;

  mb = mbuf_alloc(512);
  if (!mb)
    return ENOMEM;

  mb->pos = 114;

  /* write useragent */
  err = mbuf_printf(mb, "%s (%s/%s)", g_useragent, sys_os_get(), sys_arch_get());
  if (err)
    goto out;

  /* get pubkey from noise engine */
  cryptosign_pk_fromskpk(public_sign_key, ne->sign_keys);

  /* header = 114U */
  /*[SWITCH/TYPE 16U][SIGNATURE 64U][PUBLIC_KEY 32U][TAI64N 12U][OPTIONS 4U]*/
  mbuf_set_pos(mb, 0);

  /* switch/type */
  mbuf_write_u16(mb, arch_htobe16(1)); /* 1 = register */

  /* wait for sig later */
  mbuf_advance(mb, CRYPTOSIGN_SIGNATURE_LENGTH/* 64U */);

  /* write public key */
  mbuf_write_mem(mb, public_sign_key, 32);
  
  /* {t} */
  tai64n_now( mbuf_buf(mb) );
  mbuf_advance(mb, TAI64_N_LEN);

  /* options -- keep blank for now */
  mbuf_write_u32(mb, 0);

  /* go back to top of sign stack */
  mbuf_set_pos(mb, 2);

  /* sign out (must start at where SIGNATURE begins, 64 bits before content) */
  cryptosign_bytes(ne->sign_keys, mbuf_buf(mb), mbuf_get_left(mb));

  /* top of packet */
  mbuf_set_pos(mb, 0);

  err = websock_send( wsc->wc
                    , WEBSOCK_BIN
                    , "%b"
                    , mbuf_buf(mb), mbuf_get_left(mb)
                    );
  if (err)
    goto out;

out:
  mb = mem_deref( mb );
  return err;
}

static int wsc_send_search( struct ws_client *wsc
                          , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH] )
{
  int err = 0;
  struct mbuf *mb = NULL;

  if (!wsc || !wsc->wc)
    return EINVAL;

  mb = mbuf_alloc(512);
  if (!mb)
    return ENOMEM;

  /* header = 114U */
  /* [SWITCH/TYPE 16U][EVERIP 16B/128U] */
  mbuf_set_pos(mb, 0);

  /* switch/type */
  mbuf_write_u16(mb, arch_htobe16(2)); /* 2 = search */

  mbuf_write_mem(mb, everip_addr, EVERIP_ADDRESS_LENGTH);

  /* top of packet */
  mbuf_set_pos(mb, 0);

  err = websock_send( wsc->wc
                    , WEBSOCK_BIN
                    , "%b"
                    , mbuf_buf(mb), mbuf_get_left(mb)
                    );
  if (err)
    goto out;

out:
  mb = mem_deref( mb );
  return err;
}

static void ws_handle_shutdown(void *arg)
{
  (void)arg;
}

static void wsc_handler_estab(void *arg)
{
  struct ws_client *wsc = arg;
  int err = 0;

  /*error("wsc_handler_estab: CONNECTED!\n");*/

  err = wsc_send_register( wsc );

  if (err) {
    error("wsc_handler_estab: %m\n", err);
  }
}


static void wsc_handler_recv( const struct websock_hdr *hdr
                            , struct mbuf *_mb, void *arg )
{
  int err = 0;
  uint16_t type = 0;
  struct mbuf *mb = NULL;
  struct ws_client *wsc = arg;

  uint8_t *in_everip = NULL;
  uint8_t *in_pubkey = NULL;

  (void)wsc;


  if (mbuf_get_left(mb) > 1500)
    goto out;

  mb = mbuf_alloc( EVER_OUTWARD_MBE_LENGTH * 2 );
  if (!mb)
    goto out;

  mb->pos = EVER_OUTWARD_MBE_POS;
  mb->end = EVER_OUTWARD_MBE_POS;

  mbuf_write_mem(mb, mbuf_buf(_mb), mbuf_get_left(_mb));

  mb->pos = EVER_OUTWARD_MBE_POS;

  /*error("wsc_handler_recv: %w\n", mbuf_buf(mb), mbuf_get_left(mb));*/

  if (mbuf_get_left(mb) < 2)
    goto out;

  type = arch_betoh16(mbuf_read_u16(mb));

  switch (type) {
    case 256: /* server search response */
    {
      int err_proto = 0;
      uint8_t new_peer = 0;
      struct wsc_peer *wp = NULL;

      if (mbuf_get_left(mb) < (16 + 32))
        goto out;
      in_everip = mbuf_buf(mb);
      mbuf_advance(mb, 16);
      in_pubkey = mbuf_buf(mb);

      err_proto = wsc_peer_alloc( &wp
                                , wsc->ctx
                                , in_everip
                                , &new_peer
                                );
      if (err_proto || !wp)
        goto out;


      err_proto = conduit_peer_initiate( &wp->cp
                                       , wsc->ctx->conduit
                                       , in_pubkey
                                       , true );

      if (err_proto && new_peer) {
        wp = mem_deref( wp );
      }
      break;
    }
    case 512: /* server forward response */
    {
      /* [SWITCH 2B][EVERIP 16B][MSG] */
      int err_proto = 0;
      uint8_t new_peer = 0;
      struct wsc_peer *wp = NULL;

      in_everip = mbuf_buf(mb);
      mbuf_advance(mb, 16);

      err_proto = wsc_peer_alloc( &wp
                                , wsc->ctx
                                , in_everip
                                , &new_peer
                                );
      if (err_proto || !wp)
        goto out;

      if (conduit_incoming(wsc->ctx->conduit, &wp->cp, mb) && new_peer) {
        wp = mem_deref( wp );
      }

      break;
    }
    default:
      goto out;
  }

  wsc->last_jiffy = tmr_jiffies();

 out:
  if (mb) {
    mb = mem_deref(mb);
  }
  if (err) {
    error("wsc_handler_recv: %m\n", err);
  }
}


static void wsc_handler_close(int err, void *arg)
{
  struct ws_client *wsc = arg;
  struct ws_client *wsc_new = NULL;

  /* translate error code */
  error("wsc_handler_close: %m\n", err);

  /* if this fails, we really don't have much in the way of recourse */
  (void)wsc_alloc(&wsc_new
                 , wsc->ctx
                 , http_client_bound(wsc->http)
                 , WEB_RECONNECT_TIMEOUT_MS );
  list_append(&wsc->ctx->ws_clients, &wsc_new->le, wsc_new);

  wsc = mem_deref(wsc);

}

static void module_wsc_tmr_kick_h( void *arg )
{
  int err = 0;
  struct ws_client *wsc = arg;

  /* websocket connect */
  err = websock_connect( &wsc->wc, wsc->ws
                       , wsc->http, wsc->uri, 0
                       , &wsc_handler_estab
                       , &wsc_handler_recv
                       , &wsc_handler_close, wsc
                       , "User-Agent: %s (%s/%s)\r\n"
                       , g_useragent, sys_os_get(), sys_arch_get()
                       );
  if (err) {
    wsc = mem_deref(wsc);
  }

}

static void wsc_destructor(void *data)
{
  struct ws_client *wsc = data;

  list_unlink(&wsc->le);

  wsc->http = mem_deref(wsc->http);
  wsc->dnsc = mem_deref(wsc->dnsc);

  wsc->wc = mem_deref(wsc->wc);
  websock_shutdown(wsc->ws);
  mem_deref(wsc->ws);

  tmr_cancel(&wsc->tmr_kick);

}

static int wsc_alloc( struct ws_client **wscp
                    , struct this_module *mod
                    , const struct sa *bind
                    , uint64_t ms_to_activation )
{
  int err = 0;
  struct sa dns;
  struct ws_client *wsc = NULL;
  uint8_t everip_addr[EVERIP_ADDRESS_LENGTH];

  if (!wscp || !mod || !bind)
    return EINVAL;

  if ( sa_af(bind) != AF_INET
    || sa_is_linklocal(bind)
    || sa_is_loopback(bind) ) {
    /* websocket subsystem currently only supports IPv4 */
    return EINVAL;
  }

  error("[WS] attempting connection via %j\n", bind);

  wsc = mem_zalloc(sizeof(*wsc), wsc_destructor);
  if (!wsc)
    return ENOMEM;

  wsc->ctx = mod;

  /* get everip */
  everip_addr_copy(everip_addr);

  if (everip_addr[0] != 0xfc) {
    err = EINVAL;
    goto out;
  }

  /* dns */
  err |= sa_set_str(&dns, "8.8.8.8", 53);
  if (err)
    goto out;

  err = dnsc_alloc(&wsc->dnsc, NULL, &dns, 1);
  if (err)
    goto out;

  /* http client */
  err = http_client_alloc(&wsc->http, wsc->dnsc);
  if (err)
    goto out;

  err = http_client_bind(wsc->http, bind);
  if (err)
    goto out;

  /* websocket alloc */
  err = websock_alloc(&wsc->ws, ws_handle_shutdown, wsc);
  if (err)
    goto out;

  /* create url that includes our everip address */
  (void)re_snprintf( wsc->uri
                   , sizeof(wsc->uri)
                   , "http://ws." WEBSOCKET_V ".ever.network/" WEBSOCKET_V "/dock/%w"
                   , everip_addr, EVERIP_ADDRESS_LENGTH);


  tmr_init(&wsc->tmr_kick);

  tmr_start( &wsc->tmr_kick
           , ms_to_activation ? ms_to_activation : 1
           , &module_wsc_tmr_kick_h
           , wsc
           );

out:
  if (err) {
    wsc = mem_deref(wsc);
  } else {
    *wscp = wsc;
  }
  return err;
}


/* ---- conduit module layer ----- */

static int _conduit_search( const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH]
                          , void *arg )
{
  struct ws_client *wsc = NULL;
  struct this_module *mod = arg;

  debug("websocket: _conduit_search;\n");

  wsc = list_ledata(list_head(&mod->ws_clients));
  if (!wsc) {
    /* we don't have a connection to send this to; DROP */
    goto out;
  }

  wsc_send_search(wsc, everip_addr);

out:
  return 0;
}

/*static int _conduit_peer_create( struct conduit_peer **peerp
                                , struct pl *key
                                , struct pl *host
                                , void *arg )
{
  struct this_module *mod = arg;

  (void)key;
  (void)host;
  (void)mod;

  *peerp = NULL;

  return 0;
}*/

static int _conduit_sendto_outside( struct conduit_peer *peer
                                   , struct mbuf *mb
                                   , void *arg )
{
  int err = 0;
  size_t mb_pos = 0;
  struct wsc_peer *wp;
  struct ws_client *wsc = NULL;
  struct this_module *mod = arg;

  /*debug("_conduit_sendto_outside\n");*/

  if (!peer || !mod)
    return EINVAL;

  wp = container_of(peer, struct wsc_peer, cp);

  /*error("INSIDE [%u]%w\n", mbuf_get_left(mb), mbuf_buf(mb), mbuf_get_left(mb));*/

  mbuf_advance(mb, -(size_t)(2 /* switch */ + 16 /* everip */));

  mb_pos = mb->pos;

  mbuf_write_u16(mb, arch_htobe16(3)); /* 3 = send packet */

  mbuf_write_mem(mb, wp->everip_addr, EVERIP_ADDRESS_LENGTH);

  mbuf_set_pos(mb, mb_pos);

  /*error("WEBSOCKET: [%u]%w\n", mbuf_get_left(mb), mbuf_buf(mb), mbuf_get_left(mb));*/
  
  wsc = list_ledata(list_head(&wp->mod->ws_clients));
  if (!wsc) {
    /* we don't have a connection to send this to; DROP */
    goto out;
  }
  
  websock_send( wsc->wc
              , WEBSOCK_BIN
              , "%b"
              , mbuf_buf(mb), mbuf_get_left(mb)
              );

out:
  return err;
}

static int magi_event_watcher_h( enum MAGI_EVENTDRIVER_WATCH type
                               , void *data
                               , void *arg )
{
  int err = 0;
  struct le *le;
  struct ws_client *wsc = NULL;
  struct this_module *mod = arg;
  struct netevent_event *event = data;

  if (type != MAGI_EVENTDRIVER_WATCH_NETEVENT)
    goto out;

  if (!sa_isset(&event->sa, SA_ADDR))
    goto out;

  LIST_FOREACH(&mod->ws_clients, le) {
    wsc = le->data;
    if (sa_cmp(&event->sa, http_client_bound(wsc->http), SA_ADDR)) {
      break;
    } else {
      wsc = NULL;
    }
  }

  switch(event->type) {
    case NETEVENT_EVENT_ADDR_NEW:
      if (wsc) {
        wsc = mem_deref(wsc);
      }
      err = wsc_alloc(&wsc, mod, &event->sa, 0);
      if (err)
        goto out;
      list_append(&mod->ws_clients, &wsc->le, wsc);
      goto out;
    case NETEVENT_EVENT_ADDR_DEL:
      if (wsc) {
        wsc = mem_deref(wsc);
      }
      goto out;
    default:
      goto out;
  }

out:
  return 0;
}

static bool module_maintain_wsc_sort_h(struct le *le1, struct le *le2, void *arg)
{
  struct ws_client *wsc_1 = le1->data;
  struct ws_client *wsc_2 = le2->data;

  (void)arg;

  return wsc_1->last_jiffy >= wsc_2->last_jiffy;
}

static void module_maintain_tmr_h( void *arg )
{
  struct this_module *mod = arg;

  list_sort(&mod->ws_clients, &module_maintain_wsc_sort_h, mod);

  /* rebind */
  tmr_start( &mod->tmr_maintain
           , WEBSOCKET_MAINTAIN_TMR_MS
           , &module_maintain_tmr_h
           , mod
           );
}

static void module_destructor(void *data)
{
  struct this_module *mod = data;
  /*mod->wsc = mem_deref(mod->wsc);*/

  list_flush( &mod->ws_clients );

  hash_flush( mod->peers );
  mod->peers = mem_deref( mod->peers );

  g_mod->conduit = mem_deref( g_mod->conduit );
  tmr_cancel(&mod->tmr_maintain);
}

static int module_init(void)
{
  int err = 0;

  g_mod = mem_zalloc(sizeof(*g_mod), module_destructor);
  if (!g_mod)
    return ENOMEM;

  hash_alloc(&g_mod->peers, 16);

  err = magi_eventdriver_handler_register( everip_eventdriver()
                                         , MAGI_EVENTDRIVER_WATCH_NETEVENT
                                         , magi_event_watcher_h
                                         , g_mod );
  if (err) {
    error("websocket: magi_eventdriver_handler_register\n");
    return err;
  }

  conduits_register( &g_mod->conduit
                   , everip_conduits()
                   , 0
                   , "WEB"
                   , "Websocket"
                   );

  if (!g_mod->conduit) {
    err = ENOMEM;
    goto out;
  }

  mem_ref( g_mod->conduit );

/*  conduit_register_peer_create( g_mod->conduit
                              , _conduit_peer_create
                              , g_mod);*/

  conduit_register_search_handler( g_mod->conduit
                                 , _conduit_search
                                 , g_mod );

  conduit_register_send_handler( g_mod->conduit
                               , _conduit_sendto_outside
                               , g_mod);

  conduit_register_debug_handler( g_mod->conduit
                                , _conduit_debug
                                , g_mod );

  tmr_init(&g_mod->tmr_maintain);

  /* kickoff timer */
  tmr_start( &g_mod->tmr_maintain
           , WEBSOCKET_MAINTAIN_TMR_MS
           , &module_maintain_tmr_h
           , g_mod
           );

out:
  if (err) {
    g_mod = mem_deref( g_mod );
  }
  return err;
}

static int module_close(void)
{
  g_mod = mem_deref(g_mod);
  return 0;
}

const struct mod_export DECL_EXPORTS(web) = {
  "web",
  "conduit",
  module_init,
  module_close
};
