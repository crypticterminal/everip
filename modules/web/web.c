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

struct this_module;

struct ws_client {
  struct dnsc *dnsc;
  struct websock *ws;
  struct http_cli *http;
  struct websock_conn *wc;

  struct this_module *ctx;

};

struct this_module {
  struct ws_client *wsc;
  struct tmr tmr_retry;
};

static struct this_module *g_mod = NULL;

#define WEB_RECONNECT_TIMEOUT_MS 4000

static const char g_useragent[] = "ConnectFree(R) EVER/IP(R) v" EVERIP_VERSION;

static void module_wsc_tmr_retry_h( void *arg );

/* ---- websocket client layer ----- */

static int wsc_register_send( struct ws_client *wsc )
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
  err = mbuf_printf(mb, "%s", g_useragent);
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

static void ws_handle_shutdown(void *arg)
{
  (void)arg;
}

static void wsc_handler_estab(void *arg)
{
  struct ws_client *wsc = arg;
  int err = 0;

  error("wsc_handler_estab: CONNECTED!\n");

  err = wsc_register_send( wsc );

  if (err) {
    error("wsc_handler_estab: %m\n", err);
  }
}


static void wsc_handler_recv(const struct websock_hdr *hdr,
             struct mbuf *mb, void *arg)
{
  struct ws_client *wsc = arg;
  int err = 0;

  (void)wsc;

/* out:*/
  if (err) {
    error("wsc_handler_recv: %m\n", err);
  }
}


static void wsc_handler_close(int err, void *arg)
{
  struct ws_client *wsc = arg;

  tmr_start( &wsc->ctx->tmr_retry
           , WEB_RECONNECT_TIMEOUT_MS
           , module_wsc_tmr_retry_h
           , wsc->ctx
           );

  /* translate error code */
  error("wsc_handler_close: %m\n", err);

  wsc = mem_deref(wsc);

}

static void wsc_destructor(void *data)
{
  struct ws_client *wsc = data;

  wsc->wc = mem_deref(wsc->wc);
  websock_shutdown(wsc->ws);
  mem_deref(wsc->ws);

  wsc->http = mem_deref(wsc->http);
  wsc->dnsc = mem_deref(wsc->dnsc);
}

static int wsc_alloc(struct ws_client **wscp, struct this_module *mod )
{
  int err = 0;
  char uri[256];
  struct sa dns;
  struct ws_client *wsc = NULL;

  if (!wscp || !mod)
    return EINVAL;

  wsc = mem_zalloc(sizeof(*wsc), wsc_destructor);
  if (!wsc)
    return ENOMEM;

  wsc->ctx = mod;

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

  /* websocket alloc */
  err = websock_alloc(&wsc->ws, ws_handle_shutdown, wsc);
  if (err)
    goto out;

  /* create url that includes our everip address */
  (void)re_snprintf( uri
                   , sizeof(uri)
                   , "http://160.16.126.97/v1/dock/%s"
                   , "fc46623a198dcb63febd3e658e40ca6f");

  /* websocket connect */
  err = websock_connect( &wsc->wc, wsc->ws
                        , wsc->http, uri, 0
                        , wsc_handler_estab
                        , wsc_handler_recv
                        , wsc_handler_close, wsc
                        , "User-Agent: %s\r\n", g_useragent
                        );
  if (err)
    goto out;

out:
  if (err) {
    wsc = mem_deref(wsc);
  } else {
    *wscp = wsc;
  }
  return err;
}


/* ---- conduit module layer ----- */

static void module_wsc_tmr_retry_h( void *arg )
{
  int err = 0;
  struct this_module *mod = arg;
  if (!mod)
    return;
  err = wsc_alloc(&mod->wsc, mod);
}

static void module_destructor(void *data)
{
  struct this_module *mod = data;
  mod->wsc = mem_deref(mod->wsc);
  tmr_cancel(&mod->tmr_retry);
}

static int module_init(void)
{
  int err = 0;

  g_mod = mem_zalloc(sizeof(*g_mod), module_destructor);
  if (!g_mod)
    return ENOMEM;

  err = wsc_alloc(&g_mod->wsc, g_mod);
  if (err)
    goto out;

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
