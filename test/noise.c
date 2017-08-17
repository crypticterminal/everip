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
#include "test.h"

#define PRIVATEKEY_A "355dd5874b2f0cbd45bb82c7ed61ebb1f0f9f8ca0b287efe0951cd11635aac37"
#define PUBLICKEY_A "EE04BA528A74ACB3BF5702DDB1BC72BCABFF21D3BD6540092238C15763EAD265"

#define PRIVATEKEY_B "a43c1b1c5af9960432250f19c17ffa10ad4ca4675d69d681f9073791d07eed2c"
#define PUBLICKEY_B "BE3137ECB72C3D9CCD5911B0C146ED43B6E8D2FFB1B9537EAA0F6E974457842E"

#define BUFFER_PRE_LEN 300U

static struct noise_engine *ne1 = NULL;
static struct noise_session *ns1 = NULL;

static struct noise_engine *ne2 = NULL;
static struct noise_session *ns2 = NULL;


static struct mbuf *
_tool_create_mb(const char *x)
{
  struct mbuf *mb;
  size_t len = (((str_len(x)+1) / 8) + 1) * 8;
  mb = mbuf_alloc(len + BUFFER_PRE_LEN);
  if (!mb)
    return NULL;

  memset(mb->buf, 0, mb->size);

  mb->pos = BUFFER_PRE_LEN;
  mb->end = len + BUFFER_PRE_LEN;

  mbuf_write_str(mb, x); /* write message */

  mbuf_set_pos(mb, BUFFER_PRE_LEN);

  return mb;
}

#if 0
static int mb_encrypt( struct mbuf **mbp
                     , struct noise_session *sess
                     , const char *x)
{
  int err = 0;
  struct mbuf *mb;
  int len = (((str_len(x)+1) / 8) + 1) * 8;

  mb = mbuf_alloc(len + BUFFER_PRE_LEN);
  ASSERT_TRUE(mb != NULL);
  memset(mb->buf, 0, mb->size);

  mb->pos = BUFFER_PRE_LEN;
  mb->end = len + BUFFER_PRE_LEN;

  mbuf_write_str(mb, x); /* write message */

  mbuf_set_pos(mb, BUFFER_PRE_LEN);
  ASSERT_TRUE(!noise_session_encrypt(sess, mb));

  *mbp = mb;

out:
  if (err) {
    mb = mem_deref(mb);
  }
  return err;
}

static int mb_decrypt( struct mbuf *mb
                     , struct noise_session *sess
                     , const char *x)
{
  int err = 0;
  if (!x) {
    ASSERT_TRUE(caengine_session_decrypt(sess, mb));
  } else {
    ASSERT_TRUE(!caengine_session_decrypt(sess, mb));
    TEST_STRCMP(x, str_len(x), mbuf_buf(mb), str_len(x));
  }
out:
  return err;
}

static int do_encdec( struct noise_session *src
                    , struct noise_session *dst
                    , const char *x
                    , bool expect_ok)
{
  int err = 0;
  struct mbuf *mb = NULL;
    err = mb_encrypt( &mb, ctx, ctx->sess2, x);
  TEST_ERR(err);
  ASSERT_TRUE(mb != NULL);

  err = mb_decrypt( ctx, mb, ctx->sess1, expect_ok ? x : NULL);
  TEST_ERR(err);

out:
  mb = mem_deref(mb);
  return err;
}

#endif


static void _ns2_send_h(struct noise_session *s, struct mbuf *mb, void *arg)
{
  debug("_ns2_send_h <%p>\n", s);

  if (!ns1) {
    error("ns1 should exist!\n");
    return;
  }

  /*noise_engine_recieve(ne1, mb, );*/

}

static void _ns2_event_h( struct noise_session *s
                        , enum NOISE_SESSION_EVENT event
                        , void *arg)
{
  debug("_ns2_event_h <%p> %u\n", s, event);
  return;
}

static void _ns1_send_h(struct noise_session *s, struct mbuf *mb, void *arg)
{
  debug("_ns1_send_h <%p>\n", s);
  /*noise_engine_recieve(ne2, mb);*/
}

static void _ns1_event_h( struct noise_session *s
                        , enum NOISE_SESSION_EVENT event
                        , void *arg)
{
  debug("_ns1_event_h <%p> %u\n", s, event);

  if (event == NOISE_SESSION_EVENT_BEGIN_PILOT) {
    struct mbuf *mb = _tool_create_mb("hello, noise!");
    //error("BEFORE: [%W]\n", mbuf_buf(mb), mbuf_get_left(mb));
    noise_session_send(s, mb);
    //error("AFTER : [%W]\n", mbuf_buf(mb), mbuf_get_left(mb));
    mb = mem_deref(mb);
  }

  return;
}

static void _recv_h( struct noise_session *s
                   , struct mbuf *mb
                   , void *arg)
{
  error("recv_h! <%p>\n", s);
}

int test_noise(void)
{
  int err = 0;
  struct mbuf *mb;

  uint8_t a_pub[NOISE_PUBLIC_KEY_LEN];
  uint8_t a_prv[NOISE_PUBLIC_KEY_LEN];
  uint8_t b_pub[NOISE_PUBLIC_KEY_LEN];
  uint8_t b_prv[NOISE_PUBLIC_KEY_LEN];

  str_hex(a_pub, NOISE_PUBLIC_KEY_LEN, PUBLICKEY_A);
  str_hex(a_prv, NOISE_PUBLIC_KEY_LEN, PRIVATEKEY_A);
  str_hex(b_pub, NOISE_PUBLIC_KEY_LEN, PUBLICKEY_B);
  str_hex(b_prv, NOISE_PUBLIC_KEY_LEN, PRIVATEKEY_B);

  err = noise_engine_test_counter();
  TEST_ERR(err);

  err = noise_engine_init( &ne1 );
  TEST_ERR(err);

  noise_si_private_key_set( &ne1->si, a_prv );

  TEST_MEMCMP(a_pub, NOISE_PUBLIC_KEY_LEN, ne1->si.public, NOISE_PUBLIC_KEY_LEN);

  err = noise_engine_init( &ne2 );
  TEST_ERR(err);

  noise_si_private_key_set( &ne2->si, b_prv );
  
  TEST_MEMCMP(b_pub, NOISE_PUBLIC_KEY_LEN, ne2->si.public, NOISE_PUBLIC_KEY_LEN);

  /* create sessions */
  err = noise_session_new( &ns1, ne1, 0, b_pub, NULL);
  TEST_ERR(err);

  err = noise_session_new( &ns2, ne2, 0, a_pub, NULL);
  TEST_ERR(err);

  /* simple test */
  noise_session_hs_step1_pilot(ns1, false, NULL);

  mb = _tool_create_mb("kristopher!");
  noise_session_send(ns2, mb);
  mb = mem_deref(mb);

  mb = _tool_create_mb("nanndeshouka");
  noise_session_send(ns1, mb);
  mb = mem_deref(mb);

  /*tmr_debug();*/

out:
  ne1 = mem_deref(ne1);
  ne2 = mem_deref(ne2);
  ns1 = mem_deref(ne1);
  ns2 = mem_deref(ne2);
  return err;
}

