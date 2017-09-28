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
#include <string.h>
#include "test.h"

struct test {
  struct websock *ws;
  struct websock_conn *wc_cli;
  struct websock_conn *wc_srv;
  uint32_t n_estab_cli;
  uint32_t n_recv_cli;
  uint32_t n_recv_srv;
  int err;
};

static const char test_payload[]     = "hello websockets";
static const char custom_useragent[] = "TEST v0.1";


static void abort_test(struct test *t, int err)
{
  t->err = err;
  re_cancel();
}


static void done(struct test *t)
{
  t->wc_cli = mem_deref(t->wc_cli);
  t->wc_srv = mem_deref(t->wc_srv);

  websock_shutdown(t->ws);
}


static void srv_websock_recv_handler(const struct websock_hdr *hdr,
             struct mbuf *mb, void *arg)
{
  struct test *test = arg;
  int err;

  test->n_recv_srv++;

  /* ECHO */
  err = websock_send(test->wc_srv, hdr->opcode,
         "%b", mbuf_buf(mb), mbuf_get_left(mb));
  if (err)
    abort_test(test, err);
}


static void srv_websock_close_handler(int err, void *arg)
{
  struct test *test = arg;
  (void)test;
  (void)err;
}


static void websock_shutdown_handler(void *arg)
{
  abort_test(arg, 0);
}


static void http_req_handler(struct http_conn *conn,
           const struct http_msg *msg, void *arg)
{
  struct test *test = arg;
  int err;

  ASSERT_TRUE(http_msg_hdr_has_value(msg, HTTP_HDR_USER_AGENT,
             custom_useragent));

  err = websock_accept(&test->wc_srv, test->ws, conn, msg,
           0, srv_websock_recv_handler,
           srv_websock_close_handler, test);
 out:
  if (err)
    abort_test(test, err);
}


static void cli_websock_estab_handler(void *arg)
{
  struct test *test = arg;
  int err;

  test->n_estab_cli++;

  err = websock_send(test->wc_cli, WEBSOCK_TEXT, test_payload);
  if (err)
    abort_test(test, err);
}


static void cli_websock_recv_handler(const struct websock_hdr *hdr,
             struct mbuf *mb, void *arg)
{
  struct test *test = arg;
  int err = 0;

  test->n_recv_cli++;

  ASSERT_EQ(WEBSOCK_TEXT, hdr->opcode);

  TEST_STRCMP(test_payload, strlen(test_payload),
        mbuf_buf(mb), mbuf_get_left(mb));

  done(test);

 out:
  if (err)
    abort_test(test, err);
}


static void cli_websock_close_handler(int err, void *arg)
{
  struct test *test = arg;
  (void)test;
  (void)err;

  /* translate error code */
  if (err) {
    abort_test(test, ENOMEM);
  }
}


static int test_websock_loop(void)
{
  struct http_sock *httpsock = NULL;
  struct http_cli *http_cli = NULL;
  struct dnsc *dnsc = NULL;
  struct sa srv, dns;
  struct test test;
  char uri[256];
  int err = 0;

  memset(&test, 0, sizeof(test));

  err |= sa_set_str(&srv, "127.0.0.1", 0);
  err |= sa_set_str(&dns, "127.0.0.1", 53);    /* note: unused */
  if (err)
    goto out;

  err = http_listen(&httpsock, &srv, http_req_handler, &test);
  if (err)
    goto out;

  err = tcp_sock_local_get(http_sock_tcp(httpsock), &srv);
  if (err)
    goto out;

  err = dnsc_alloc(&dnsc, NULL, &dns, 1);
  if (err)
    goto out;

  err = http_client_alloc(&http_cli, dnsc);
  if (err)
    goto out;

  err = websock_alloc(&test.ws, websock_shutdown_handler, &test);
  if (err)
    goto out;

  (void)re_snprintf(uri, sizeof(uri),
        "http://127.0.0.1:%u/", sa_port(&srv));
  err = websock_connect(&test.wc_cli, test.ws,
            http_cli, uri, 0,
            cli_websock_estab_handler,
            cli_websock_recv_handler,
            cli_websock_close_handler, &test,
            "User-Agent: %s\r\n", custom_useragent);
  if (err)
    goto out;

  err = re_main_timeout(500);
  if (err)
    goto out;

  if (test.err) {
    err = test.err;
    goto out;
  }

  /* verify results after traffic is successfully done */
  ASSERT_EQ(1, test.n_estab_cli);
  ASSERT_EQ(1, test.n_recv_cli);
  ASSERT_EQ(1, test.n_recv_srv);

 out:
  mem_deref(httpsock);
  mem_deref(test.wc_cli);
  mem_deref(test.ws);
  mem_deref(test.wc_srv);
  mem_deref(http_cli);
  mem_deref(dnsc);

  return err;
}


int test_websock_core(void)
{
  int err = 0;

  err |= test_websock_loop();

  return err;
}
