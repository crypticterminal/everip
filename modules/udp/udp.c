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

struct udp_csock {
  struct udp_sock *us;
  struct udp_sock *us_bcast;
  uint16_t port;

  struct conduit *conduit;
  struct hash *peers;
  struct sa group;
};

struct udp_peer {
  struct conduit_peer cp;
  struct le le;
  struct sa sa;
};

static bool _peer_debug(struct le *le, void *arg)
{
  struct re_printf *pf = arg;
  struct udp_peer *up = le->data;
  re_hprintf(pf, "%J %H\n", &up->sa, conduit_peer_debug, &up->cp);
  return false;
}

static int _conduit_debug(struct re_printf *pf, void *arg)
{
  int err = 0;
  struct udp_csock *udp_c = arg;

  hash_apply(udp_c->peers, _peer_debug, pf);

  return err;
}

static int _sendto_outside(struct conduit_peer *peer, struct mbuf *mb, void *arg)
{
  int err = 0;
  struct udp_peer *up;
  struct udp_csock *udp_c = arg;

  if (!peer || !udp_c)
    return EINVAL;

  if (peer->flags & CONDUIT_PEER_FLAG_BCAST) {
    /*debug("Broadcasting! [%W]\n", mbuf_buf(mb), mbuf_get_left(mb));*/
    (void)udp_send(udp_c->us, &udp_c->group, mb);
  } else {
    up = container_of(peer, struct udp_peer, cp);

    debug( "got %zu bytes of data FOR %J\n"
         , mbuf_get_left(mb)
         , &up->sa);
    
    (void)udp_send(udp_c->us, &up->sa, mb);
  }
  return err;
}

// static struct csock *udp_handle_incoming( struct csock *csock
//                                        , struct mbuf *mb )
// {
//  struct udp_csock *udp_c = (struct udp_csock *)csock;
//  struct sa *dst;
//  struct sa bcast;
//  size_t pfix = mb->pos;
// 
//  mbuf_set_pos(mb, 0);
//  struct csock_addr *csaddr = (struct csock_addr *)(void *)mbuf_buf(mb);
// 
//  if (csaddr->flags & CSOCK_ADDR_BCAST) {
//    return NULL; /* not available on UDP */
//  }
// 
//  if (csaddr->flags & CSOCK_ADDR_BCAST) {
//    sa_set_str(&bcast, "255.255.255.255", udp_c->port);
//    dst = &bcast;
//  } else {
//    dst = &csaddr->a.sa;
//  }
// 
//  mbuf_set_pos(mb, pfix);
// 
//  debug("got %zu bytes of data FOR %J (salen=%u)\n",
//      mbuf_get_left(mb), dst, dst->len);
// 
//  (void)udp_send(udp_c->us, dst, mb);
// 
//  return NULL;
// }

static bool _peer_handler(struct le *le, void *arg)
{
  struct udp_peer *up = le->data;
  return sa_cmp(&up->sa, (const struct sa *)arg, SA_ALL);
}

static void udp_peer_destructor(void *data)
{
  struct udp_peer *up = data;
  /* x:start process cp */
  conduit_peer_deref(&up->cp);
  /* x:end process cp */
  list_unlink(&up->le);
}

static void _recv_handler( struct udp_csock *udp_c
                         , const struct sa *src
                         , struct mbuf *mb
                         , bool is_bcast )
{
  struct udp_peer *up = NULL;
  bool new_peer = false;

  up = list_ledata(hash_lookup( udp_c->peers
                              , sa_hash(src, SA_ALL)
                              , _peer_handler
                              , (void *)src));

  if (!up) {
    up = mem_zalloc(sizeof(*up), udp_peer_destructor);
    if (!up)
      return;
    new_peer = true;
    sa_cpy(&up->sa, src);
    up->cp.conduit = udp_c->conduit;
    hash_append(udp_c->peers, sa_hash(src, SA_ALL), &up->le, up);
  }

  if (is_bcast)
    up->cp.flags |= CONDUIT_PEER_FLAG_BCAST;

  if (conduit_incoming(udp_c->conduit, &up->cp, mb) && new_peer) {
    up = mem_deref( up );
  } else if (is_bcast) {
    /* remove bcast flag */
    up->cp.flags &= ~(CONDUIT_PEER_FLAG_BCAST);
  }

}

static void recv_handler(const struct sa *src, struct mbuf *mb, void *arg)
{
  struct udp_csock *udp_c = arg;
  debug( "got %zu bytes of UDP data from %J\n"
       , mbuf_get_left(mb)
       , src);
  _recv_handler(udp_c, src, mb, false);
}

static void recv_handler_bcast(const struct sa *src, struct mbuf *mb, void *arg)
{
  struct udp_csock *udp_c = arg;

  /*debug( "BCAST: got %zu bytes of UDP data from %J\n"
       , mbuf_get_left(mb)
       , src);*/
  _recv_handler(udp_c, src, mb, true);
}

static void udp_c_destructor(void *data)
{
  struct udp_csock *udp_c = data;

  udp_c->us = mem_deref(udp_c->us);

  udp_multicast_leave(udp_c->us_bcast, &udp_c->group);
  udp_c->us_bcast = mem_deref(udp_c->us_bcast);

  hash_flush( udp_c->peers );
  udp_c->peers = mem_deref( udp_c->peers );

  udp_c->conduit = mem_deref( udp_c->conduit );

}

static struct udp_csock *udp_c = NULL;

static int _peer_create( struct conduit_peer **peerp
                       , struct pl *key
                       , struct pl *host
                       , void *arg)
{
  struct sa laddr;
  struct udp_peer *up = NULL;

  if (!key || !host)
    return EINVAL;

  debug("_peer_create\n");

  (void)key;
  (void)arg;

  if (sa_decode(&laddr, host->p, host->l)) {
    if (sa_set(&laddr, host, 1988)) {
      error("Error: Invalid IP Address <%r>\n", host);
      return EINVAL;
    }
  }

  up = list_ledata(hash_lookup( udp_c->peers
                              , sa_hash(&laddr, SA_ALL)
                              , _peer_handler
                              , &laddr));

  if (!up) {
    up = mem_zalloc(sizeof(*up), udp_peer_destructor);
    if (!up)
      return ENOMEM;
    sa_cpy(&up->sa, &laddr);
    up->cp.conduit = udp_c->conduit;
    hash_append(udp_c->peers, sa_hash(&laddr, SA_ALL), &up->le, up);
  }

  debug("registering %J on UDP;\n", &up->sa);

  *peerp = &up->cp;

  return 0;
}

static int module_init(void)
{
  int err = 0;
  struct sa laddr;

  udp_c = mem_zalloc(sizeof(*udp_c), udp_c_destructor);
  if (!udp_c)
    return ENOMEM;

  udp_c->port = everip_udpport_get();

  (void)sa_set_str(&laddr, "0.0.0.0", udp_c->port);

  err = udp_listen(&udp_c->us, &laddr, recv_handler, udp_c);
  if (err) {
    re_fprintf(stderr, "udp listen error: %s\n", strerror(err));
    goto out;
  }

  udp_rxsz_set(udp_c->us, EVER_OUTWARD_MBE_LENGTH * 2); /* MTU 1500 max */
  udp_rxbuf_presz_set(udp_c->us, EVER_OUTWARD_MBE_POS);

  udp_sockbuf_set(udp_c->us, 24000);

  re_printf("listening on UDP socket: %J\n", &laddr);

  /* HANDLE BROADCASTER... */

  (void)sa_set_str(&laddr, "0.0.0.0", 8891);

  err = udp_listen_advanced( &udp_c->us_bcast
                           , &laddr
                           , recv_handler_bcast
                           , true
                           , udp_c);
  if (err) {
    re_fprintf(stderr, "udp listen error: %s\n", strerror(err));
    goto out;
  }

  switch (sa_af(&laddr)) {
    case AF_INET:
      err = sa_set_str(&udp_c->group, "224.0.0.1", 8891);
      break;
    case AF_INET6:
      err = sa_set_str(&udp_c->group, "ff02::1", 8891);
      break;
    default:
      err = EAFNOSUPPORT;
      break;
  }
  if (err)
    goto out;

  err = udp_multicast_join(udp_c->us_bcast, &udp_c->group);
  if (err)
    goto out;

  hash_alloc(&udp_c->peers, 16);

  conduits_register( &udp_c->conduit
                   , everip_conduits()
                   , CONDUIT_FLAG_BCAST
                   , "UDP"
                   , "UDP/IP Driver Conduit"
                   );

  if (!udp_c->conduit)
    return ENOMEM;

  mem_ref( udp_c->conduit );

  conduit_register_peer_create( udp_c->conduit
                              , _peer_create
                              , udp_c);

  conduit_register_send_handler( udp_c->conduit
                               , _sendto_outside
                               , udp_c);

  conduit_register_debug_handler( udp_c->conduit
                                , _conduit_debug
                                , udp_c );

out:
  if (err) {
    mem_deref(udp_c);
  }
  return err;
}


static int module_close(void)
{
  udp_c = mem_deref(udp_c);
  return 0;
}


const struct mod_export DECL_EXPORTS(udp) = {
  "udp",
  "conduit",
  module_init,
  module_close
};
