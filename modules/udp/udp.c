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

struct this_module {
  struct list udp_engines;
};

struct udp_engine {
  struct le le; /* struct this_module */
  struct conduit *conduit;
  struct hash *peers;

  struct sa bound;
  struct sa group;
  struct udp_sock *us;
  struct udp_sock *us_bcast;
  unsigned int if_index;
};

struct udp_peer {
  struct conduit_peer cp;
  struct le le;
  struct sa sa;
};

static struct this_module *g_mod = NULL;

/* ----------- debug code ----------- */

static bool _peer_debug(struct le *le, void *arg)
{
  struct re_printf *pf = arg;
  struct udp_peer *up = le->data;
  re_hprintf(pf, "→ %J %H\n", &up->sa, conduit_peer_debug, &up->cp);
  return false;
}

static int _conduit_debug(struct re_printf *pf, void *arg)
{
  int err = 0;
  struct udp_engine *ue = arg;
  hash_apply(ue->peers, _peer_debug, pf);
  return err;
}

/* ----------- peer/conduit code ----------- */

static int _sendto_outside( struct conduit_peer *peer
                          , struct mbuf *mb
                          , void *arg )
{
  int err = 0;
  struct udp_peer *up = NULL;
  struct udp_engine *ue = arg;

  if (!peer || !ue)
    return EINVAL;

  if (peer->flags & CONDUIT_PEER_FLAG_BCAST) {
    /*info("Broadcasting via %J [%W]\n", &ue->bound, mbuf_buf(mb), mbuf_get_left(mb));*/
    (void)udp_send(ue->us, &ue->group, mb);
  } else {
    up = container_of(peer, struct udp_peer, cp);

    /*debug( "got %zu bytes of data FOR %J\n"
         , mbuf_get_left(mb)
         , &up->sa);*/

    (void)udp_send(ue->us, &up->sa, mb);

  }

  return err;
}

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

static int _peer_create( struct conduit_peer **peerp
                       , struct pl *key
                       , struct pl *host
                       , void *arg)
{
  struct sa laddr;
  struct udp_peer *up = NULL;
  struct udp_engine *ue = arg;

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

  up = list_ledata(hash_lookup( ue->peers
                              , sa_hash(&laddr, SA_ALL)
                              , _peer_handler
                              , &laddr));

  if (!up) {
    up = mem_zalloc(sizeof(*up), udp_peer_destructor);
    if (!up)
      return ENOMEM;
    sa_cpy(&up->sa, &laddr);
    up->cp.conduit = ue->conduit;
    hash_append(ue->peers, sa_hash(&laddr, SA_ALL), &up->le, up);
  }

  debug("registering %J on UDP;\n", &up->sa);

  *peerp = &up->cp;

  return 0;
}


/* ----------- udp rx code ----------- */

static void _recv_handler( struct udp_engine *ue
                         , const struct sa *src
                         , struct mbuf *mb
                         , bool is_bcast )
{
  int err = 0;
  struct udp_peer *up = NULL;
  bool new_peer = false;

  up = list_ledata(hash_lookup( ue->peers
                              , sa_hash(src, SA_ALL)
                              , _peer_handler
                              , (void *)src));

  if (!up) {
    up = mem_zalloc(sizeof(*up), udp_peer_destructor);
    if (!up)
      return;
    new_peer = true;
    sa_cpy(&up->sa, src);
    up->cp.conduit = ue->conduit;
    hash_append(ue->peers, sa_hash(src, SA_ALL), &up->le, up);
  }

  if (is_bcast)
    up->cp.flags |= CONDUIT_PEER_FLAG_BCAST;

  err = conduit_incoming(ue->conduit, &up->cp, mb);

  if (err && err != EALREADY) {
    up = mem_deref( up );
  } else if (is_bcast) {
    /* remove bcast flag */
    up->cp.flags &= ~(CONDUIT_PEER_FLAG_BCAST);
  }

}

static void recv_handler(const struct sa *src, struct mbuf *mb, void *arg)
{
  struct udp_engine *ue = arg;
  /*debug( "got %zu bytes of UDP data from %J\n"
       , mbuf_get_left(mb)
       , src);*/
  _recv_handler(ue, src, mb, false);
}

static void recv_handler_bcast(const struct sa *src, struct mbuf *mb, void *arg)
{
  struct udp_engine *ue = arg;
  /*info( "BCAST got %zu bytes of UDP data from %J\n"
       , mbuf_get_left(mb)
       , src);*/
  _recv_handler(ue, src, mb, true);
}

/* ----------- udp engines ----------- */

static void udp_engine_destructor(void *data)
{
  struct udp_engine *ue = data;
  list_unlink(&ue->le);
  udp_multicast_leave(ue->us_bcast, &ue->group, ue->if_index);
  ue->us_bcast = mem_deref( ue->us_bcast );
  ue->us = mem_deref( ue->us );

  hash_flush( ue->peers );
  ue->peers = mem_deref( ue->peers );

  ue->conduit = conduits_unregister( ue->conduit );
  /* are we still holding onto it? */
  if (ue->conduit)
    ue->conduit = mem_deref( ue->conduit );
}

static int udp_engine_alloc( struct udp_engine **uep
                           , struct this_module *mod
                           , const char *if_name
                           , const struct sa *if_addr 
                           , unsigned int if_index )
{
  int err = 0;
  struct sa laddr;
  struct udp_engine *ue = NULL;

  char conduit_name[512];
  char conduit_desc[512];

  if (!uep || !mod || !if_name || !if_addr || !if_index)
    return EINVAL;

  ue = mem_zalloc(sizeof(*ue), udp_engine_destructor);
  if (!ue)
    return ENOMEM;

  ue->if_index = if_index;

  sa_cpy(&ue->bound, if_addr);

  err = sa_set_str(&ue->group, "ff02::1", 8891);
  if (err)
    goto out;

  err = sa_set_str(&laddr, "::", 8891);
  if (err)
    goto out;

  err = udp_listen_advanced( &ue->us_bcast
                           , &laddr
                           , recv_handler_bcast
                           , true
                           , ue);
  if (err) {
    error("[udp-b] listen error for %J (%m)\n", &laddr, err);
    goto out;
  }

#if 1
  /* set index sockoption */
  err = udp_setsockopt( ue->us_bcast
                      , IPPROTO_IPV6
                      , IPV6_MULTICAST_IF
                      , &if_index, sizeof(if_index) );
  if (err) {
    error("[udp-b] could not set index option (%m)\n", err);
    goto out;
  }
#endif

#if 0
{
  int do_loop = 1;
  err = udp_setsockopt( ue->us
                      , IPPROTO_IPV6
                      , IPV6_MULTICAST_LOOP
                      , &do_loop, sizeof(do_loop) );
  if (err) {
    error("[udp] could not set loop option (%m)\n", err);
    goto out;
  }
}
#endif

#if 1
  err = udp_multicast_join(ue->us_bcast, &ue->group, ue->if_index);
  if (err) {
    error("[udp] error joining multicast group %J (%m)\n", &ue->group, err);
    goto out;
  }
#endif

  
  sa_set_port(&ue->bound, 0);

  err = udp_listen_advanced( &ue->us
                           , &ue->bound
                           , recv_handler
                           , true
                           , ue);
  if (err) {
    error("[udp] listen error for %J (%m)\n", &ue->bound, err);
    goto out;
  }

  /* set index sockoption */
  err = udp_setsockopt( ue->us
                      , IPPROTO_IPV6
                      , IPV6_MULTICAST_IF
                      , &if_index, sizeof(if_index) );
  if (err) {
    error("[udp] could not set index option (%m)\n", err);
    goto out;
  }

  udp_rxsz_set(ue->us, EVER_OUTWARD_MBE_LENGTH * 2); /* MTU 1500 max */
  udp_rxbuf_presz_set(ue->us, EVER_OUTWARD_MBE_POS);

  udp_sockbuf_set(ue->us, 24000);

  udp_local_get(ue->us, &ue->bound);

  /* register with conduit system */

  hash_alloc(&ue->peers, 16);

  re_snprintf( conduit_name, sizeof(conduit_name)
             , "UDP%%%s", if_name);
  re_snprintf( conduit_desc, sizeof(conduit_desc)
             , "UDP/IP Driver Conduit on %j", if_addr);

  conduits_register( &ue->conduit
                   , everip_conduits()
                   , CONDUIT_FLAG_BCAST
                   , conduit_name
                   , conduit_desc
                   );

  if (!ue->conduit) {
    err = ENOMEM;
    goto out;
  }

  mem_ref( ue->conduit );

  conduit_register_peer_create( ue->conduit
                              , _peer_create
                              , ue);

  conduit_register_send_handler( ue->conduit
                               , _sendto_outside
                               , ue);

  conduit_register_debug_handler( ue->conduit
                                , _conduit_debug
                                , ue );


out:
  if (err) {
    ue = mem_deref(ue);
  } else {
    *uep = ue;
  }
  return err;
}

/* ----------- module code ----------- */

static int magi_event_watcher_h( enum MAGI_EVENTDRIVER_WATCH type
                               , void *data
                               , void *arg )
{
  int err = 0;
  struct le *le;
  struct udp_engine *ue = NULL;
  struct this_module *mod = arg;
  struct netevent_event *event = data;

  if (type != MAGI_EVENTDRIVER_WATCH_NETEVENT)
    goto out;

  /* we require a name each interface */
  if (!(event->if_options & NETEVENT_EVENT_OPT_NAME))
    goto out;

  /* we require an index for link local on ipv6 */
  if (!(event->if_options & NETEVENT_EVENT_OPT_INDEX))
    goto out;

  /* we check interface kind */
  if ( !(event->if_options & NETEVENT_EVENT_OPT_KIND)
    || ( event->if_kind != NETEVENTS_IFACE_KIND_ETHERNET
      && event->if_kind != NETEVENTS_IFACE_KIND_WIRELESS) )
    goto out;

  if (!sa_isset(&event->sa, SA_ADDR))
    goto out;

  /* only accept broadcast over ipv6 */
  if (sa_af(&event->sa) != AF_INET6)
    goto out;

  /* only bind to link local addresses */
  if ( !sa_is_linklocal( &event->sa ) )
    goto out;

  LIST_FOREACH(&mod->udp_engines, le) {
    ue = le->data;
    if (sa_cmp(&event->sa, &ue->bound, SA_ADDR)) {
      break;
    } else {
      ue = NULL;
    }
  }

  switch(event->type) {
    case NETEVENT_EVENT_ADDR_NEW:
      if (ue) {
        ue = mem_deref(ue);
      }

      err = udp_engine_alloc(&ue, mod, event->if_name, &event->sa, event->if_index);
      if (err)
        goto out;

      list_append(&mod->udp_engines, &ue->le, ue);
      goto out;
    case NETEVENT_EVENT_ADDR_DEL:
      if (ue) {
        ue = mem_deref(ue);
      }
      goto out;
    default:
      goto out;
  }

out:
  return 0;
}

static void module_destructor(void *data)
{
  struct this_module *mod = data;
  list_flush(&mod->udp_engines);
}

static int module_init(void)
{
  int err = 0;

  g_mod = mem_zalloc(sizeof(*g_mod), module_destructor);
  if (!g_mod)
    return ENOMEM;

  list_init(&g_mod->udp_engines);

  /* init net events */
#if 1
  err = magi_eventdriver_handler_register( everip_eventdriver()
                                         , MAGI_EVENTDRIVER_WATCH_NETEVENT
                                         , magi_event_watcher_h
                                         , g_mod );
  if (err) {
    error("websocket: magi_eventdriver_handler_register\n");
    return err;
  }
#else
  {
    struct udp_engine *ue = NULL;
    (void)sa_set_str(&laddr, "::", 0);
    err = udp_engine_alloc(&ue, g_mod, &laddr, 0);
    if (err)
      goto out;

    list_append(&g_mod->udp_engines, &ue->le, ue);
  }
#endif

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

const struct mod_export DECL_EXPORTS(udp) = {
  "udp",
  "conduit",
  module_init,
  module_close
};
