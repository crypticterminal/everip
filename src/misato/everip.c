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

#include <sodium.h>

#if defined(HAVE_GENDO)
#include <gendo.h>
#endif

static struct everip {

  uint8_t myaddr[EVERIP_ADDRESS_LENGTH];

  struct magi_eventdriver *eventdriver;
  struct noise_engine *noise;
  struct conduits *conduits;
  struct ledbat *ledbat;
  struct magi *magi;
  struct magi_melchior *magi_melchior;

  /* ritsuko */
  struct network *net;
  struct commands *commands;

  /* terminal dogma */
  struct tunif *tunif;

  struct netevents *netevents;

  struct atfield *atfield;

  uint16_t udp_port;

  struct csock cs_tunnel;
  struct csock cs_conduits;

} everip;

static uint64_t ledbat_callback_h(ledbat_callback_arguments *a, void *arg)
{
  (void)arg;
  struct mbuf *mb = NULL;
  uint8_t *everip_addr = NULL;
  struct magi_node *mnode = NULL;
  struct conduit_peer *cp_selected = NULL;

  debug("everip: ledbat_callback_h <%u>\n", a->callback_type);

  switch (a->callback_type) {
    case LEDBAT_SENDTO:
    {
      /* check to make sure that it is AF_INET6 */
      everip_addr = (uint8_t *)(void *)&((struct sockaddr_in6 *)(void *)a->u1.address)->sin6_addr;
      debug( "everip: sendto: %zd byte packet to %W\n"
           , a->len
           , everip_addr, EVERIP_ADDRESS_LENGTH );

      cp_selected = conduits_conduit_peer_search( everip.conduits
                                                , true /* virtual is OK */
                                                , everip_addr );
      if (!cp_selected) {
        debug("ledbat_callback_h: peer not found yet\n");
        return 0;
      }

      mb = mbuf_outward_alloc(2 + a->len);
      if (!mb)
        goto out;

      mbuf_write_u16(mb, arch_htobe16( TYPE_BASE ));
      mbuf_write_mem(mb, a->buf, a->len);

      mbuf_set_pos(mb, EVER_OUTWARD_MBE_POS);
    
      conduit_peer_encrypted_send( cp_selected
                                 , mb );

      mb = mem_deref( mb );

      break;
    }
    case LEDBAT_ON_READ:
    {
      mnode = ledbat_sock_userdata_get( a->socket );
      
      if (!mnode)
        goto out;

      mb = mbuf_alloc(a->len);
      if (!mb)
        goto out;

      mbuf_write_mem(mb, a->buf, a->len);
      mb->pos = 0;

      magi_node_ledbat_recv(mnode, mb);

      mb = mem_deref(mb);

      break;
    }
    case LEDBAT_ON_ACCEPT:
    {
      /* accept! */
      everip_addr = (uint8_t *)(void *)&((struct sockaddr_in6 *)(void *)a->u1.address)->sin6_addr;
      mnode = magi_node_lookup_by_eipaddr( everip.magi
                                         , everip_addr );
      if (!mnode) {
        error("everip: hmm, no magi record!\n");
        goto out;
      }

      magi_node_ledbat_sock_set(mnode, NULL);

      ledbat_sock_userdata_set(a->socket, mnode );
      magi_node_ledbat_sock_set(mnode, a->socket);

      (void)magi_node_status_update(mnode, MAGI_NODE_STATUS_CONNECTED);

      /*BREAKPOINT;*/
      break;
    }
    case LEDBAT_ON_STATE_CHANGE:
    {
      bool _break = true;
      switch (a->u1.state) {
        case LEDBAT_STATE_EOF:
          _break = false;
          break;
        case LEDBAT_STATE_CONNECT:
          mnode = ledbat_sock_userdata_get( a->socket );
          magi_node_status_update(mnode, MAGI_NODE_STATUS_CONNECTED);
          break;
        default:
          break;
      }
      if (_break)
        break;      
    }
      /* @FALLTHROUGH@ */
    case LEDBAT_ON_ERROR:
    {
      mnode = ledbat_sock_userdata_get( a->socket );
      
      if (!mnode)
        goto out;
      
      magi_node_ledbat_sock_set(mnode, NULL);
      break;
    }
  }

out:
  return 0;
}

static struct csock *_from_tun( struct csock *csock
                              , enum SOCK_TYPE type
                              , void *data )
{
  uint16_t next_header;
  struct mbuf *mb = data;
  struct conduit_peer *cp_selected = NULL;

  if (!csock || type != SOCK_TYPE_DATA_MB || !mb)
    return NULL;

  mbuf_advance(mb, 4);

  struct _wire_ipv6_header *ihdr = \
      (struct _wire_ipv6_header *)mbuf_buf(mb);

  if (ihdr->dst[0] != 0xFC) {
    return NULL; /* toss */
  }

  /* handle packets to self */
  if (!memcmp(ihdr->dst, everip.myaddr, EVERIP_ADDRESS_LENGTH)) {
    mbuf_advance(mb, -4);
    /* back out on where you came */
    csock_forward( csock
                 , SOCK_TYPE_DATA_MB
                 , mb );
    return NULL;
  }

  next_header = ihdr->next_header;

  cp_selected = conduits_conduit_peer_search( everip.conduits
                                            , true /* virtual is OK */
                                            , ihdr->dst );
  if (!cp_selected) {
    debug("_from_tun: peer not found yet\n");
    return NULL;
  }

  mbuf_advance(mb, WIRE_IPV6_HEADER_LENGTH);
  mbuf_advance(mb, -2);
  mbuf_write_u16(mb, arch_htobe16(next_header));
  mbuf_advance(mb, -2);

  conduit_peer_encrypted_send( cp_selected
                             , mb );

  return NULL;
}

static struct csock *_from_conduits( struct csock *csock
                                   , enum SOCK_TYPE type
                                   , void *data )
{
  uint16_t next_header;
  struct conduit_data *cdata = data;

  if (!csock || type != SOCK_TYPE_DATA_CONDUIT || !cdata)
    return NULL;

  debug("everip: _from_conduits [%u]\n", mbuf_get_left(cdata->mb));

  if (mbuf_get_left(cdata->mb) < 2)
    return NULL;

  next_header = arch_betoh16(mbuf_read_u16(cdata->mb));

  if (next_header < TYPE_BASE) {
    /* IPv6 */

    /*info("IPv6<%u>: %u\n", next_header, mbuf_get_left(cdata->mb));*/

    mbuf_advance(cdata->mb, -(WIRE_IPV6_HEADER_LENGTH));

    struct _wire_ipv6_header *ihdr = \
          (struct _wire_ipv6_header *)mbuf_buf(cdata->mb);

    memset(ihdr, 0, WIRE_IPV6_HEADER_LENGTH - 32);

    ((uint8_t*)ihdr)[0] |= (6) << 4;
    ihdr->hop = 42;
    ihdr->next_header = next_header;
    ihdr->payload_be = arch_htobe16(mbuf_get_left(cdata->mb) - WIRE_IPV6_HEADER_LENGTH);

    memcpy(ihdr->src, cdata->cp->everip_addr, EVERIP_ADDRESS_LENGTH);
    memcpy(ihdr->dst, everip.myaddr, EVERIP_ADDRESS_LENGTH);

    if (!atfield_check(everip_atfield(), ihdr->src)) {
      return NULL;
    }

    mbuf_advance(cdata->mb, -4);

    ((uint16_t*)(void *)mbuf_buf(cdata->mb))[0] = 0;
    ((uint16_t*)(void *)mbuf_buf(cdata->mb))[1] = arch_htobe16(0x86DD);

    csock_forward( &everip.cs_tunnel
                 , SOCK_TYPE_DATA_MB
                 , cdata->mb );
  } else {
    /* later check return value... */
    ledbat_process_incoming( everip_ledbat()
                           , cdata->cp->everip_addr
                           , cdata->mb );
  }

  return NULL;

}

static int magi_event_watcher_h( enum MAGI_EVENTDRIVER_WATCH type
                               , void *data
                               , void *arg )
{
  struct sa laddr;
  if (!data)
    return 0;

  if (type == MAGI_EVENTDRIVER_WATCH_NOISE)
  {
    struct magi_node *mnode = NULL;
    struct noise_event *event = data;
    uint8_t public_key[NOISE_PUBLIC_KEY_LEN];

    switch (event->type) {
      case NOISE_SESSION_EVENT_INIT:
        break;
      case NOISE_SESSION_EVENT_CLOSE:
        break;
      case NOISE_SESSION_EVENT_ZERO:
        break;
      case NOISE_SESSION_EVENT_HSHAKE:
        break;
      case NOISE_SESSION_EVENT_HSXMIT:
        break;
      case NOISE_SESSION_EVENT_CONNECTED:
        break;
      case NOISE_SESSION_EVENT_REKEY:
        break;
      case NOISE_SESSION_EVENT_BEGIN_PILOT:
      case NOISE_SESSION_EVENT_BEGIN_COPILOT:
        if (noise_session_publickey_copy(event->ns, public_key))
          goto out;

        mnode = magi_node_lookup_or_create(everip.magi, public_key);
        if (!mnode)
          goto out;

        break;
      default:
        error("everip: _noise_h: unknown type <%d>\n", event->type);
        break;
    }
  }
  else if (type == MAGI_EVENTDRIVER_WATCH_E2E)
  {
    struct magi_e2e_event *event = data;

    sa_init(&laddr, AF_INET6);
    sa_set_in6(&laddr, event->everip_addr, 0);

    info("[MAGI][%j] STATUS CHANGED TO %s\n", &laddr, magi_node_status_tostr(event->status));

  }
  else if (type == MAGI_EVENTDRIVER_WATCH_NETEVENT)
  {
    struct netevent_event *event = data;

    switch(event->type) {
      case NETEVENT_EVENT_INIT:
        info("[NETEVENT] INIT\n");
        break;
      case NETEVENT_EVENT_CLOSE:
        info("[NETEVENT] CLOSE\n");
        break;
      case NETEVENT_EVENT_DEV_UP:
      case NETEVENT_EVENT_DEV_DOWN:
        info( "[NETEVENT] IF [%s@%u] is %s [KIND:%s]\n"
           , event->if_name
           , event->if_index
           , event->type == NETEVENT_EVENT_DEV_UP ? "UP" : "DOWN"
           , netevents_iface_kind_tostr(event->if_kind)
           );
        break;
      case NETEVENT_EVENT_ADDR_NEW:
      case NETEVENT_EVENT_ADDR_DEL:
        info( "[NETEVENT] IF [%s@%u] ADDR %s %j\n"
           , event->if_name
           , event->if_index
           , event->type == NETEVENT_EVENT_ADDR_NEW ? "NEW" : "DEL"
           , &event->sa
           );
        break;
      default:
        goto out;
    }

  }

out:
  return 0;
}

int everip_init( const uint8_t skey[NOISE_SECRET_KEY_LEN]
               , uint16_t port_default )
{
  int err;
  struct sa laddr;

  memset(&everip, 0, sizeof(struct everip));

  if (sodium_init() == -1) {
    return EINVAL;
  }

  /* Initialise Network */
  err = net_alloc(&everip.net);
  if (err) {
    return err;
  }

  err = magi_eventdriver_alloc(&everip.eventdriver);
  if (err) {
    error("everip_init: magi_eventdriver_alloc\n");
    return err;
  }

  /* register events */
  err = magi_eventdriver_handler_register( everip.eventdriver
                                         , MAGI_EVENTDRIVER_WATCH_NOISE
                                         , magi_event_watcher_h
                                         , NULL );
  if (err) {
    error("everip_init: magi_eventdriver_handler_register\n");
    return err;
  }

  err = magi_eventdriver_handler_register( everip.eventdriver
                                         , MAGI_EVENTDRIVER_WATCH_E2E
                                         , magi_event_watcher_h
                                         , NULL );
  if (err) {
    error("everip_init: magi_eventdriver_handler_register\n");
    return err;
  }

  err = magi_eventdriver_handler_register( everip.eventdriver
                                         , MAGI_EVENTDRIVER_WATCH_NETEVENT
                                         , magi_event_watcher_h
                                         , NULL );
  if (err) {
    error("everip_init: magi_eventdriver_handler_register\n");
    return err;
  }

  err = noise_engine_init( &everip.noise, everip.eventdriver);
  if (err) {
    error("everip_init: noise_engine_init\n");
    return err;
  }

  if (!addr_calc_pubkeyaddr( everip.myaddr, everip.noise->si.public )) {
    error("everip_init: Invalid Identity\n");
    return EINVAL;
  }

  everip.cs_conduits.send = _from_conduits;

  err = conduits_init( &everip.conduits
                     , &everip.cs_conduits
                     , everip.eventdriver);
  if (err) {
    error("everip_init: conduits_init\n");
    return err;
  }

  err = ledbat_alloc( &everip.ledbat );
  if (err) {
    error("everip_init: ledbat_alloc\n");
    return err;
  }

  err = ledbat_callback_register( everip.ledbat
                                , ledbat_callback_h
                                , NULL );
  if (err) {
    error("everip_init: ledbat_callback_register\n");
    return err;
  }

  err = magi_alloc( &everip.magi, everip.eventdriver);
  if (err) {
    error("everip_init: magi_alloc\n");
    return err;
  }

  err = magi_melchior_alloc( &everip.magi_melchior, everip.magi, everip.noise );
  if (err) {
    error("everip_init: magi_melchior_alloc\n");
    return err;
  }

  err = cmd_init(&everip.commands);
  if (err)
    return err;

  if (!everip.udp_port)
      everip.udp_port = port_default ? port_default : 1988;

  /* atfield */
  err = atfield_init( &everip.atfield );
  if (err) {
    error("everip_init: atfield_init\n");
    return err;
  }

  err = netevents_alloc( &everip.netevents, everip.eventdriver);
  if (err) {
    error("everip_init: netevents_alloc\n");
    return err;
  }

  sa_init(&laddr, AF_INET6);
  sa_set_in6(&laddr, everip.myaddr, 0);

  info("UNLOCKING LICENSED EVER/IP(R) ADDRESS\n[%j]\n", &laddr, 16);

  err = tunif_init( &everip.tunif );
  if (err) {
    error("everip_init: tunif_init\n");
    err = 0;
    goto skip_tun;
  }

  for (int i = 0; i < 10; ++i) {
    err = net_if_setaddr( everip.tunif->name
                        , &laddr
                        , 8 );
    if (!err) break;
    sys_msleep(10);
  }

  if (err) {
    error("everip_init: net_if_setaddr\n");
    return err;
  }

  for (int i = 0; i < 10; ++i) {
    err = net_if_setmtu( everip.tunif->name
                       , 1304);
    if (!err) break;
    sys_msleep(10);
  }

  if (err) {
    error("everip_init: net_if_setmtu\n");
    return err;
  }

skip_tun:

#if !defined(WIN32) && !defined(CYGWIN)
  if (!everip.tunif) {
    warning("everip_init: enabling unix domain tunnel\n");
    {
      char *_path = NULL;
      re_sdprintf( &_path
                 , "/tmp/ever-socket-%w.sock"
                 , everip.myaddr, EVERIP_ADDRESS_LENGTH );
      err = tunif_un_init(&everip.tunif, _path);
      _path = mem_deref( _path );
      if (err) {
        error("everip_init: tunif_un_init\n");
        return err;
      }
    }
  }

#endif

  if (everip.tunif) {
    info("tunnel device: [%s] init;\n", everip.tunif->name);
    everip.cs_tunnel.send = _from_tun;
    csock_flow(&everip.cs_tunnel, &everip.tunif->cs_tmldogma);
  }

#if !defined(WIN32) && !defined(CYGWIN)
  module_preload("stdio");
#else
  module_preload("wincon");
#endif
  module_preload("dcmd");

  /* wui: web ui*/
  module_preload("wui");

  /* conduits*/
  module_preload("null");
  module_preload("udp");
  module_preload("udpd");
  module_preload("web");

  /* virtual */
  module_preload("treeoflife");

#if defined(HAVE_GENDO)
  GENDO_MID;
#endif

  return 0;
}


void everip_close(void)
{

#if defined(HAVE_GENDO)
  GENDO_DEINIT;
#endif

  /* handles sendto, etc. */

  everip.magi_melchior = mem_deref(everip.magi_melchior);
  everip.magi = mem_deref( everip.magi );

  everip.netevents = mem_deref(everip.netevents);

  /* reverse from init */
  everip.tunif = mem_deref(everip.tunif);
  everip.commands = mem_deref(everip.commands);
  everip.net = mem_deref(everip.net);
  everip.atfield = mem_deref(everip.atfield);

  everip.conduits = mem_deref(everip.conduits);
  everip.noise = mem_deref(everip.noise);
  everip.eventdriver = mem_deref(everip.eventdriver);

  everip.ledbat = mem_deref(everip.ledbat);
}


struct network *everip_network(void)
{
  return everip.net;
}

struct magi *everip_magi(void)
{
  return everip.magi;
}

struct magi_melchior *everip_magi_melchior(void)
{
  return everip.magi_melchior;
}

struct magi_eventdriver *everip_eventdriver(void)
{
  return everip.eventdriver;
}

struct netevents *everip_netevents(void)
{
  return everip.netevents;
}

struct ledbat *everip_ledbat(void)
{
  return everip.ledbat;
}

struct commands *everip_commands(void)
{
  return everip.commands;
}

struct noise_engine *everip_noise(void)
{
  return everip.noise;
}

struct conduits *everip_conduits(void)
{
  return everip.conduits;
}

struct atfield *everip_atfield(void)
{
  return everip.atfield;
}

int everip_addr_copy(uint8_t everip_addr[EVERIP_ADDRESS_LENGTH])
{
  memcpy(everip_addr, everip.myaddr, EVERIP_ADDRESS_LENGTH);
  return 0;
}



void everip_udpport_set(uint16_t port)
{
  everip.udp_port = port;
}

uint16_t everip_udpport_get(void)
{
  return everip.udp_port;
}

