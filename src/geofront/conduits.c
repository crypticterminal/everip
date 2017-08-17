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

#define CONDUITS_BEACON_DELAY_MS 5000

struct conduits {
  struct list condl;
  uint32_t id_counter;
  struct hash *hash_cp_addr;

  struct csock csock;

  struct tmr beacon;

};

int conduits_debug(struct re_printf *pf, const struct conduits *conduits)
{
  int err = 0;
  struct le *le;
  struct conduit *c;
  int i = 0;

  if (!conduits)
    return 0;

  err  = re_hprintf(pf, "[Conduit Drivers]\n");
  
  if (!conduits->condl.head)
    err  = re_hprintf(pf, "□ NO CONDUITS LOADED\n");

  LIST_FOREACH(&conduits->condl, le) {
    c = le->data;
    err  = re_hprintf( pf
                     , "■ %s\t%s%s\t(%s)\n%H"
                     , c->name
                     , c->flags & CONDUIT_FLAG_BCAST ? "[BCAST]" : ""
                     , c->flags & CONDUIT_FLAG_VIRTUAL ? "[VIRTUAL]" : ""
                     , c->desc
                     , c->debug_h, c->debug_h_arg );
    i++;
  }

  err  = re_hprintf(pf, "\n[END]\n\n");

  return err;
}

struct conduit *conduit_find_byname( const struct conduits *conduits
                                   , const char *name )
{
  struct le *le;

  if (!conduits || !name)
    return NULL;

  for (le = conduits->condl.head; le; le = le->next) {
    struct conduit *c = le->data;
    if (c && !str_casecmp((const char *)c->name, name)) {
      return c;
    }
  }

  return NULL;
}

static struct csock *_noise_h( struct csock *csock
                             , enum CSOCK_TYPE type
                             , void *data )
{
  struct conduit_peer *peer = container_of(csock, struct conduit_peer, csock);
  struct mbuf *mb = data;
  struct noise_event *event = data;

  debug("_noise_h <%p><%p><%p>\n", csock, mb, peer);

  if (!peer || !peer->conduit)
    return NULL;

  switch (type) {
    case CSOCK_TYPE_DATA_MB:
      if (!peer->conduit->send_h)
        break;
      peer->conduit->send_h(peer, mb, peer->conduit->send_h_arg);
      break;
    case CSOCK_TYPE_NOISE_EVENT:
      {
        uint8_t public_key[NOISE_PUBLIC_KEY_LEN];
        struct magi_node *mnode = NULL;

        peer->ns_last_event = event->type;

        switch (event->type) {
          case NOISE_SESSION_EVENT_INIT:
            break;
          case NOISE_SESSION_EVENT_CLOSE:
            peer->ns = NULL;
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
            peer->ns = event->ns;
            if (noise_session_publickey_copy(event->ns, public_key))
              goto out;

            /* hash it and make sure it starts with fc */
            if (!addr_calc_pubkeyaddr( peer->everip_addr, public_key ))
              goto out;

            mnode = magi_node_lookup_or_create(everip_magi(), public_key );
            if (!mnode)
              goto out;

            list_unlink( &peer->le_addr );
            hash_append( peer->conduit->ctx->hash_cp_addr
                       , *(uint32_t *)(void *)peer->everip_addr
                       , &peer->le_addr
                       , peer );

            break;
          default:
            error("conduits: _noise_h: unknown type <%d>\n", event->type);
            break;
        }
      }
    default:
      return NULL;
  }
out:
  return NULL;
}

int conduit_peer_encrypted_send( struct conduit_peer *cp
                               , struct mbuf *mb )
{
  if (!cp)
    return EINVAL;
  return noise_session_send(cp->ns, mb);
}

int conduit_peer_create( struct conduit_peer **peerp
                       , struct conduit *conduit
                       , struct pl *key
                       , struct pl *host
                       , bool do_handshake )
{
  size_t i;
  int err = 0;
  uint8_t public_key[NOISE_PUBLIC_KEY_LEN];
  struct noise_session *session = NULL;

  /*debug("conduit_peer_create\n");*/

  if (!peerp || !conduit || !key)
    return EINVAL;

  if (key->l != 64) {
    error("Error: Public Key Length is %u, but should be 64\n", key->l);
    return EINVAL;
  }

  for (i=0; i<key->l; i+=2) {
    public_key[i/2]  = ch_hex(key->p[i]) << 4;
    public_key[i/2] += ch_hex(key->p[i+1]);
  }

  if (!conduit->peer_create_h)
    return EINVAL;

  /*debug("conduit_peer_create inslide\n");*/

  err = conduit->peer_create_h(peerp, key, host, conduit->peer_create_h_arg);
  if (err || !peerp || !*peerp)
    return err ? err : EINVAL;

  err = noise_session_new( &session
                         , everip_noise()
                         , (uintptr_t)conduit
                         , public_key
                         , NULL /*preshared_key*/);
  if (err)
    return err;

  (*peerp)->csock.send = _noise_h;

  if (do_handshake)
    noise_session_hs_step1_pilot( session
                                , false
                                , &(*peerp)->csock );

  return err;
}

int conduit_incoming( struct conduit *conduit
                    , struct conduit_peer *cp
                    , struct mbuf *mb )
{
  int err = 0;
  struct conduit_data cdata;
  struct noise_session *ns = NULL;
  enum NOISE_ENGINE_RECIEVE ne_rx;

  debug("conduit_incoming\n");
  cp->csock.send = _noise_h;

  if (cp->flags & CONDUIT_PEER_FLAG_BCAST) {
    cp->flags &= ~CONDUIT_PEER_FLAG_BCAST;
    /* check */
    if (mbuf_get_left(mb) < 44)
      goto bad;

    if (mbuf_read_u8(mb) != 1)
      goto bad;

    if (mbuf_read_u8(mb) != 0)
      goto bad;

    if (memcmp(mbuf_buf(mb), "EVER/IP(R)", 10))
      goto bad;

    mbuf_advance(mb, 10);

    err = noise_session_new( &ns
                           , everip_noise()
                           , (uintptr_t)conduit
                           , mbuf_buf(mb)
                           , NULL /* preshared_key */);

    if (err && err != EALREADY)
      goto bad;

    err = noise_session_hs_step1_pilot(ns, false, &cp->csock);
    if (err && err != EALREADY)
      goto bad;

    return 0;
  } else {
    ne_rx = noise_engine_recieve( everip_noise()
                                , &ns
                                , (uintptr_t)conduit
                                , mb
                                , &cp->csock );

    if (ne_rx < 0) {
      goto bad;
    }
    if (ne_rx == NOISE_ENGINE_RECIEVE_DECRYPTED) {
      cdata.cp = cp;
      cdata.mb = mb;
      csock_forward(&conduit->ctx->csock, CSOCK_TYPE_DATA_CONDUIT, &cdata);
    }
    return 0;
  }
  /* don't need this peer */
bad:
  return EPROTO;
}

static struct csock *_from_outside( struct csock *csock
                                          , enum CSOCK_TYPE type
                                          , void *data )
{
  struct conduit_data *cdata = data;
  if (!csock || type != CSOCK_TYPE_DATA_CONDUIT || !cdata)
    return NULL;

  debug("_from_outside (same as conduit_peer_encrypted_send)\n");

  conduit_peer_encrypted_send(cdata->cp, cdata->mb);

  return NULL;
}

static bool _conduits_conduit_peer_lookup(struct le *le, void *arg)
{
  struct conduit_peer *cp = le->data;
  return 0 == memcmp(cp->everip_addr, (uint8_t *)arg, EVERIP_ADDRESS_LENGTH);
}

struct conduit_peer *
conduits_conduit_peer_search( struct conduits *conduits
                            , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH] )
{
  struct conduit_peer *cp = NULL;

  if (!conduits || !everip_addr)
    return NULL;

  error("conduits_conduit_peer_search %W\n", everip_addr, EVERIP_ADDRESS_LENGTH);

  cp = list_ledata(hash_lookup( conduits->hash_cp_addr
                              , *(uint32_t *)(void *)everip_addr
                              , _conduits_conduit_peer_lookup
                              , (void *)everip_addr));
  return cp;
}

static void conduit_destructor(void *data)
{
  struct conduit *c = data;

  c->name = mem_deref(c->name);
  c->desc = mem_deref(c->desc);
}

int conduit_register_peer_create( struct conduit *conduit
                                , conduit_peer_create_h *peer_create_h
                                , void *peer_create_h_arg )
{
  if (!conduit || !peer_create_h)
    return EINVAL;

  conduit->peer_create_h = peer_create_h;
  conduit->peer_create_h_arg = peer_create_h_arg;

  return 0;
}

int conduit_register_send_handler( struct conduit *conduit
                                 , conduit_send_h *send_h
                                 , void *send_h_arg )
{
  if (!conduit || !send_h)
    return EINVAL;

  conduit->send_h = send_h;
  conduit->send_h_arg = send_h_arg;
  return 0;
}

int conduit_register_debug_handler( struct conduit *conduit
                                  , conduit_debug_h *debug_h
                                  , void *debug_h_arg )
{
  if (!conduit || !debug_h)
    return EINVAL;

  conduit->debug_h = debug_h;
  conduit->debug_h_arg = debug_h_arg;
  return 0;
}

/**
 * Register conduits
 *
 *
 * @return 0 if success, otherwise errorcode
 */
int conduits_register( struct conduit **conduit
                     , struct conduits *conduits
                     , uint8_t flags
                     , const char *name
                     , const char *desc )
{
  struct conduit *c;

  if (!conduits || !name || !desc)
    return EINVAL;

  c = mem_zalloc(sizeof(*c), conduit_destructor);
  if (!c)
    return ENOMEM;

  c->ctx = conduits;

  str_dup(&c->name, name);
  str_dup(&c->desc, desc);

  c->flags = flags;

  *conduit = c;

  list_append(&conduits->condl, &c->le, c);

  return 0;
}

static void conduits_beacon_cb( void *data )
{
  struct le *le;
  struct mbuf *mb;
  struct conduit *c;
  struct conduits *conduits = data;
  uint8_t public_key[NOISE_PUBLIC_KEY_LEN];

  struct conduit_peer bcast_peer;
  memset(&bcast_peer, 0, sizeof(bcast_peer));

  bcast_peer.flags = CONDUIT_PEER_FLAG_BCAST;

  if (noise_engine_publickey_copy( everip_noise(), public_key ))
    goto out;

  LIST_FOREACH(&conduits->condl, le) {
    c = le->data;
    if (!(c->flags & CONDUIT_FLAG_BCAST) || !c->send_h)
      continue;

    mb = mbuf_alloc(EVER_OUTWARD_MBE_POS);

    mb->pos = EVER_OUTWARD_MBE_POS;
    mb->end = EVER_OUTWARD_MBE_POS;

    mbuf_advance(mb, -44);
    mbuf_write_u8(mb, 1); /* version 1 */
    mbuf_write_u8(mb, 0); /* reserved -- no flags */
    mbuf_write_mem(mb, (uint8_t *)"EVER/IP(R)", 10);
    mbuf_write_mem(mb, public_key, NOISE_PUBLIC_KEY_LEN);
    mbuf_advance(mb, -44);

    /* SEND */
    c->send_h(&bcast_peer, mb, c->send_h_arg);

    mb = mem_deref(mb);
  }

out:
  tmr_start( &conduits->beacon
           , CONDUITS_BEACON_DELAY_MS
           , conduits_beacon_cb
           , conduits);
}

static void conduits_destructor(void *data)
{
  struct conduits *conduits = data;
  list_flush(&conduits->condl);
  hash_flush(conduits->hash_cp_addr);
  conduits->hash_cp_addr = mem_deref( conduits->hash_cp_addr );

  tmr_cancel( &conduits->beacon );
}

int conduits_init( struct conduits **conduitsp
                 , struct csock *csock )
{
  struct conduits *conduits;

  if (!conduitsp)
    return EINVAL;

  conduits = mem_zalloc(sizeof(*conduits), conduits_destructor);
  if (!conduits)
    return ENOMEM;

  hash_alloc(&conduits->hash_cp_addr, 16);

  conduits->csock.send = _from_outside;
  csock_flow(csock, &conduits->csock);

  /* timer */
  tmr_init( &conduits->beacon );
  tmr_start( &conduits->beacon
           , 100 /* beacon on start! */
           , conduits_beacon_cb
           , conduits);


  *conduitsp = conduits;

  return 0;
}
