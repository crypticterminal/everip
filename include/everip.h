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

#ifndef EVERIP_H__
#define EVERIP_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <sodium.h>
#include "__arch.h"
#include "__wires.h"

#define EVERIP_VERSION "0.1.1"

#define EVERIP_VERSION_PROTOCOL 3

static inline bool everip_version_compat(uint32_t a, uint32_t b) {
  return (a == b);
}

/* super defines */

#define TYPE_BASE 256
#define KEY_LENGTH 15
#define ZONE_COUNT 1
#define ROUTE_LENGTH 16 /* 128 bytes */

#define EVER_OUTWARD_MBE_POS (512)
#define EVER_OUTWARD_MBE_LENGTH (1500)

#define TAI64_N_LEN 12U

ASSERT_COMPILETIME(TAI64_N_LEN == (sizeof(uint64_t) + sizeof(uint32_t)));

struct noise_engine;
struct noise_session;

struct ledbat_sock;

/* ENUMS */

enum noise_lengths {
    NOISE_PUBLIC_KEY_LEN = 32U
  , NOISE_SECRET_KEY_LEN = 32U
  , NOISE_SYMMETRIC_KEY_LEN = crypto_aead_chacha20poly1305_IETF_KEYBYTES
  , NOISE_TIMESTAMP_LEN = TAI64_N_LEN
  , NOISE_AUTHTAG_LEN = crypto_aead_chacha20poly1305_IETF_ABYTES
  , NOICE_NONCE_LEN = crypto_aead_chacha20poly1305_IETF_NPUBBYTES
  , NOISE_HASH_LEN = 32U
};

enum NOISE_SESSION_HANDLE {
    NOISE_SESSION_HANDLE_RECV = 0
  , NOISE_SESSION_HANDLE_EVENT = 1
};

enum NOISE_ENGINE_RECIEVE {
    NOISE_ENGINE_RECIEVE_EBADMSG = -1
  , NOISE_ENGINE_RECIEVE_OK = 0
  , NOISE_ENGINE_RECIEVE_EINVAL = 1
  , NOISE_ENGINE_RECIEVE_IGNORE = 2
  , NOISE_ENGINE_RECIEVE_DECRYPTED = 3
};

/*
 * Address
 */

#define EVERIP_ADDRESS_LENGTH 16

#define ADDR_KEY_SIZE 32
#define ADDR_NETWORK_ADDR_SIZE ROUTE_LENGTH
#define ADDR_SERIALIZED_SIZE 40

struct PACKONE addr
{
    uint32_t protover;
    uint32_t padding;/** unused */
    union {
        struct {
            uint32_t three_be;
            uint32_t four_be;
            uint32_t one_be;
            uint32_t two_be;
        } ints;
        struct {
            uint64_t two_be;
            uint64_t one_be;
        } longs;
        uint8_t bytes[EVERIP_ADDRESS_LENGTH];
    } ip6;
    uint8_t key[ADDR_KEY_SIZE];
    uint8_t route[ROUTE_LENGTH];
};

int addr_calc_isvalid(const uint8_t address[16]);
int addr_calc_pubkeyaddr( uint8_t out_address[16], const uint8_t key[32] );

uint32_t addr_ip6_prefix(uint8_t ip6[16]);
uint32_t addr_prefix(struct addr *addr);

int addr_base32_decode( uint8_t* out , const uint32_t olen , const uint8_t* in , const uint32_t ilen );
int addr_base32_encode( uint8_t* out , const uint32_t olen , const uint8_t* in , const uint32_t ilen );

/*
 * TAI64
 */

void tai64n_now( uint8_t output[TAI64_N_LEN] );

/*
 * BENCODE
 */

enum bencode_typ {
  BENCODE_STRING,
  BENCODE_INT,
  BENCODE_NULL,
};

struct bencode_value {
  union {
    struct pl pl;
    int64_t integer;
  } v;
  enum bencode_typ type;
};

struct bencode_handlers;

typedef int (bencode_object_entry_h)(const char *name,
          const struct bencode_value *value, void *arg);
typedef int (bencode_array_entry_h)(unsigned idx,
         const struct bencode_value *value, void *arg);
typedef int (bencode_object_h)(const char *name, unsigned idx,
          struct bencode_handlers *h);
typedef int (bencode_array_h)(const char *name, unsigned idx,
         struct bencode_handlers *h);

struct bencode_handlers {
  bencode_object_h *oh;
  bencode_array_h *ah;
  bencode_object_entry_h *oeh;
  bencode_array_entry_h *aeh;
  void *arg;
};

int bencode_decode(const char *str, size_t len, unsigned maxdepth,
    bencode_object_h *oh, bencode_array_h *ah,
    bencode_object_entry_h *oeh, bencode_array_entry_h *aeh, void *arg);

int bencode_decode_odict(struct odict **op, uint32_t hash_size, const char *str,
          size_t len, unsigned maxdepth);
int bencode_encode_odict(struct re_printf *pf, const struct odict *o);

/*
 * MBUF (helpers)
 */

static inline struct mbuf * mbuf_outward_alloc(size_t size)
{
  struct mbuf *mb = mbuf_alloc(EVER_OUTWARD_MBE_POS + size);
  if (!mb)
    goto out;

  mb->pos = EVER_OUTWARD_MBE_POS;
  mb->end = EVER_OUTWARD_MBE_POS + size;

out:
  return mb;
}

/*
 * MAGI
 */

struct magi;
struct magi_node;
struct magi_eventdriver;
struct magi_eventdriver_handler;

struct magi_melchior;
struct magi_melchior_rpc;
struct magi_melchior_ticket;

enum MAGI_NODE_STATUS {
     MAGI_NODE_STATUS_MINIMUM = -3
   , MAGI_NODE_STATUS_REMOVAL = -2
   , MAGI_NODE_STATUS_CREATED = -1
   , MAGI_NODE_STATUS_OFFLINE = 0
   , MAGI_NODE_STATUS_SEARCHING
   , MAGI_NODE_STATUS_CONNECTED
   , MAGI_NODE_STATUS_OPERATIONAL
   , MAGI_NODE_STATUS_MAXIMUM /* must be last! */
};

static inline const char * magi_node_status_tostr(enum MAGI_NODE_STATUS status)
{
  switch (status) {
    case MAGI_NODE_STATUS_REMOVAL:
      return "REMOVAL";
    case MAGI_NODE_STATUS_CREATED:
      return "CREATED";
    case MAGI_NODE_STATUS_OFFLINE:
      return "OFFLINE";
    case MAGI_NODE_STATUS_SEARCHING:
      return "SEARCHING";
    case MAGI_NODE_STATUS_CONNECTED:
      return "CONNECTED";
    case MAGI_NODE_STATUS_OPERATIONAL:
      return "OPERATIONAL";
    default:
      break;
  }
  return "UNKNOWN";
}

enum MAGI_EVENTDRIVER_WATCH {
     MAGI_EVENTDRIVER_WATCH_E2E = 0
   , MAGI_EVENTDRIVER_WATCH_NOISE
   , MAGI_EVENTDRIVER_WATCH_LEDBAT
   , MAGI_EVENTDRIVER_WATCH_NETEVENT
   , MAGI_EVENTDRIVER_WATCH_MAXIMUM /* must be last! */
};

enum MAGI_LEDBAT_PORT {
     MAGI_LEDBAT_PORT_MELCHIOR = 0
   , MAGI_LEDBAT_PORT_TREEOFLIFE
   , MAGI_LEDBAT_PORT_MAXIMUM /* must be last! */
};

enum MAGI_MELCHIOR_RETURN_STATUS {
     MAGI_MELCHIOR_RETURN_STATUS_OK = 0
   , MAGI_MELCHIOR_RETURN_STATUS_ERR
   , MAGI_MELCHIOR_RETURN_STATUS_TIMEDOUT
};

typedef int (magi_eventdriver_h)(enum MAGI_EVENTDRIVER_WATCH type, void *data, void *arg);

typedef void (magi_melchior_h)( enum MAGI_MELCHIOR_RETURN_STATUS status
                              , struct odict *od_sent
                              , struct odict *od_recv
                              , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH]
                              , uint64_t timediff
                              , void *userdata );

typedef int (magi_melchior_rpc_h)( struct magi_melchior_rpc *rpc
                                 , struct pl *method
                                 , void *arg );

struct magi_melchior_rpc {
  struct odict *in;
  struct odict *out;
  const uint8_t *everip_addr;

  /* options */
  bool is_routable;
};

struct magi_e2e_event {
  enum MAGI_NODE_STATUS status;
  const uint8_t *everip_addr;
};

int magi_eventdriver_handler_run( struct magi_eventdriver *ed
                                , enum MAGI_EVENTDRIVER_WATCH type
                                , void *data );

int magi_eventdriver_handler_register( struct magi_eventdriver *ed
                                     , enum MAGI_EVENTDRIVER_WATCH type
                                     , magi_eventdriver_h *handler
                                     , void *userdata );

int magi_eventdriver_alloc(struct magi_eventdriver **edp);

/* core */

int magi_node_ledbat_sock_set( struct magi_node *mnode
                                       , struct ledbat_sock *lsock );

struct ledbat_sock *
magi_node_ledbat_sock_get( struct magi_node *mnode );

int magi_node_ledbat_send( struct magi_node *mnode
                         , struct mbuf *mb
                         , uint16_t port );

int magi_node_ledbat_recv( struct magi_node *mnode, struct mbuf *mb );

int magi_node_everipaddr_copy( struct magi_node *mnode
                             , uint8_t everip_addr[EVERIP_ADDRESS_LENGTH] );

struct magi_node *
magi_node_lookup_by_eipaddr( struct magi *magi
                           , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH] );

int magi_node_status_update( struct magi_node *mnode
                           , enum MAGI_NODE_STATUS status );

struct magi_node *
magi_node_lookup_or_create( struct magi *magi
                          , const uint8_t public_key[NOISE_PUBLIC_KEY_LEN] );

int magi_alloc(struct magi **magip, struct magi_eventdriver *med);

/* melchior */

int magi_melchior_send( struct magi_melchior *mm
                      , struct odict *od
                      , struct pl *method
                      , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH]
                      , uint64_t timeout
                      , bool is_routable
                      , magi_melchior_h *callback
                      , void *userdata );

int magi_melchior_recv( struct magi_melchior *mm, struct mbuf *mb);

int magi_melchior_register( struct magi_melchior *mm
                          , const uint8_t prefix[4]
                          , magi_melchior_rpc_h *callback
                          , void *userdata );

int magi_melchior_alloc( struct magi_melchior **mmp
                       , struct magi *magi
                       , struct noise_engine *ne );

/* socks */

enum SOCK_TYPE {
     SOCK_TYPE_DATA_MB = 0
   , SOCK_TYPE_DATA_CONDUIT
   , SOCK_TYPE_NOISE_EVENT
};

/*
 * LSOCK (list sock)
 */

struct lsock;

typedef int (lsock_send_h)(struct lsock *lsock, enum SOCK_TYPE type, void *data);

struct lsock {
  lsock_send_h *s;
  struct list l;
};

static inline struct lsock *lsock_fromle(struct le *ls_le)
{
  return container_of(ls_le->list, struct lsock, l);
}

static inline void lsock_forward(struct le *ls_le, enum SOCK_TYPE type, void *data)
{
  struct lsock *ls = NULL;

  if (!ls_le || !ls_le->list)
    return;

  ls = container_of(ls_le->list, struct lsock, l);

  if (ls->s)
    (void)ls->s(ls, type, data);

}

static inline void lsock_install(struct lsock *ls, struct le *le, void *data)
{
  if (!ls || !le) return;

  if (!list_contains(&ls->l, le))  
    list_prepend(&ls->l, le, data);

}

/*
 * CSOCK
 */

struct csock;

typedef struct csock *(csock_send_h)(struct csock *csock, enum SOCK_TYPE type, void *data);

struct csock {
  csock_send_h *send;
  struct csock *adj;
};

static inline void csock_forward(struct csock *csock, enum SOCK_TYPE type, void *data)
{
  do {
    struct csock* adj = csock->adj;
    if (!adj || !adj->send) return;
    csock = adj->send(adj, type, data);
  } while (csock);
}

static inline struct csock *csock_next(struct csock *csock, enum SOCK_TYPE type, void *data)
{
  if (!csock || !csock->adj) return NULL;
  csock_forward(csock, type, data);
  return NULL;
}

static inline void csock_stop(struct csock *c)
{
  if (!c) return;
  if (c->adj) {
    c->adj->adj = NULL;
  }
  c->adj = NULL;
}

static inline void csock_flow(struct csock *c_a, struct csock *c_b)
{
  if (!c_a || !c_b) return;

  csock_stop(c_a);
  csock_stop(c_b);

  c_a->adj = c_b;
  c_b->adj = c_a;
}

/*
 * NOISE
 */

enum NOISE_SESSION_EVENT {
     NOISE_SESSION_EVENT_NULL = 0
   , NOISE_SESSION_EVENT_INIT = 1
   , NOISE_SESSION_EVENT_CLOSE = 2
   , NOISE_SESSION_EVENT_ZERO = 3
   , NOISE_SESSION_EVENT_HSHAKE = 4
   , NOISE_SESSION_EVENT_HSXMIT = 5
   , NOISE_SESSION_EVENT_CONNECTED = 6
   , NOISE_SESSION_EVENT_REKEY = 7
   , NOISE_SESSION_EVENT_BEGIN_PILOT = 8
   , NOISE_SESSION_EVENT_BEGIN_COPILOT = 9
};

static inline const char * noise_session_event_tostr(enum NOISE_SESSION_EVENT event)
{
  switch (event) {
    case NOISE_SESSION_EVENT_NULL:
      return "NULL";
    case NOISE_SESSION_EVENT_INIT:
      return "INIT";
    case NOISE_SESSION_EVENT_CLOSE:
      return "CLOSE";
    case NOISE_SESSION_EVENT_ZERO:
      return "ZERO";
    case NOISE_SESSION_EVENT_HSHAKE:
      return "HANDSHAKE";
    case NOISE_SESSION_EVENT_HSXMIT:
      return "HSXMIT";
    case NOISE_SESSION_EVENT_CONNECTED:
      return "CONNECTED";
    case NOISE_SESSION_EVENT_REKEY:
      return "REKEY";
    case NOISE_SESSION_EVENT_BEGIN_PILOT:
      return "PILOT";
    case NOISE_SESSION_EVENT_BEGIN_COPILOT:
      return "COPILOT";
    default:
      return "UNKNOWN";
  }
}

typedef void (noise_session_recv_h)(struct noise_session *s, struct mbuf *mb, void *arg);

typedef void (noise_session_event_h)(struct noise_session *s, enum NOISE_SESSION_EVENT event, void *arg);

struct noise_si {
  bool has_identity;
  uint8_t public[NOISE_PUBLIC_KEY_LEN];
  uint8_t private[NOISE_SECRET_KEY_LEN];
};

struct noise_engine {
  uint8_t hshake_hash[NOISE_HASH_LEN];
  uint8_t hshake_chaining_key[NOISE_HASH_LEN];

  struct noise_si si;
  uint8_t sign_keys[NOISE_PUBLIC_KEY_LEN+NOISE_SECRET_KEY_LEN];

  struct list sessions_all;
  struct hash *idlookup;

  uint32_t sessions_counter;

  struct list handlers_event;

  struct csock cs_event;

  struct magi_eventdriver *ed;

};

struct noise_event {
  struct noise_engine *ne;
  struct noise_session *ns;
  enum NOISE_SESSION_EVENT type;
};

struct noise_session_counters {
  uint64_t rx_bytes;
  uint64_t tx_bytes;
};

void noise_si_private_key_set( struct noise_si *si
                             , const uint8_t private_key[NOISE_PUBLIC_KEY_LEN] );

uint64_t noise_session_score(struct noise_session *ns);

int noise_session_counters(struct noise_session *ns, struct noise_session_counters *counters);

int noise_session_keepalive_send(struct noise_session *ns);
int noise_session_keepalive_recv(struct noise_session *ns, struct mbuf *mb);

int noise_session_hs_step1_pilot( struct noise_session *ns
                                , bool is_retry
                                , struct lsock *lsock );

int noise_session_send(struct noise_session *ns, struct mbuf *mb);

int noise_session_handle_register( struct noise_session *ns
                                 , enum NOISE_SESSION_HANDLE type
                                 , struct csock *csock );

int noise_session_publickey_copy( struct noise_session *ns
                                , uint8_t public_key[NOISE_PUBLIC_KEY_LEN] );

int noise_session_new( struct noise_session **sessionp
                     , struct noise_engine *ne
                     , uintptr_t channel_lock
                     , const uint8_t public_key[NOISE_PUBLIC_KEY_LEN]
                     , const uint8_t preshared_key[NOISE_SYMMETRIC_KEY_LEN] );

struct noise_session *
noise_engine_find_session_bykey( struct noise_engine *ne
                               , uintptr_t channel_lock
                               , const uint8_t key[NOISE_PUBLIC_KEY_LEN]);

struct noise_idlookup *
noise_engine_lookup_byid( struct noise_engine *ne
                        , uint8_t kind
                        , uint32_t key);

#define noise_engine_lookup_session_byid(ne, key) \
  container_of(noise_engine_lookup_byid(ne, NOISE_LOOKUP_KIND_SESSION, key), struct noise_session, lookup)

#define noise_engine_lookup_keypair_byid(ne, key) \
  container_of(noise_engine_lookup_byid(ne, NOISE_LOOKUP_KIND_KEYPAIR, key), struct noise_keypair, lookup)

int noise_engine_session_handle_register( struct noise_engine *ne
                                        , enum NOISE_SESSION_HANDLE type
                                        , struct csock *csock );

int noise_engine_recieve( struct noise_engine *ne
                        , struct noise_session **nsp
                        , uintptr_t channel_lock
                        , struct mbuf *mb
                        , struct lsock *lsock );

int noise_engine_publickey_copy( struct noise_engine *ne
                               , uint8_t public_key[NOISE_PUBLIC_KEY_LEN] );

int noise_engine_debug(struct re_printf *pf, void *arg);

int noise_engine_init( struct noise_engine **nenginep, struct magi_eventdriver *ed);

int noise_engine_test_counter(void);

/*
 * Crypto Sign
 */

#define CRYPTOSIGN_SIGNATURE_LENGTH crypto_sign_ed25519_BYTES
ASSERT_COMPILETIME(CRYPTOSIGN_SIGNATURE_LENGTH == 64U);

static inline void cryptosign_pk_fromskpk(uint8_t pk[32], const uint8_t skpk[64])
{
  memcpy(pk, &skpk[32], 32);
}

void cryptosign_skpk_fromcurve25519(uint8_t skpk[64], const uint8_t sk[32]);
int cryptosign_bytes_verify(uint8_t pk[32], uint8_t *s, uint8_t *m, size_t mlen);
void cryptosign_bytes(uint8_t skpk[64], uint8_t *m, size_t mlen);

/*
 * Conduits
 */

struct conduits;
struct conduit_peer;

typedef int (conduit_peer_create_h)(struct conduit_peer **peerp, struct pl *key, struct pl *host, void *arg);

typedef int (conduit_send_h)(struct conduit_peer *peer, struct mbuf *mb, void *arg);

typedef int (conduit_debug_h)(struct re_printf *pf, void *arg);

typedef int (conduit_search_h)(const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH], void *arg);

#define CONDUIT_FLAG_NONE      (0)    /* No flags defined */
#define CONDUIT_FLAG_DISABLED  (1<<0) /* conduit is disabled and cannot be used */
#define CONDUIT_FLAG_BCAST     (1<<1) /* this conduit can broadcast messages */
#define CONDUIT_FLAG_VIRTUAL   (1<<2) /* for things like tree of life */
#define CONDUIT_FLAG_SECONDARY (1<<3) /* used for selection sorting order */

struct conduit {
  struct le le; /* struct conduits */
  struct conduits *ctx;

  struct list peers;

  bool registered;
  uint8_t flags;

  char *name;
  char *desc;

  conduit_peer_create_h *peer_create_h;
  void *peer_create_h_arg;

  conduit_send_h *send_h;
  void *send_h_arg;

  conduit_debug_h *debug_h;
  void *debug_h_arg;

  conduit_search_h *search_h;
  void *search_h_arg;
};

#define CONDUIT_PEER_FLAG_BCAST (1<<0)

struct conduit_peer {
  struct le le_addr; /* struct conduits */
  struct le le_conduit; /* struct conduit */
  uint8_t flags;
  uint8_t everip_addr[EVERIP_ADDRESS_LENGTH];
  struct conduit *conduit;
  enum NOISE_SESSION_EVENT ns_last_event;

  struct lsock lsock;

};

struct conduit_data {
  struct conduit_peer *cp;
  struct mbuf *mb;
};

static inline int conduit_peer_debug(struct re_printf *pf, struct conduit_peer *peer)
{
  int err = 0;
  struct sa laddr;
  struct noise_session *ns = NULL;
  struct noise_session_counters nsc;

  sa_set_in6(&laddr, peer->everip_addr, 0);

  memset(&nsc, 0, sizeof(nsc));
  ns = list_ledata(peer->lsock.l.head);
  err = noise_session_counters(ns, &nsc);

  err  = re_hprintf(pf, "[%j][%p][%s][SCORE=%u][TX=%zu][RX=%zu]"
                      , &laddr
                      , ns
                      , noise_session_event_tostr(peer->ns_last_event)
                      , noise_session_score(ns)
                      , nsc.tx_bytes
                      , nsc.rx_bytes
                      );
  return err;
}

static inline void conduit_peer_deref(struct conduit_peer *peer)
{
  list_unlink(&peer->le_addr);
  list_clear(&peer->lsock.l);
}

int conduit_peer_encrypted_send( struct conduit_peer *cp
                               , struct mbuf *mb );

int conduit_peer_initiate( struct conduit_peer *peer
                         , const uint8_t public_key[NOISE_PUBLIC_KEY_LEN]
                         , bool do_handshake );

int conduit_peer_create( struct conduit_peer **peerp
                       , struct conduit *conduit
                       , struct pl *key
                       , struct pl *host
                       , bool do_handshake );

int conduit_incoming( struct conduit *conduit
                    , struct conduit_peer *cp
                    , struct mbuf *mb );

int conduit_register_peer_create( struct conduit *conduit
                                , conduit_peer_create_h *peer_create_h
                                , void *peer_create_h_arg );

int conduit_register_send_handler( struct conduit *conduit
                                 , conduit_send_h *send_h
                                 , void *send_h_arg );

int conduit_register_debug_handler( struct conduit *conduit
                                  , conduit_debug_h *debug_h
                                  , void *debug_h_arg );

int conduit_register_search_handler( struct conduit *conduit
                                   , conduit_search_h *search_h
                                   , void *search_h_arg );

struct conduit_peer *
conduits_conduit_peer_search( struct conduits *conduits
                            , bool allow_virtual
                            , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH] );

int conduits_init( struct conduits **conduitsp
                 , struct csock *csock
                 , struct magi_eventdriver *ed );

int conduits_register( struct conduit **conduitp
                     , struct conduits *conduits
                     , uint8_t flags
                     , const char *name
                     , const char *desc );
struct conduit *conduits_unregister( struct conduit *conduit );

#define conduit_find conduit_find_byname
struct conduit *conduit_find_byname( const struct conduits *conduits , const char *name );

int conduits_debug(struct re_printf *pf, const struct conduits *conduits);


/*
 * LEDBAT
 */

enum {
  // socket has reveived syn-ack (notification only for outgoing connection completion)
  // this implies writability
  LEDBAT_STATE_CONNECT = 1,
  // socket is able to send more data
  LEDBAT_STATE_WRITABLE = 2,
  // connection closed
  LEDBAT_STATE_EOF = 3,
  // socket is being destroyed, meaning all data has been sent if possible.
  // it is not valid to refer to the socket after this state change occurs
  LEDBAT_STATE_DESTROYING = 4,
};

enum {
  LEDBAT_ECONNREFUSED = 0,
  LEDBAT_ECONNRESET,
  LEDBAT_ETIMEDOUT,
};

enum {
  LEDBAT_ON_FIREWALL = 0,
  LEDBAT_ON_ACCEPT = 1,
  LEDBAT_ON_CONNECT = 2,
  LEDBAT_ON_ERROR = 3,
  LEDBAT_ON_READ = 4,
  LEDBAT_ON_OVERHEAD_STATISTICS = 5,
  LEDBAT_ON_STATE_CHANGE = 6,
  LEDBAT_ON_DELAY_SAMPLE = 8,
  LEDBAT_GET_UDP_MTU = 9,
  LEDBAT_GET_UDP_OVERHEAD = 10,
  LEDBAT_GET_MILLISECONDS = 11,
  LEDBAT_GET_MICROSECONDS = 12,
  LEDBAT_GET_RANDOM = 13,
  LEDBAT_LOG = 14,
  LEDBAT_SENDTO = 15,
  LEDBAT_PUBLIC_ARRAY_END, /* must be last */
};

struct ledbat;
struct ledbat_sock;

typedef struct {
  struct ledbat *context;
  struct ledbat_sock *socket;
  size_t len;
  uint32_t flags;
  int callback_type;
  const uint8_t *buf;

  union {
    const struct sockaddr *address;
    int send;
    int sample_ms;
    int error_code;
    int state;
  } u1;

} ledbat_callback_arguments;

typedef uint64_t ledbat_callback_t(ledbat_callback_arguments *a, void *userdata);

int ledbat_sock_send(struct ledbat_sock *lsock, struct mbuf *mb);

int ledbat_sock_connect( struct ledbat_sock *lsock
                       , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH] );

int ledbat_sock_reconnect( struct ledbat_sock *lsock );

int ledbat_sock_callback_register( struct ledbat_sock *lsock
                                 , ledbat_callback_t *callback
                                 , void *userdata );

void *ledbat_sock_userdata_get( struct ledbat_sock *lsock );

int ledbat_sock_userdata_set( struct ledbat_sock *lsock, void *userdata );

int ledbat_sock_alloc( struct ledbat_sock **lsockp
                     , struct ledbat *l );

int ledbat_callback_register( struct ledbat *ledbat
                            , ledbat_callback_t *callback
                            , void *userdata );

int ledbat_process_incoming( struct ledbat *l
                           , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH]
                           , struct mbuf *mb );

int ledbat_alloc( struct ledbat **ledbatp );

/*
 * AT Field
 */

#define ATFIELD_MODE_BLANK 0
#define ATFIELD_MODE_BLACK 1<<0
#define ATFIELD_MODE_WHITE 1<<1
#define ATFIELD_MODE_LOCKL 1<<2 /* license lock */

struct atfield_item {
  struct le le;
  union {
      struct {
          uint32_t three_be;
          uint32_t four_be;
          uint32_t one_be;
          uint32_t two_be;
      } i;
      struct {
          uint64_t two_be;
          uint64_t one_be;
      } l;
      uint8_t b[EVERIP_ADDRESS_LENGTH];
  } ip6;
  uint8_t mode;
};

struct atfield {
  struct list list;
  uint8_t white;
};

int atfield_init( struct atfield **atfieldp );
int atfield_remove( struct atfield *at , uint8_t ip6[EVERIP_ADDRESS_LENGTH] );
uint8_t atfield_check( struct atfield *at , uint8_t ip6[EVERIP_ADDRESS_LENGTH] );
int atfield_add( struct atfield *at , uint8_t ip6[EVERIP_ADDRESS_LENGTH] , uint8_t mode );
void atfield_gowhite( struct atfield *at, bool gowhite);

int atfield_debug(struct re_printf *pf, const struct atfield *atfield);

/*
 * TUN
 */

/* windows has long device names */
#define TUN_IFNAMSIZ (512)

struct tunif {
  int fd;
  char name[TUN_IFNAMSIZ];
  struct csock cs_tmldogma;
};

int tunif_init( struct tunif **tunifp );
int tunif_un_init( struct tunif **tunifp, const char *socket_path );

/*
 * Stacks
 */

struct stack_needle;

uint8_t stack_height_get(const uint8_t *binrep);
void stack_height_set(uint8_t *binrep, uint8_t height);
uint16_t stack_calc_size(uint8_t *binrep, uint8_t *height);
size_t stack_layer_add(uint8_t *binrep, uint64_t nodeid);
int stack_step(struct stack_needle *needle);
int stack_linf_diff(uint8_t left[ROUTE_LENGTH], uint8_t right[ROUTE_LENGTH], int *places);
int stack_debug(struct re_printf *pf, const uint8_t *binrep);

/*
 * Tree of Life
 */

int treeoflife_ledbat_recv( struct mbuf *mb );

/*
 * Modules
 */

#ifdef STATIC
#define DECL_EXPORTS(name) exports_ ##name
#else
#define DECL_EXPORTS(name) exports
#endif

int module_preload(const char *module);
void module_app_unload(void);

#ifndef NET_MAX_NS
#define NET_MAX_NS (4)
#endif

/*
 * Log
 */

enum log_level {
  LEVEL_DEBUG = 0,
  LEVEL_INFO,
  LEVEL_WARN,
  LEVEL_ERROR,
};

typedef void (log_h)(uint32_t level, const char *msg);

struct log {
  struct le le;
  log_h *h;
};

void log_register_handler(struct log *logh);
void log_unregister_handler(struct log *logh);
void log_enable_debug(bool enable);
void log_enable_info(bool enable);
void log_enable_stderr(bool enable);
void vlog(enum log_level level, const char *fmt, va_list ap);
void loglv(enum log_level level, const char *fmt, ...);
void debug(const char *fmt, ...);
void info(const char *fmt, ...);
void warning(const char *fmt, ...);
void error(const char *fmt, ...);

/*
 * Net - Networking
 */

struct network;

typedef void (net_change_h)(void *arg);

int  net_alloc(struct network **netp);
int  net_use_nameserver(struct network *net, const struct sa *ns);
void net_change(struct network *net, uint32_t interval,
    net_change_h *ch, void *arg);
void net_force_change(struct network *net);
bool net_check(struct network *net);
int  net_af(const struct network *net);
int  net_debug(struct re_printf *pf, const struct network *net);
const struct sa *net_laddr_af(const struct network *net, int af);
const char      *net_domain(const struct network *net);
struct dnsc     *net_dnsc(const struct network *net);

enum NETEVENT_EVENT {
     NETEVENT_EVENT_INIT = 0
   , NETEVENT_EVENT_CLOSE = 1
   , NETEVENT_EVENT_DEV_UP = 2
   , NETEVENT_EVENT_DEV_DOWN = 3
   , NETEVENT_EVENT_ADDR_NEW = 4
   , NETEVENT_EVENT_ADDR_DEL = 5
   , NETEVENT_EVENT_ADDR_EXISTS = 6
};

struct netevents;
struct netevents_runner;

enum NETEVENTS_IFACE_KIND {
     NETEVENTS_IFACE_KIND_UNKNOWN  = 0
   , NETEVENTS_IFACE_KIND_LOOPBACK = 1
   , NETEVENTS_IFACE_KIND_ETHERNET = 2
   , NETEVENTS_IFACE_KIND_WIRELESS = 3
   , NETEVENTS_IFACE_KIND_IPTUNNEL = 4
};

struct netevent_event {
  struct netevents *ne;
  enum NETEVENT_EVENT type;

#define NETEVENT_EVENT_OPT_NAME  (1<<0)
#define NETEVENT_EVENT_OPT_INDEX (1<<1)
#define NETEVENT_EVENT_OPT_ADDR  (1<<2)
#define NETEVENT_EVENT_OPT_KIND  (1<<3)
  uint16_t if_options;

  const char *if_name;
  unsigned int if_index;
  enum NETEVENTS_IFACE_KIND if_kind;

  struct sa sa;
};

static inline const char * netevents_iface_kind_tostr(enum NETEVENTS_IFACE_KIND kind)
{
  switch (kind) {
    case NETEVENTS_IFACE_KIND_UNKNOWN:
      return "UNKNOWN";
    case NETEVENTS_IFACE_KIND_LOOPBACK:
      return "LOOPBACK";
    case NETEVENTS_IFACE_KIND_ETHERNET:
      return "ETHERNET";
    case NETEVENTS_IFACE_KIND_WIRELESS:
      return "WIRELESS";
    case NETEVENTS_IFACE_KIND_IPTUNNEL:
      return "IPTUNNEL";
    default:
      break;
  }
  return "UNKNOWN";
}

/**
 * Defines the list apply handler
 *
 * @param event  Netevent event
 * @param arg Handler argument
 *
 * @return true to stop traversing, false to continue
 */
typedef bool (netevents_interfaces_apply_h)(struct netevent_event *event, void *arg);

int netevents_alloc( struct netevents **neteventsp, struct magi_eventdriver *ed );
int netevents_runner_alloc( struct netevents_runner **nerp, struct mqueue *mq );
int netevents_interfaces_apply( struct netevents *ne , netevents_interfaces_apply_h *fn , void *arg);

/* platform specific */
int netevents_platform_getkind( const char* ifname, enum NETEVENTS_IFACE_KIND *kindp );

/*
 * User Interface
 */

typedef int  (ui_output_h)(const char *str);

struct ui {
  struct le le;
  const char *name;
  ui_output_h *outputh;
};

void ui_register(struct ui *ui);
void ui_unregister(struct ui *ui);

void ui_reset(void);
void ui_input(char key);
void ui_input_key(char key, struct re_printf *pf);
void ui_input_str(const char *str);
int  ui_input_pl(struct re_printf *pf, const struct pl *pl);
void ui_output(const char *fmt, ...);
bool ui_isediting(void);
int  ui_password_prompt(char **passwordp);


/*
 * Command interface
 */

#define KEYCODE_NONE   (0x00)
#define KEYCODE_REL    (0x04)
#define KEYCODE_ESC    (0x1b)

enum {
  CMD_PRM  = (1<<0),
  CMD_PROG = (1<<1),

  CMD_IPRM = CMD_PRM | CMD_PROG,
};

struct cmd_arg {
  char key;
  char *prm;
  bool complete;
  void *data;
};

struct cmd {
  const char *name;
  char key;
  int flags;
  const char *desc;
  re_printf_h *h;
};

struct cmd_ctx;
struct commands;

int  cmd_init(struct commands **commandsp);
int  cmd_register(struct commands *commands,
      const struct cmd *cmdv, size_t cmdc);
void cmd_unregister(struct commands *commands, const struct cmd *cmdv);
int  cmd_process(struct commands *commands, struct cmd_ctx **ctxp, char key,
     struct re_printf *pf, void *data);
int  cmd_process_long(struct commands *commands, const char *str, size_t len,
          struct re_printf *pf_resp, void *data);
int cmd_print(struct re_printf *pf, const struct commands *commands);
const struct cmd *cmd_find_long(const struct commands *commands,
        const char *name);
struct cmds *cmds_find(const struct commands *commands,
           const struct cmd *cmdv);

#if defined (PATH_MAX)
#define FS_PATH_MAX PATH_MAX
#elif defined (_POSIX_PATH_MAX)
#define FS_PATH_MAX _POSIX_PATH_MAX
#else
#define FS_PATH_MAX 512
#endif

/*
 * EVER/IP instance
 */

int everip_init( const uint8_t skey[NOISE_SECRET_KEY_LEN]
               , uint16_t port_default );
void everip_close(void);

struct network *everip_network(void);
struct magi *everip_magi(void);
struct magi_melchior *everip_magi_melchior(void);
struct magi_eventdriver *everip_eventdriver(void);
struct netevents *everip_netevents(void);
struct ledbat *everip_ledbat(void);
struct commands *everip_commands(void);
struct noise_engine *everip_noise(void);
struct conduits *everip_conduits(void);
struct atfield *everip_atfield(void);

int everip_addr_copy(uint8_t everip_addr[EVERIP_ADDRESS_LENGTH]);

/* udp port */
void everip_udpport_set(uint16_t port);
uint16_t everip_udpport_get(void);

static inline void main_goodbye(void)
{
  re_printf("Good-bye.\n");
  module_app_unload();
  re_cancel();
}

#ifdef __cplusplus
}
#endif


#endif /* EVERIP_H__ */
