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
#include "blake2s.h"

#if defined(HAVE_GENDO)
#include <gendo.h>
#endif

#if defined(SIGNED_CLA_LICENSE)
#include <cla_license_data.h>
#endif

#if 1
#define noise_info(...)
#define noise_debug(...)
#define noise_error(...)
#define handshake_error(...)
#define handshake_debug(...)
#else
#define noise_info error
#define noise_debug error
#define noise_error error
#define handshake_error error
#define handshake_debug error
#endif

static const uint8_t g_hshake[37] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

#if defined(SIGNED_CLA_LICENSE)
  CLA_LICENSE_DATA__NOISE_INIT
#else
#error Please contact connectFree Licensing or its distributor network for a license to use this product.
static const uint8_t g_ident[] = "ConnectFree(R) EVER/IP(R) v1 (c) kristopher tate and ConnectFree Corporation";
static const uint8_t g_identkey[] = "NOT LICENSED: THIS KEY MUST BE LICENSED FROM CONNECTFREE CORPORATION";
#endif

#define UNSIGNED_LONG_BITS 32 /*(sizeof(unsigned long) * 8)*/

enum rfc6479_values {
    RFC6479_BITS_TOTAL = 2048
  , RFC6479_REDUNDANT_BITS = UNSIGNED_LONG_BITS
  , RFC6479_REDUNDANT_BITS_SHIFTBY = (31 - __builtin_clz(UNSIGNED_LONG_BITS))
  , RFC6479_WINDOW_SIZE = RFC6479_BITS_TOTAL - RFC6479_REDUNDANT_BITS
};

ASSERT_COMPILETIME(UNSIGNED_LONG_BITS == 32);
ASSERT_COMPILETIME(RFC6479_REDUNDANT_BITS_SHIFTBY == 5);

#define REKEY_TIMEOUT 5000
#define REKEY_TIMEOUT_JITTER_MAX 333
#define REKEY_AFTER_TIME 120000
#define KEEPALIVE_TIMEOUT 10000
#define REJECT_AFTER_TIME 180000
#define REKEY_AFTER_MESSAGES (UINT64_MAX - 0xffff)
#define REJECT_AFTER_MESSAGES (UINT64_MAX - RFC6479_WINDOW_SIZE - 1)
#define INITIATIONS_PER_SECOND 20
#define MAX_TIMER_HANDSHAKES ((90000) / REKEY_TIMEOUT)

union rfc6479_counter {
  struct {
    uint64_t counter;
    unsigned long backtrack[RFC6479_BITS_TOTAL / UNSIGNED_LONG_BITS];
  } receive;
  uint64_t counter;
};

struct noise_symmetric_key {
  uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
  union rfc6479_counter counter;
  uint64_t birthdate;
  bool is_valid;
};

#define NOISE_LOOKUP_KIND_SESSION 1
#define NOISE_LOOKUP_KIND_KEYPAIR 2
struct noise_idlookup {
  struct le le;
  uint8_t kind;
  uint32_t id;
};

struct noise_keypair {
  struct noise_idlookup lookup;
  struct noise_session *ns;
  struct noise_symmetric_key sending;
  struct noise_symmetric_key receiving;
  uint32_t remote_index;
  bool its_my_plane;
  
  uint64_t rx_bytes, tx_bytes;
  struct le lsock_le;
};

enum noise_handshake_state {
  HANDSHAKE_ZEROED,
  HANDSHAKE_CREATED_INITIATION,
  HANDSHAKE_CONSUMED_INITIATION,
  HANDSHAKE_CREATED_RESPONSE,
  HANDSHAKE_CONSUMED_RESPONSE
};

struct noise_session_handshake {
  enum noise_handshake_state state;
  uint64_t last_initiation_consumption;

  struct noise_si *static_identity;

  uint8_t ephemeral_private[NOISE_PUBLIC_KEY_LEN];
  uint8_t remote_static[NOISE_PUBLIC_KEY_LEN];
  uint8_t remote_ephemeral[NOISE_PUBLIC_KEY_LEN];
  uint8_t precomputed_static_static[NOISE_PUBLIC_KEY_LEN];

  uint8_t preshared_key[NOISE_SYMMETRIC_KEY_LEN];

  uint8_t hash[NOISE_HASH_LEN];
  uint8_t chaining_key[NOISE_HASH_LEN];

  uint8_t latest_timestamp[NOISE_TIMESTAMP_LEN];
  uint32_t remote_index;

  struct le lsock_le;
};

struct noise_session {
  struct noise_idlookup lookup;
  struct le le_all;

  struct noise_engine *ne;

  uintptr_t channel_lock;

  enum NOISE_SESSION_EVENT event_last;

  struct noise_keypair *keypair_now;
  struct noise_keypair *keypair_then;
  struct noise_keypair *keypair_next;

  struct noise_session_handshake handshake;
  uint64_t last_sent_handshake;

  uint64_t keepalive_send;
  uint64_t keepalive_recv;
  uint64_t keepalive_diff;
  uint16_t keepalive_nonce;

  uint64_t rx_last, tx_last;

  uint64_t rx_bytes, tx_bytes;
  unsigned int tmr_hs_attempts;
  unsigned long persistent_keepalive_interval;
  bool tmr_setup_next_keepalive;
  bool need_resend_queue;
  bool sent_lastminute_handshake;

  struct tmr tmr_hs_new, tmr_hs_rexmit, tmr_keepalive, tmr_zero, tmr_persist;

};

enum NOISE_TIMER_ON {
     NOISE_TIMER_ON_EKEY       = 0
   , NOISE_TIMER_ON_DATA_TX    = 1
   , NOISE_TIMER_ON_DATA_RX    = 2
   , NOISE_TIMER_ON_POLY_RX    = 3
   , NOISE_TIMER_ON_POLY_TXRX  = 4
   , NOISE_TIMER_ON_HAND_INIT  = 5
   , NOISE_TIMER_ON_HAND_DONE  = 6
};

#define NOISE_ENCRYPTED_LEN(plain_len) (plain_len + NOISE_AUTHTAG_LEN)

static bool _session_debug(struct le *le, void *arg)
{
  struct re_printf *pf = arg;
  struct noise_session *ns = le->data;
  re_hprintf( pf, "→ %W [CH:%p][%s][TX=%zu][RX=%zu][REF:%zu]\n"
            , ns->handshake.remote_static, NOISE_PUBLIC_KEY_LEN
            , ns->channel_lock
            , noise_session_event_tostr(ns->event_last)
            , ns->tx_bytes
            , ns->rx_bytes
            , mem_nrefs(ns)
            );


  if (ns->keypair_now) {
    re_hprintf( pf, "\t{KEY:NOW} [TX=%zu][RX=%zu]\n"
              , ns->keypair_now->tx_bytes
              , ns->keypair_now->rx_bytes
              );
  }
  if (ns->keypair_then) {
    re_hprintf( pf, "\t{KEY:THEN} [TX=%zu][RX=%zu]\n"
              , ns->keypair_then->tx_bytes
              , ns->keypair_then->rx_bytes
              );
  }
  if (ns->keypair_next) {
    re_hprintf( pf, "\t{KEY:NEXT} [TX=%zu][RX=%zu]\n"
              , ns->keypair_next->tx_bytes
              , ns->keypair_next->rx_bytes
              );
  }

  return false;
}

int noise_engine_debug(struct re_printf *pf, void *arg)
{
  int err = 0;
  struct sa laddr;
  struct noise_engine *ne = arg;
  uint8_t everip_addr[EVERIP_ADDRESS_LENGTH];

  everip_addr_copy(everip_addr);

  sa_set_in6(&laddr, everip_addr, 0);

  err |= re_hprintf(pf, "[Noise Engine]\n");

  err  = re_hprintf( pf, "■ Public Key\n");
  err  = re_hprintf( pf, "→ %W\n", ne->si.public, NOISE_PUBLIC_KEY_LEN);
  err  = re_hprintf( pf, "■ Authenticated EVER/IP Addresses\n");
  err  = re_hprintf( pf, "→ %j\n", &laddr);
  err  = re_hprintf( pf, "■ Sessions\n");

  list_apply(&ne->sessions_all, true, _session_debug, pf);

  err |= re_hprintf(pf, "\n[END]\n");

  return err;
}

static int noise_keypair_create( struct noise_keypair **keypairp
                               , struct noise_session *ns );

static void noise_session_tmr_control( struct noise_session *ns
                                     , enum NOISE_TIMER_ON tkind );

/* This implements Noise_IKpsk2:
 *
 * <- s
 * ******
 * -> e, es, s, ss, {t}
 * <- e, ee, se, psk, {}
 */

static void noise_session_event_run( struct noise_session *ns
                                   , enum NOISE_SESSION_EVENT type)
{
  struct noise_event event;

  if (!ns)
    return;

  /* do timers and stuff */
  switch (type) {
    case NOISE_SESSION_EVENT_BEGIN_PILOT:
      noise_session_keepalive_send(ns);
    case NOISE_SESSION_EVENT_BEGIN_COPILOT:
      ns->sent_lastminute_handshake = false;
      noise_session_tmr_control(ns, NOISE_TIMER_ON_HAND_DONE);
      noise_session_keepalive_send(ns); /* x:test 2017.10.1 */
      break;
    default:
      break;
  }

  warning( "[NOISE] %W [CH:%p][%s]\n"
         , ns->handshake.remote_static, NOISE_PUBLIC_KEY_LEN
         , ns->channel_lock
         , noise_session_event_tostr(type)
         );

  ns->event_last = type;

  event.ne = ns->ne;
  event.ns = ns;
  event.type = type;

  if (ns->keypair_now) {
    lsock_forward(&ns->keypair_now->lsock_le, SOCK_TYPE_NOISE_EVENT, &event);
  }
  
  magi_eventdriver_handler_run( ns->ne->ed
                              , MAGI_EVENTDRIVER_WATCH_NOISE
                              , &event );

}

void noise_si_private_key_set( struct noise_si *si
                             , const uint8_t private_key[NOISE_PUBLIC_KEY_LEN] )
{
  if (private_key) {
    memcpy(si->private, private_key, NOISE_PUBLIC_KEY_LEN);
    si->has_identity = (0 == crypto_scalarmult_base(si->public, private_key));
  } else {
    sodium_memzero(si->private, NOISE_PUBLIC_KEY_LEN);
    sodium_memzero(si->public, NOISE_PUBLIC_KEY_LEN);
    si->has_identity = false;
  }
}

static void _kdf( uint8_t *first_dst
                , uint8_t *second_dst
                , uint8_t *third_dst
                , const uint8_t *data
                , size_t first_len
                , size_t second_len
                , size_t third_len
                , size_t data_len
                , const uint8_t chaining_key[NOISE_HASH_LEN])
{
  uint8_t secret[BLAKE2S_OUTBYTES];
  uint8_t output[BLAKE2S_OUTBYTES + 1];

  if (   first_len > BLAKE2S_OUTBYTES
      || second_len > BLAKE2S_OUTBYTES
      || third_len > BLAKE2S_OUTBYTES
      || ((second_len || second_dst || third_len || third_dst) && (!first_len || !first_dst))
      || ((third_len || third_dst) && (!second_len || !second_dst))
      ) {
    BREAKPOINT;
  }

  /* Extract entropy from data into secret */
  blake2s_hmac(secret, data, chaining_key, BLAKE2S_OUTBYTES, data_len, NOISE_HASH_LEN);

  if (!first_dst || !first_len)
    goto out;

  /* Expand first key: key = secret, data = 0x1 */
  output[0] = 1;
  blake2s_hmac(output, output, secret, BLAKE2S_OUTBYTES, 1, BLAKE2S_OUTBYTES);
  memcpy(first_dst, output, first_len);

  if (!second_dst || !second_len)
    goto out;

  /* Expand second key: key = secret, data = first-key || 0x2 */
  output[BLAKE2S_OUTBYTES] = 2;
  blake2s_hmac(output, output, secret, BLAKE2S_OUTBYTES, BLAKE2S_OUTBYTES + 1, BLAKE2S_OUTBYTES);
  memcpy(second_dst, output, second_len);

  if (!third_dst || !third_len)
    goto out;

  /* Expand third key: key = secret, data = second-key || 0x3 */
  output[BLAKE2S_OUTBYTES] = 3;
  blake2s_hmac(output, output, secret, BLAKE2S_OUTBYTES, BLAKE2S_OUTBYTES + 1, BLAKE2S_OUTBYTES);
  memcpy(third_dst, output, third_len);

out:
  /* Clear sensitive data from stack */
  sodium_memzero(secret, BLAKE2S_OUTBYTES);
  sodium_memzero(output, BLAKE2S_OUTBYTES + 1);
}

static void _mix_hash( uint8_t hash[NOISE_HASH_LEN]
                     , const uint8_t *src
                     , size_t src_len)
{
  blake2s_ctx ctx;
  blake2s_init(&ctx, NOISE_HASH_LEN, NULL, 0);
  blake2s_update(&ctx, hash, NOISE_HASH_LEN);
  blake2s_update(&ctx, src, src_len);
  blake2s_final(&ctx, hash);
}

static void _mix_psk( uint8_t chaining_key[NOISE_HASH_LEN]
                    , uint8_t hash[NOISE_HASH_LEN]
                    , uint8_t key[NOISE_SYMMETRIC_KEY_LEN]
                    , const uint8_t psk[NOISE_SYMMETRIC_KEY_LEN] )
{
  uint8_t temp_hash[NOISE_HASH_LEN];
  _kdf( chaining_key
      , temp_hash
      , key
      , psk
      , NOISE_HASH_LEN
      , NOISE_HASH_LEN
      , NOISE_SYMMETRIC_KEY_LEN
      , NOISE_SYMMETRIC_KEY_LEN
      , chaining_key );
  _mix_hash(hash, temp_hash, NOISE_HASH_LEN);
  sodium_memzero(temp_hash, NOISE_HASH_LEN);
}

static void _handshake_init( struct noise_engine *ne
                           , uint8_t chaining_key[NOISE_HASH_LEN]
                           , uint8_t hash[NOISE_HASH_LEN]
                           , const uint8_t remote_static[NOISE_PUBLIC_KEY_LEN])
{
  memcpy(hash, ne->hshake_hash, NOISE_HASH_LEN);
  memcpy(chaining_key, ne->hshake_chaining_key, NOISE_HASH_LEN);
  _mix_hash(hash, remote_static, NOISE_PUBLIC_KEY_LEN);
}

static void _handshake_zero(struct noise_session_handshake *handshake)
{
  sodium_memzero(&handshake->ephemeral_private, NOISE_PUBLIC_KEY_LEN);
  sodium_memzero(&handshake->remote_ephemeral, NOISE_PUBLIC_KEY_LEN);
  sodium_memzero(&handshake->hash, NOISE_HASH_LEN);
  sodium_memzero(&handshake->chaining_key, NOISE_HASH_LEN);
  handshake->remote_index = 0;
  handshake->state = HANDSHAKE_ZEROED;

  list_unlink(&handshake->lsock_le);

}

static void _message_ephemeral( uint8_t ephemeral_dst[NOISE_PUBLIC_KEY_LEN]
                              , const uint8_t ephemeral_src[NOISE_PUBLIC_KEY_LEN]
                              , uint8_t chaining_key[NOISE_HASH_LEN]
                              , uint8_t hash[NOISE_HASH_LEN])
{
  if (ephemeral_dst != ephemeral_src)
    memcpy(ephemeral_dst, ephemeral_src, NOISE_PUBLIC_KEY_LEN);
  _mix_hash(hash, ephemeral_src, NOISE_PUBLIC_KEY_LEN);
  _kdf(chaining_key, NULL, NULL, ephemeral_src, NOISE_HASH_LEN, 0, 0, NOISE_PUBLIC_KEY_LEN, chaining_key);
}

static bool __attribute__((warn_unused_result)) 
_mix_dh( uint8_t chaining_key[NOISE_HASH_LEN]
       , uint8_t key[NOISE_SYMMETRIC_KEY_LEN]
       , const uint8_t private[NOISE_PUBLIC_KEY_LEN]
       , const uint8_t public[NOISE_PUBLIC_KEY_LEN] )
{
  uint8_t dh_calculation[NOISE_PUBLIC_KEY_LEN];

  if (crypto_scalarmult_curve25519( dh_calculation /* q */
                                  , private /* n */
                                  , public /* p */ ) != 0)
  {
    return false;
  }

  _kdf( chaining_key
      , key
      , NULL
      , dh_calculation
      , NOISE_HASH_LEN
      , NOISE_SYMMETRIC_KEY_LEN
      , 0
      , NOISE_PUBLIC_KEY_LEN
      , chaining_key );

  sodium_memzero(dh_calculation, NOISE_PUBLIC_KEY_LEN);

  return true;
}

static void _mhash_message_encrypt( uint8_t *dst_ciphertext
                                  , const uint8_t *src_plaintext
                                  , size_t src_len
                                  , uint8_t key[NOISE_SYMMETRIC_KEY_LEN]
                                  , uint8_t hash[NOISE_HASH_LEN] )
{
  uint8_t nonce[NOISE_NONCE_LEN] = {0};

  crypto_aead_chacha20poly1305_encrypt( dst_ciphertext
                                      , NULL
                                      , src_plaintext
                                      , src_len
                                      , hash /* ad */
                                      , NOISE_HASH_LEN /* adlen */
                                      , NULL /* NSEC */
                                      , nonce /* NONCE will always be zero for Noise_IK */
                                      , key /* key */
                                      );

  _mix_hash( hash
           , dst_ciphertext
           , NOISE_ENCRYPTED_LEN( src_len )
           );
}

static bool _mhash_message_decrypt( uint8_t *dst_plaintext
                                  , const uint8_t *src_ciphertext
                                  , size_t src_len
                                  , uint8_t key[NOISE_SYMMETRIC_KEY_LEN]
                                  , uint8_t hash[NOISE_HASH_LEN] )
{
  uint8_t nonce[NOISE_NONCE_LEN] = {0};

  if (crypto_aead_chacha20poly1305_decrypt( dst_plaintext /* out message */
                                          , NULL /* out mlen */
                                          , NULL /* NSEC */
                                          , src_ciphertext
                                          , src_len
                                          , hash /* ad */
                                          , NOISE_HASH_LEN /* adlen */
                                          , nonce /* NONCE will always be zero for Noise_IK */
                                          , key /* key */
                                          ) != 0) {
    return false;
  }
    
  _mix_hash(hash, src_ciphertext, src_len);

  return true;
}

static void _symmetric_key_init( struct noise_symmetric_key *key )
{
  key->counter.counter = 0;
  sodium_memzero( key->counter.receive.backtrack
                , sizeof(key->counter.receive.backtrack) );
  key->birthdate = tmr_jiffies();
  key->is_valid = true;
}

static void _derive_keys( struct noise_symmetric_key *first_dst
                        , struct noise_symmetric_key *second_dst
                        , const uint8_t chaining_key[NOISE_HASH_LEN] )
{
  _kdf( first_dst->key
      , second_dst->key
      , NULL
      , NULL
      , NOISE_SYMMETRIC_KEY_LEN
      , NOISE_SYMMETRIC_KEY_LEN
      , 0
      , 0
      , chaining_key
      );
  _symmetric_key_init( first_dst );
  _symmetric_key_init( second_dst );
}

static inline
int rfc6479_counter_ok( union rfc6479_counter *counter
                      , uint64_t their_counter)
{
  unsigned long index, index_current, top, i, bitloc;

  if ( counter->receive.counter >= REJECT_AFTER_MESSAGES + 1
    || their_counter >= REJECT_AFTER_MESSAGES )
    return EBADMSG;

  ++their_counter;

  if ((RFC6479_WINDOW_SIZE + their_counter) < counter->receive.counter) {
    return EBADMSG;
  }

  index = their_counter >> RFC6479_REDUNDANT_BITS_SHIFTBY;

  if (their_counter > counter->receive.counter) {
    index_current = counter->receive.counter >> RFC6479_REDUNDANT_BITS_SHIFTBY;
    top = arch_min((unsigned long)(index - index_current), (unsigned long)(RFC6479_BITS_TOTAL / UNSIGNED_LONG_BITS));
    for (i = 1; i <= top; ++i) {
      counter->receive.backtrack[(i + index_current) & ((RFC6479_BITS_TOTAL / UNSIGNED_LONG_BITS) - 1)] = 0;
    }

    counter->receive.counter = their_counter;
  }

  index &= (RFC6479_BITS_TOTAL / UNSIGNED_LONG_BITS) - 1;
  bitloc = (their_counter & (UNSIGNED_LONG_BITS - 1));

  if (counter->receive.backtrack[index] & (1<<bitloc)) {
    noise_error( "BAD: [%W]\n", counter->receive.backtrack, 256);
    return EBADMSG; /* already received */
  } else {
    /*noise_info( "MOK: [%W]\n", counter->receive.backtrack, 256);*/
  }

  counter->receive.backtrack[index] |= (1<<bitloc);
  return 0;
}

/* */

uint64_t noise_session_score(struct noise_session *ns)
{
  if (!ns)
    return UINT64_MAX;

  if ( ns->event_last < NOISE_SESSION_EVENT_CONNECTED
    || ns->keepalive_diff > (KEEPALIVE_TIMEOUT + REKEY_TIMEOUT))
    return UINT64_MAX - ns->event_last;

  return ns->keepalive_diff + (ns->tx_last > ns->rx_last ? ns->tx_last - ns->rx_last : 0);
}

int noise_session_counters( struct noise_session *ns
                          , struct noise_session_counters *counters )
{
  if (!ns || !counters)
    return EINVAL;

  counters->rx_bytes = ns->rx_bytes;
  counters->tx_bytes = ns->tx_bytes;

  return 0;
}

/* session send */

int noise_session_hs_step1_pilot( struct noise_session *ns
                                , bool is_retry
                                , struct lsock *lsock )
{
  struct mbuf *mb = NULL;
  size_t mb_pos;
  struct noise_session_handshake *hs = NULL;
  uint8_t timestamp[NOISE_TIMESTAMP_LEN];
  uint8_t key[NOISE_SYMMETRIC_KEY_LEN];

  uint32_t out_sender_index;
  uint8_t out_unencrypted_ephemeral[32];
  uint8_t out_encrypted_static[NOISE_ENCRYPTED_LEN(32)];
  uint8_t out_encrypted_timestamp[NOISE_ENCRYPTED_LEN(12)];

  noise_info("noise_session_hs_step1_pilot\n");

  if (!ns)
    return EINVAL;

  hs = &ns->handshake;

  if (!hs->static_identity->has_identity)
    goto out;

  if (!is_retry)
    ns->tmr_hs_attempts = 0;

  if ( ns->event_last == NOISE_SESSION_EVENT_CONNECTED
    || ns->event_last > NOISE_SESSION_EVENT_REKEY )
    return EALREADY;

  if (ns->last_sent_handshake + REKEY_TIMEOUT > tmr_jiffies())
    return EALREADY;

  ns->last_sent_handshake = tmr_jiffies();

  _handshake_init(ns->ne, hs->chaining_key, hs->hash, hs->remote_static);

  lsock_install(lsock, &hs->lsock_le, ns);

  /* e */
  randombytes_buf(hs->ephemeral_private, 32);
  if (0 != crypto_scalarmult_base(out_unencrypted_ephemeral, hs->ephemeral_private))
    goto out;

  _message_ephemeral( out_unencrypted_ephemeral
                    , out_unencrypted_ephemeral
                    , hs->chaining_key
                    , hs->hash);

  /* es */
  if (!_mix_dh( hs->chaining_key
              , key
              , hs->ephemeral_private
              , hs->remote_static))
    goto out;

  /* s */
  _mhash_message_encrypt( out_encrypted_static
                        , hs->static_identity->public
                        , NOISE_PUBLIC_KEY_LEN
                        , key
                        , hs->hash);

  /* ss */
  _kdf( hs->chaining_key
      , key
      , NULL
      , hs->precomputed_static_static
      , NOISE_HASH_LEN
      , NOISE_SYMMETRIC_KEY_LEN
      , 0
      , NOISE_PUBLIC_KEY_LEN
      , hs->chaining_key);

  /* {t} */
  
  tai64n_now( timestamp );

  _mhash_message_encrypt( out_encrypted_timestamp
                        , timestamp
                        , NOISE_TIMESTAMP_LEN
                        , key
                        , hs->hash);

  /* unlink if were linked */
  hash_unlink(&ns->lookup.le);

  /* reup */
  ns->lookup.id = ns->ne->sessions_counter++;
  hash_append( ns->ne->idlookup
             , ns->lookup.id
             , &ns->lookup.le
             , &ns->lookup);

  out_sender_index = arch_htole32( ns->lookup.id );

  hs->state = HANDSHAKE_CREATED_INITIATION;

  /* write and send */

  mb = mbuf_alloc(EVER_OUTWARD_MBE_LENGTH*2);
  mb->pos = EVER_OUTWARD_MBE_POS;
  mb->end = EVER_OUTWARD_MBE_POS;

  mb_pos = mb->pos;

  mbuf_write_u32(mb, arch_htole32( 1 ));
  mbuf_write_u32(mb, out_sender_index);
  mbuf_write_mem(mb, out_unencrypted_ephemeral, 32);
  mbuf_write_mem(mb, out_encrypted_static, NOISE_ENCRYPTED_LEN(32));
  mbuf_write_mem(mb, out_encrypted_timestamp, NOISE_ENCRYPTED_LEN(12));

  mbuf_fill(mb, 0, 16); /* mac1 */
  mbuf_fill(mb, 0, 16); /* mac2 */

  /*debug("resetting position: %u\n", mb->pos - mb_pos);*/

  mbuf_set_pos(mb, mb_pos);

  noise_session_tmr_control(ns, NOISE_TIMER_ON_HAND_INIT);

  lsock_forward(&hs->lsock_le, SOCK_TYPE_DATA_MB, mb);

out:
  sodium_memzero(key, NOISE_SYMMETRIC_KEY_LEN);
  mb = mem_deref(mb);
  return 0;
}

static struct noise_session *
noise_session_hs_step2_copilot( struct noise_engine *ne
                              , uintptr_t channel_lock
                              , struct mbuf *mb
                              , enum NOISE_ENGINE_RECIEVE *err )
{
  bool replay_attack, flood_attack;
  uint8_t s[NOISE_PUBLIC_KEY_LEN];
  uint8_t e[NOISE_PUBLIC_KEY_LEN];
  uint8_t t[NOISE_TIMESTAMP_LEN];
  uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
  uint8_t hash[NOISE_HASH_LEN];
  uint8_t chaining_key[NOISE_HASH_LEN];

  uint32_t in_sender_index;
  uint8_t in_unencrypted_ephemeral[32];
  uint8_t in_encrypted_static[NOISE_ENCRYPTED_LEN(32)];
  uint8_t in_encrypted_timestamp[NOISE_ENCRYPTED_LEN(12)];
  uint8_t in_mac1[16];
  uint8_t in_mac2[16];

  struct noise_session *ns = NULL;
  struct noise_session_handshake *hs;

  if (!ne || !ne->si.has_identity || !mb) {
    *err = NOISE_ENGINE_RECIEVE_EINVAL;
    return NULL;
  }

  /* read msg */
  if (mbuf_get_left(mb) < 144) {
    *err = NOISE_ENGINE_RECIEVE_EBADMSG;
    return NULL;
  }

  in_sender_index = arch_letoh32( mbuf_read_u32(mb) );
  mbuf_read_mem(mb, in_unencrypted_ephemeral, 32);
  mbuf_read_mem(mb, in_encrypted_static, NOISE_ENCRYPTED_LEN(32));
  mbuf_read_mem(mb, in_encrypted_timestamp, NOISE_ENCRYPTED_LEN(12));
  mbuf_read_mem(mb, in_mac1, 16);
  mbuf_read_mem(mb, in_mac2, 16);

  _handshake_init(ne, chaining_key, hash, ne->si.public);

  /* e */
  _message_ephemeral(e, in_unencrypted_ephemeral, chaining_key, hash);

  /* es */
  if (!_mix_dh(chaining_key, key, ne->si.private, e))
    goto out;

  /* s */
  if (!_mhash_message_decrypt(s, in_encrypted_static, sizeof(in_encrypted_static), key, hash))
    goto out;

  handshake_debug("INCOMING: %W\n", s, NOISE_PUBLIC_KEY_LEN);

  ns = noise_engine_find_session_bykey(ne, channel_lock, s);
  if (!ns) {
    noise_session_new( &ns
                     , ne
                     , channel_lock
                     , s
                     , NULL /*preshared_key*/);
  }

  if (!ns) {
    *err = NOISE_ENGINE_RECIEVE_EINVAL;
    goto out;
  }

  hs = &ns->handshake;

  /* ss */
  _kdf( chaining_key
      , key
      , NULL
      , hs->precomputed_static_static
      , NOISE_HASH_LEN
      , NOISE_SYMMETRIC_KEY_LEN
      , 0
      , NOISE_PUBLIC_KEY_LEN
      , chaining_key);

  /* {t} */
  if (!_mhash_message_decrypt( t
                             , in_encrypted_timestamp
                             , sizeof(in_encrypted_timestamp)
                             , key
                             , hash))
    goto out;

  replay_attack = memcmp(t, hs->latest_timestamp, NOISE_TIMESTAMP_LEN) <= 0;
  flood_attack = (tmr_jiffies() < hs->last_initiation_consumption + INITIATIONS_PER_SECOND);

  if (replay_attack || flood_attack) {
    ns = NULL;
    *err = NOISE_ENGINE_RECIEVE_EREPLAY;
    goto out;
  }

  memcpy(hs->remote_ephemeral, e, NOISE_PUBLIC_KEY_LEN);
  memcpy(hs->latest_timestamp, t, NOISE_TIMESTAMP_LEN);
  memcpy(hs->hash, hash, NOISE_HASH_LEN);
  memcpy(hs->chaining_key, chaining_key, NOISE_HASH_LEN);
  hs->remote_index = in_sender_index;
  hs->last_initiation_consumption = tmr_jiffies();
  hs->state = HANDSHAKE_CONSUMED_INITIATION;

out:
  sodium_memzero(key, NOISE_SYMMETRIC_KEY_LEN);
  sodium_memzero(hash, NOISE_HASH_LEN);
  sodium_memzero(chaining_key, NOISE_HASH_LEN);
  return ns;
}

static bool noise_session_hs_step3_copilot( struct mbuf **mb_replyp
                                          , struct noise_session *ns )
{
  bool ret = false;
  uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
  struct mbuf *mb_reply = NULL;
  size_t mb_reply_pos;

  uint32_t out_sender_index;
  uint32_t out_receiver_index;
  uint8_t out_unencrypted_ephemeral[32];
  uint8_t out_encrypted_nothing[NOISE_ENCRYPTED_LEN(0)];

  if (!mb_replyp || !ns)
    goto out;

  if (ns->handshake.state != HANDSHAKE_CONSUMED_INITIATION)
    goto out;

  out_receiver_index = ns->handshake.remote_index;

  /* e */
  randombytes_buf(ns->handshake.ephemeral_private, 32);
  if (0 != crypto_scalarmult_base(out_unencrypted_ephemeral, ns->handshake.ephemeral_private))
    goto out;

  _message_ephemeral( out_unencrypted_ephemeral
                    , out_unencrypted_ephemeral
                    , ns->handshake.chaining_key
                    , ns->handshake.hash );

  /* ee */
  if (!_mix_dh( ns->handshake.chaining_key
              , NULL
              , ns->handshake.ephemeral_private
              , ns->handshake.remote_ephemeral))
    goto out;

  /* se */
  if (!_mix_dh( ns->handshake.chaining_key
              , NULL
              , ns->handshake.ephemeral_private
              , ns->handshake.remote_static ))
    goto out;

  /* psk */
  _mix_psk( ns->handshake.chaining_key
          , ns->handshake.hash
          , key
          , ns->handshake.preshared_key );

  /* {} */
  _mhash_message_encrypt( out_encrypted_nothing
                        , NULL
                        , 0
                        , key
                        , ns->handshake.hash );

  /* unlink if were linked */
  hash_unlink(&ns->lookup.le);

  ns->lookup.id = ns->ne->sessions_counter++;
  hash_append( ns->ne->idlookup
             , ns->lookup.id
             , &ns->lookup.le
             , &ns->lookup);

  out_sender_index = arch_htole32( ns->lookup.id );
  ns->handshake.state = HANDSHAKE_CREATED_RESPONSE;
  ret = true;

  /* write-out! */
  mb_reply = mbuf_alloc(EVER_OUTWARD_MBE_LENGTH*2);
  mb_reply->pos = EVER_OUTWARD_MBE_POS;
  mb_reply->end = EVER_OUTWARD_MBE_POS;

  mb_reply_pos = mb_reply->pos;

  mbuf_write_u32(mb_reply, arch_htole32( 2 ));
  mbuf_write_u32(mb_reply, out_sender_index );
  mbuf_write_u32(mb_reply, out_receiver_index );
  mbuf_write_mem(mb_reply, out_unencrypted_ephemeral, 32);
  mbuf_write_mem(mb_reply, out_encrypted_nothing, NOISE_ENCRYPTED_LEN(0));

  mbuf_fill(mb_reply, 0, 16); /* mac1 */
  mbuf_fill(mb_reply, 0, 16); /* mac2 */

  mbuf_set_pos(mb_reply, mb_reply_pos);

  *mb_replyp = mb_reply;

out:
  sodium_memzero(key, NOISE_SYMMETRIC_KEY_LEN);
  return ret;
}

static struct noise_session *
noise_session_hs_step4_pilot( struct noise_engine *ne
                            , struct mbuf *mb
                            , enum NOISE_ENGINE_RECIEVE *err )
{
  struct noise_session *ns = NULL;
  struct noise_session_handshake *hs;

  uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
  uint8_t hash[NOISE_HASH_LEN];
  uint8_t chaining_key[NOISE_HASH_LEN];
  uint8_t e[NOISE_PUBLIC_KEY_LEN];
  uint8_t ephemeral_private[NOISE_PUBLIC_KEY_LEN];
  uint8_t static_private[NOISE_PUBLIC_KEY_LEN];

  enum noise_handshake_state state = HANDSHAKE_ZEROED;

  uint32_t in_sender_index;
  uint32_t in_receiver_index;
  uint8_t in_unencrypted_ephemeral[32];
  uint8_t in_encrypted_nothing[NOISE_ENCRYPTED_LEN(0)];
  uint8_t in_mac1[16];
  uint8_t in_mac2[16];

  if (!ne || !ne->si.has_identity || !mb) {
    *err = NOISE_ENGINE_RECIEVE_EINVAL;
    goto out;
  }

  /* read packet! */
  if (mbuf_get_left(mb) < 88) {
    *err = NOISE_ENGINE_RECIEVE_EBADMSG;
    return NULL;
  }

  in_sender_index = arch_letoh32( mbuf_read_u32(mb) );
  in_receiver_index = arch_letoh32( mbuf_read_u32(mb) );
  mbuf_read_mem(mb, in_unencrypted_ephemeral, 32);
  mbuf_read_mem(mb, in_encrypted_nothing, NOISE_ENCRYPTED_LEN(0));
  mbuf_read_mem(mb, in_mac1, 16);
  mbuf_read_mem(mb, in_mac2, 16);

  ns = noise_engine_lookup_session_byid(ne, in_receiver_index);
  if (!ns) {
    *err = NOISE_ENGINE_RECIEVE_EINVAL;
    goto fail;
  }

  hs = &ns->handshake;

  state = hs->state;
  memcpy(hash, hs->hash, NOISE_HASH_LEN);
  memcpy(chaining_key, hs->chaining_key, NOISE_HASH_LEN);
  memcpy(ephemeral_private, hs->ephemeral_private, NOISE_PUBLIC_KEY_LEN);

  if (state != HANDSHAKE_CREATED_INITIATION) {
    *err = NOISE_ENGINE_RECIEVE_EINVAL;
    goto fail;
  }

  /* e */
  _message_ephemeral(e, in_unencrypted_ephemeral, chaining_key, hash);

  /* ee */
  if (!_mix_dh(chaining_key, NULL, ephemeral_private, e)) {
    *err = NOISE_ENGINE_RECIEVE_EBADMSG;
    goto out;
  }

  /* se */
  if (!_mix_dh(chaining_key, NULL, ne->si.private, e)) {
    *err = NOISE_ENGINE_RECIEVE_EBADMSG;
    goto out;
  }

  /* psk */
  _mix_psk(chaining_key, hash, key, hs->preshared_key);

  /* {} */
  if (!_mhash_message_decrypt( NULL
                             , in_encrypted_nothing
                             , sizeof(in_encrypted_nothing)
                             , key
                             , hash)) {
    *err = NOISE_ENGINE_RECIEVE_EBADMSG;
    goto fail;
  }

  /* Success! Copy everything to peer */
  /* It's important to check that the state is still the same */
  if (hs->state != state) {
    *err = NOISE_ENGINE_RECIEVE_EBADMSG;
    goto fail;
  }
  
  memcpy(hs->remote_ephemeral, e, NOISE_PUBLIC_KEY_LEN);
  memcpy(hs->hash, hash, NOISE_HASH_LEN);
  memcpy(hs->chaining_key, chaining_key, NOISE_HASH_LEN);
  hs->remote_index = in_sender_index;
  hs->state = HANDSHAKE_CONSUMED_RESPONSE;
  goto out;

fail:
  ns = NULL;
out:
  sodium_memzero(key, NOISE_SYMMETRIC_KEY_LEN);
  sodium_memzero(hash, NOISE_HASH_LEN);
  sodium_memzero(chaining_key, NOISE_HASH_LEN);
  sodium_memzero(ephemeral_private, NOISE_PUBLIC_KEY_LEN);
  sodium_memzero(static_private, NOISE_PUBLIC_KEY_LEN);
  return ns;

}

static bool noise_session_hs_step5_begin( struct noise_session *ns )
{
  struct noise_keypair *new_keypair;
  struct noise_session_handshake *s_hs;

  s_hs = &ns->handshake;

  if (s_hs->state != HANDSHAKE_CREATED_RESPONSE && s_hs->state != HANDSHAKE_CONSUMED_RESPONSE)
    goto fail;

  if (noise_keypair_create(&new_keypair, ns))
    goto fail;

  if (!new_keypair)
    goto fail;

  new_keypair->its_my_plane = (s_hs->state == HANDSHAKE_CONSUMED_RESPONSE);
  new_keypair->remote_index = s_hs->remote_index;
  new_keypair->lookup.id = ns->lookup.id;

  /* unlink engine id from handshake and reassign to keypair */
  ns->lookup.id = 0;
  hash_unlink(&ns->lookup.le);
  hash_append( ns->ne->idlookup
             , new_keypair->lookup.id
             , &new_keypair->lookup.le
             , &new_keypair->lookup);

  if (new_keypair->its_my_plane)
    _derive_keys(&new_keypair->sending, &new_keypair->receiving, s_hs->chaining_key);
  else
    _derive_keys(&new_keypair->receiving, &new_keypair->sending, s_hs->chaining_key);

  /* zero-out handshake */
  _handshake_zero( s_hs );

  /* now add keypair to session */

  /* remove old session */
  ns->keypair_then = mem_deref(ns->keypair_then);

  if (new_keypair->its_my_plane) {
    /* STATE 1A */
    if (ns->keypair_next) {
      /* STATE 1A.1 */
      ns->keypair_then = ns->keypair_next;
      ns->keypair_next = NULL;
    } else {
      /* STATE 1A.2 */
      ns->keypair_then = ns->keypair_now;
      ns->keypair_now = NULL;
    }
    ns->keypair_now = new_keypair;
  } else {
    /* STATE 1B */
    ns->keypair_next = mem_deref( ns->keypair_next );
    ns->keypair_next = new_keypair;
  }

  return true;

fail:
  return false;
}

static int _noise_session_send( struct noise_session *ns
                              , struct mbuf *mb
                              , uint8_t message_type )
{
  uint8_t nonce[NOISE_NONCE_LEN] = {0};
  uint64_t *nonce_64 = (uint64_t *)(void *)&nonce[NOISE_NONCE_LEN - sizeof(uint64_t)];
  struct noise_symmetric_key *key;
  size_t mb_pos;
  size_t mlen;

  if (!ns || !mb)
    return EINVAL;

  noise_info("noise_session_send\n");

  if (!ns->keypair_now)
    return EINVAL;

  key = &ns->keypair_now->sending;

  /* get nonce */
  if (!key->is_valid || (key->birthdate + REJECT_AFTER_TIME) <= tmr_jiffies()) {
    key->is_valid = false;
    return EINVAL;
  }

  *nonce_64 = (++key->counter.counter - 1);

  if (*nonce_64 >= REJECT_AFTER_MESSAGES) {
    key->is_valid = false;
    return EINVAL;
  }

  *nonce_64 = arch_htole64( *nonce_64 );

  /* kickback mb */
  mbuf_advance(mb, -(ssize_t)(16 + NOISE_AUTHTAG_LEN));
  mb_pos = mb->pos;

  mbuf_write_u32(mb, arch_htole32( message_type )); /* L:4 */
  mbuf_write_u32(mb, arch_htole32( ns->keypair_now->remote_index )); /* L:4 */
  mbuf_write_u64(mb, *nonce_64); /* L:8 */

  /* we use this for tx counter later */
  mlen = mbuf_get_left(mb) - NOISE_AUTHTAG_LEN;

  crypto_aead_chacha20poly1305_encrypt_detached( mbuf_buf(mb) + NOISE_AUTHTAG_LEN /* cyphertext pointer */
                                               , mbuf_buf(mb) /* MAC */
                                               , NULL /* maclen_p */
                                               , mbuf_buf(mb) + NOISE_AUTHTAG_LEN /* message pointer */
                                               , mlen /* message length */
                                               , NULL /* additional data */
                                               , 0 /* additional data length */
                                               , NULL /* NSEC */
                                               , nonce /* nonce */
                                               , key->key /* key */
                                               );

  noise_session_tmr_control(ns, NOISE_TIMER_ON_POLY_TXRX);
  noise_session_tmr_control(ns, NOISE_TIMER_ON_DATA_TX); /* make sure this is not keep alive */

  if ( ns->keypair_now->sending.is_valid
    && ( ns->keypair_now->sending.counter.counter > REKEY_AFTER_MESSAGES
      || ( ns->keypair_now->its_my_plane
        && ns->keypair_now->sending.birthdate + REKEY_AFTER_TIME < tmr_jiffies() )))
  {
    noise_session_event_run(ns, NOISE_SESSION_EVENT_REKEY);
    noise_session_hs_step1_pilot(ns, false, lsock_fromle(&ns->keypair_now->lsock_le));
  }

  mbuf_set_pos(mb, mb_pos);

  lsock_forward(&ns->keypair_now->lsock_le, SOCK_TYPE_DATA_MB, mb);

  ns->tx_bytes += mlen;
  ns->keypair_now->tx_bytes += mlen;

  ns->tx_last = tmr_jiffies();

  return 0;
}

int noise_session_send( struct noise_session *ns
                      , struct mbuf *mb )
{
  return _noise_session_send(ns, mb, 4);
}

/* session timers */

static void noise_session_tmr_zero(void *arg)
{
  struct noise_session *ns = arg;
  noise_debug("TMR noise_session_tmr_zero\n");

  noise_session_event_run(ns, NOISE_SESSION_EVENT_ZERO);

  _handshake_zero(&ns->handshake);

  ns->keypair_now = mem_deref( ns->keypair_now );
  ns->keypair_then = mem_deref( ns->keypair_then );
  ns->keypair_next = mem_deref( ns->keypair_next );

  /* noise implementation is now safe enough to decref after tmr_zero */
  ns = mem_deref( ns );

}

static void noise_session_tmr_hs_new(void *arg)
{
  struct noise_session *ns = arg;
  noise_debug("TMR noise_session_tmr_hs_new\n");
  noise_session_event_run(ns, NOISE_SESSION_EVENT_HSHAKE);

  noise_session_hs_step1_pilot( ns
                              , false
                              , ns->keypair_now ? 
                                  lsock_fromle(&ns->keypair_now->lsock_le) : NULL
                              );

}

static void noise_session_tmr_hs_rexmit(void *arg)
{
  struct noise_session *ns = arg;
  noise_debug("TMR noise_session_tmr_hs_rexmit\n");
  noise_session_event_run(ns, NOISE_SESSION_EVENT_HSXMIT);

  if (ns->tmr_hs_attempts > MAX_TIMER_HANDSHAKES) {
    /* give up... */
    tmr_cancel(&ns->tmr_keepalive);

    if (!tmr_isrunning(&ns->tmr_zero)) {
      tmr_start( &ns->tmr_zero
               , (REJECT_AFTER_TIME * 3)
               , noise_session_tmr_zero
               , ns);
    }
  } else {
    ++ns->tmr_hs_attempts;
    noise_session_hs_step1_pilot( ns
                                , true
                                , ns->keypair_now ? 
                                    lsock_fromle(&ns->keypair_now->lsock_le) : NULL
                                );
  }
}

static void noise_session_tmr_keepalive(void *arg)
{
  struct noise_session *ns = arg;
  noise_debug("TMR noise_session_tmr_keepalive\n");

  noise_session_keepalive_send(ns);

}

static void noise_session_tmr_persist(void *arg)
{
  struct noise_session *ns = arg;
  noise_debug("TMR noise_session_tmr_persist\n");
  if (ns->persistent_keepalive_interval)
    error("SEND KEEP ALIVE\n");
}

static void noise_session_tmr_control( struct noise_session *ns
                                     , enum NOISE_TIMER_ON tkind )
{
  if (!ns)
    return;

  noise_info("noise_session_tmr_control [%d]\n", tkind);
  switch (tkind) {
    case NOISE_TIMER_ON_EKEY:
      tmr_start( &ns->tmr_zero
               , (REJECT_AFTER_TIME * 3)
               , noise_session_tmr_zero
               , ns);
      break;
    case NOISE_TIMER_ON_DATA_TX:
      tmr_cancel(&ns->tmr_keepalive);
      if (!tmr_isrunning(&ns->tmr_hs_new)) {
        tmr_start( &ns->tmr_hs_new
                 , KEEPALIVE_TIMEOUT + REKEY_TIMEOUT
                 , noise_session_tmr_hs_new
                 , ns);
      }
      break;
    case NOISE_TIMER_ON_DATA_RX:
      if (!tmr_isrunning(&ns->tmr_keepalive)) {
        tmr_start( &ns->tmr_keepalive
                 , KEEPALIVE_TIMEOUT
                 , noise_session_tmr_keepalive
                 , ns);
      } else {
        ns->tmr_setup_next_keepalive = true;
      }
      break;
    case NOISE_TIMER_ON_POLY_RX:
      tmr_cancel(&ns->tmr_hs_new);
      break;
    case NOISE_TIMER_ON_POLY_TXRX:
      if (ns->persistent_keepalive_interval) {
        tmr_start( &ns->tmr_persist
                 , ns->persistent_keepalive_interval
                 , noise_session_tmr_persist
                 , ns);
      }
      break;
    case NOISE_TIMER_ON_HAND_INIT:
      tmr_cancel(&ns->tmr_keepalive);
      tmr_start( &ns->tmr_hs_rexmit
               , REKEY_TIMEOUT + randombytes_uniform(REKEY_TIMEOUT_JITTER_MAX)
               , noise_session_tmr_hs_rexmit
               , ns);
      break;
    case NOISE_TIMER_ON_HAND_DONE:
      tmr_cancel(&ns->tmr_hs_rexmit);
      ns->tmr_hs_attempts = 0;
      break;
    default:
      error("noise_session_tmr_control: UNKNOWN value;\n");
  }
}

int noise_session_keepalive_send(struct noise_session *ns)
{
  int err = 0;
  struct mbuf *mb;

  if (!ns)
    return EINVAL;

  ns->keepalive_nonce = (uint16_t)randombytes_uniform(0xFFFF);

  mb = mbuf_alloc(EVER_OUTWARD_MBE_POS);
  if (!mb) {
    err = ENOMEM;
    goto out;
  }

  mb->pos = EVER_OUTWARD_MBE_POS;
  mb->end = EVER_OUTWARD_MBE_POS;

  mbuf_advance(mb, -2);
  mbuf_write_u16(mb, arch_htobe16(ns->keepalive_nonce));
  mbuf_advance(mb, -2);

  ns->keepalive_send = tmr_jiffies();
  _noise_session_send(ns, mb, 5);

  mb = mem_deref( mb );

out:
  if (ns->tmr_setup_next_keepalive) {
    ns->tmr_setup_next_keepalive = false;
    tmr_start( &ns->tmr_keepalive
             , KEEPALIVE_TIMEOUT
             , noise_session_tmr_keepalive
             , ns);
  }

  return err;
}

static int _noise_session_keepalive_recv( struct noise_session *ns
                                        , struct mbuf *mb)
{
  uint16_t nonce;

  if (!ns)
    return EINVAL;

  nonce = arch_betoh16(mbuf_read_u16(mb));

  if (nonce != ns->keepalive_nonce)
    return EBADMSG;

  ns->keepalive_recv = tmr_jiffies();
  ns->keepalive_diff = ns->keepalive_recv - ns->keepalive_send;

  return 0;
}

static void noise_session_destructor(void *data)
{
  struct noise_session *ns = data;

  noise_session_event_run(ns, NOISE_SESSION_EVENT_CLOSE);

  _handshake_zero(&ns->handshake);

  hash_unlink(&ns->lookup.le);
  list_unlink(&ns->le_all);

  /* free keys */
  ns->keypair_now = mem_deref( ns->keypair_now );
  ns->keypair_then = mem_deref( ns->keypair_then );
  ns->keypair_next = mem_deref( ns->keypair_next );

  tmr_cancel(&ns->tmr_hs_new);
  tmr_cancel(&ns->tmr_hs_rexmit);
  tmr_cancel(&ns->tmr_keepalive);
  tmr_cancel(&ns->tmr_zero);
  tmr_cancel(&ns->tmr_persist);

}

int noise_session_publickey_copy( struct noise_session *ns
                                , uint8_t public_key[NOISE_PUBLIC_KEY_LEN] )
{
  if (!ns || !public_key)
    return EINVAL;
  memcpy(public_key, ns->handshake.remote_static, NOISE_PUBLIC_KEY_LEN);
  return 0;
}

int noise_session_new( struct noise_session **sessionp
                     , struct noise_engine *ne
                     , uintptr_t channel_lock
                     , const uint8_t public_key[NOISE_PUBLIC_KEY_LEN]
                     , const uint8_t preshared_key[NOISE_SYMMETRIC_KEY_LEN] )
{
  int err = 0;
  struct noise_session *session;
  struct noise_session_handshake *s_hs;

  if (!ne)
    return EINVAL;

  /* check to make sure that key does not already exist */
  session = noise_engine_find_session_bykey(ne, channel_lock, public_key);
  if (session) {
    *sessionp = session;
    noise_debug( "[NOISE:ALREADY] %W [CH:%p][%s]\n"
               , session->handshake.remote_static, NOISE_PUBLIC_KEY_LEN
               , session->channel_lock
               , noise_session_event_tostr(session->event_last)
               );
    return EALREADY;
  }

  /* check to make sure it is not self! */
  if (!memcmp(ne->si.public, public_key, NOISE_PUBLIC_KEY_LEN))
    return EINVAL;

  session = mem_zalloc(sizeof(*session), noise_session_destructor);
  if (!session)
    return ENOMEM;

  s_hs = &session->handshake;

  session->ne = ne;

  session->channel_lock = channel_lock;

  session->lookup.kind = NOISE_LOOKUP_KIND_SESSION;

  /* setup handshake information */

  sodium_memzero(s_hs, sizeof(*s_hs));
  memcpy(s_hs->remote_static, public_key, NOISE_PUBLIC_KEY_LEN);
  if (preshared_key) {
    memcpy(s_hs->preshared_key, preshared_key, NOISE_SYMMETRIC_KEY_LEN);
  } else {
    sodium_memzero(s_hs->preshared_key, NOISE_SYMMETRIC_KEY_LEN);
  }
  
  s_hs->static_identity = &ne->si;
  s_hs->state = HANDSHAKE_ZEROED;

  if (s_hs->static_identity->has_identity) {
    crypto_scalarmult_curve25519( s_hs->precomputed_static_static /* q */
                                , s_hs->static_identity->private /* n */
                                , s_hs->remote_static /* p */ );
  } else {
    sodium_memzero(s_hs->precomputed_static_static, NOISE_PUBLIC_KEY_LEN);
  }

  list_append( &ne->sessions_all, &session->le_all, session);

  /* init timers */
  tmr_init(&session->tmr_hs_new);
  tmr_init(&session->tmr_hs_rexmit);
  tmr_init(&session->tmr_keepalive);
  tmr_init(&session->tmr_zero);
  tmr_init(&session->tmr_persist);

  if (sessionp)
    *sessionp = session;

  return err;
}

static int noise_engine_data_rx( struct noise_engine *ne
                               , struct noise_session **nsp
                               , uintptr_t channel_lock
                               , struct mbuf *mb
                               , struct lsock *lsock)
{
  uint8_t nonce[NOISE_NONCE_LEN] = {0};
  uint64_t *nonce_64 = (uint64_t *)(void *)&nonce[NOISE_NONCE_LEN - sizeof(uint64_t)];
  struct noise_session *ns = NULL;
  struct noise_keypair *kp = NULL;
  struct noise_symmetric_key *key = NULL;
  
  uint32_t in_receiver_index;

  noise_info("noise_engine_data_rx\n");

  if (!ne || !ne->si.has_identity || !mb)
    return EINVAL;

  if (mbuf_get_left(mb) < 12)
    return EBADMSG;

  in_receiver_index = arch_letoh32( mbuf_read_u32(mb) );
  *nonce_64 = mbuf_read_u64(mb);

  /* get keypair */
  kp = noise_engine_lookup_keypair_byid(ne, in_receiver_index);
  if (!kp)
    return EBADMSG;

  ns = kp->ns;
  key = &kp->receiving;

  if (ns->channel_lock != channel_lock) {
    error("[NOISE] CHANNEL CROSS?!\n");
    return EBADMSG;
  }

  noise_info("noise_engine_data_rx: check counters\n");
  
  /* check counters */

  if ( !key->is_valid
    || (key->birthdate + REJECT_AFTER_TIME) <= tmr_jiffies()
    || key->counter.receive.counter >= REJECT_AFTER_MESSAGES ) {
    key->is_valid = false;
    return EINVAL;
  }

  /* decrypt */
  if (crypto_aead_chacha20poly1305_decrypt_detached( mbuf_buf(mb) + NOISE_AUTHTAG_LEN /* out message */
                                                   , NULL /* NSEC */
                                                   , mbuf_buf(mb) + NOISE_AUTHTAG_LEN /* in cyphertext */
                                                   , mbuf_get_left(mb) - NOISE_AUTHTAG_LEN /* in cyphertext length */
                                                   , mbuf_buf(mb) /* in mac pointer */
                                                   , NULL /* additional data */
                                                   , 0 /* additional data length */
                                                   , nonce /* nonce */
                                                   , key->key /* key */
                                                   ) != 0)
  {
    error("crypto_aead_chacha20poly1305_decrypt_detached\n");
    return EBADMSG;
  }

  mbuf_advance(mb, NOISE_AUTHTAG_LEN);

  /* update counters / timers */
  if (rfc6479_counter_ok( &kp->receiving.counter
                        , arch_letoh64( *nonce_64 )))
    return EBADMSG;

  if (kp == ns->keypair_next) {
    /* remove then */
    ns->keypair_then = mem_deref( ns->keypair_then );
    ns->keypair_then = ns->keypair_now;
    /* move next to now */
    ns->keypair_now = ns->keypair_next;
    /* clear next slot */
    ns->keypair_next = NULL;

    noise_session_event_run(ns, NOISE_SESSION_EVENT_BEGIN_COPILOT);

  }

  /* change sock if need be */
  lsock_install(lsock, &ns->keypair_now->lsock_le, ns);

  if ( ns->keypair_now->sending.is_valid
    && ns->keypair_now->its_my_plane
    && ((ns->keypair_now->sending.birthdate + REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT) <= tmr_jiffies()) )
  {
    noise_session_event_run(ns, NOISE_SESSION_EVENT_REKEY);
    /* stale connection, rekey! */
    ns->sent_lastminute_handshake = true;
    /* need to queue in tmr? */
    noise_session_hs_step1_pilot( ns
                                , false
                                , ns->keypair_now ? 
                                    lsock_fromle(&ns->keypair_now->lsock_le) : NULL
                                );
  }

  noise_session_tmr_control(ns, NOISE_TIMER_ON_DATA_RX);

  noise_session_tmr_control(ns, NOISE_TIMER_ON_POLY_RX);
  noise_session_tmr_control(ns, NOISE_TIMER_ON_POLY_TXRX);

  ns->rx_bytes += mbuf_get_left(mb);
  kp->rx_bytes += mbuf_get_left(mb);

  ns->rx_last = tmr_jiffies();

  *nsp = ns;

  return 0;
}

int noise_session_handle_register( struct noise_session *ns
                                 , enum NOISE_SESSION_HANDLE type
                                 , struct csock *csock )
{
  switch (type) {
    default:
      return EINVAL;
      break;
  }
  return 0;
}

int noise_engine_session_handle_register( struct noise_engine *ne
                                        , enum NOISE_SESSION_HANDLE type
                                        , struct csock *csock )
{
  switch (type) {
    default:
      return EINVAL;
      break;
  }
  return 0;
}


enum NOISE_ENGINE_RECIEVE
noise_engine_recieve( struct noise_engine *ne
                    , struct noise_session **nsp
                    , uintptr_t channel_lock
                    , struct mbuf *mb
                    , struct lsock *lsock )
{
  enum NOISE_ENGINE_RECIEVE err = NOISE_ENGINE_RECIEVE_OK;
  uint32_t type;
  struct mbuf *mb_reply = NULL;
  struct noise_session *ns = NULL;

  bool keepalive_pingpong = false;

  if (!ne || !mb)
    return NOISE_ENGINE_RECIEVE_EINVAL;

  type = arch_letoh32( mbuf_read_u32(mb) );

  /*
   * numbers are only 8 bits;
   * we use u32 to check that the correct endian was used
   */
  if (type > 6)
    return NOISE_ENGINE_RECIEVE_EBADMSG;

  noise_debug( "noise_engine_recieve <%p> [%u][%u][%W]\n"
             , ne, type, mbuf_get_left(mb), mbuf_buf(mb), mbuf_get_left(mb));

  switch (type) {
    case 1:
      ns = noise_session_hs_step2_copilot(ne, channel_lock, mb, &err);
      if (!ns) {
        handshake_debug("noise_engine_recieve(s2): DROP invalid handshake\n");
        if (!err)
          err = NOISE_ENGINE_RECIEVE_EBADMSG;
        goto out;
      }

      ns->last_sent_handshake = tmr_jiffies();

      if (noise_session_hs_step3_copilot(&mb_reply, ns)) {
        /*cookie_add_mac_to_packet(&packet, sizeof(packet), peer);*/
        if (noise_session_hs_step5_begin(ns)) {
          noise_session_tmr_control(ns, NOISE_TIMER_ON_EKEY);
          noise_session_tmr_control(ns, NOISE_TIMER_ON_POLY_TXRX);
          /* RAW SEND */
          lsock_install(lsock, &ns->keypair_next->lsock_le, ns);
          lsock_forward(&ns->keypair_next->lsock_le, SOCK_TYPE_DATA_MB, mb_reply);
        } else {
          handshake_error("noise_session_hs_begin\n");
        }
      } else {
        handshake_error("noise_session_hs_reply\n");
      }
      goto out;
    case 2:
      ns = noise_session_hs_step4_pilot(ne, mb, &err);
      if (!ns) {
        handshake_debug("noise_engine_recieve(s4): DROP invalid handshake\n");
        if (!err)
          err = NOISE_ENGINE_RECIEVE_EBADMSG;
        goto out;
      }

      if (noise_session_hs_step5_begin(ns)) {
        lsock_install(lsock, &ns->keypair_now->lsock_le, ns);
        noise_session_tmr_control(ns, NOISE_TIMER_ON_EKEY);
        noise_session_event_run(ns, NOISE_SESSION_EVENT_BEGIN_PILOT);
      } else {
        handshake_error("noise_session_hs_begin\n");
      }

      goto out;
    case 5: /* keepalive ping */
      /* @FALLTHROUGH@ */
    case 6: /* keepalive ping */
      keepalive_pingpong = true;
      /* @FALLTHROUGH@ */
    case 4: /* data */
      /*error("noise_engine_data_rx BEFORE: [%W]\n", mbuf_buf(mb), mbuf_get_left(mb));*/
      if (noise_engine_data_rx(ne, &ns, channel_lock, mb, lsock)) {
        err = NOISE_ENGINE_RECIEVE_IGNORE;
        noise_error( "[NOISE] noise_engine_data_rx ignore\n");
      } else {
        err = NOISE_ENGINE_RECIEVE_DECRYPTED;
      }
      /*error("noise_engine_data_rx AFTER : [%W]\n", mbuf_buf(mb), mbuf_get_left(mb));*/

      if (keepalive_pingpong && err == NOISE_ENGINE_RECIEVE_DECRYPTED) {
        if (type == 5) {/* send pong! */
          _noise_session_send(ns, mb, 6);
        } else { /* recv pong */
          _noise_session_keepalive_recv(ns, mb);
        }
      }
      goto out;
    default:
      warning("UNKNOWN TYPE <%u>\n", type);
      err = NOISE_ENGINE_RECIEVE_EBADMSG;
      goto out;
  }
out:
  *nsp = ns;
  mb_reply = mem_deref(mb_reply);
  return err;
}

int noise_engine_publickey_copy( struct noise_engine *ne
                               , uint8_t public_key[NOISE_PUBLIC_KEY_LEN] )
{
  if (!ne || !public_key)
    return EINVAL;

  if (!ne->si.has_identity)
    return EINVAL;

  memcpy(public_key, ne->si.public, NOISE_PUBLIC_KEY_LEN);

  return 0;
}

struct noise_session *
noise_engine_find_session_bykey( struct noise_engine *ne
                               , uintptr_t channel_lock
                               , const uint8_t key[NOISE_PUBLIC_KEY_LEN])
{
  struct le *le;
  struct noise_session *ns;
  LIST_FOREACH(&ne->sessions_all, le) {
    ns = le->data;
    if ( ns->channel_lock == channel_lock
      && !memcmp(ns->handshake.remote_static, key, 32))
      return ns;
  }
  return NULL;
}

static bool noise_engine_lookup_byid_helper(struct le *le, void *arg)
{
    struct noise_idlookup *look = le->data;
    uint32_t *key = arg;
    return look->id == *key;
}

struct noise_idlookup *
noise_engine_lookup_byid( struct noise_engine *ne
                        , uint8_t kind
                        , uint32_t key)
{
  struct noise_idlookup *look;
  look = list_ledata(hash_lookup( ne->idlookup
                                , key
                                , noise_engine_lookup_byid_helper
                                , &key));
  if (!look || look->kind != kind)
    return NULL;
  return look;
}

static void noise_keypair_destructor(void *data)
{
  struct noise_keypair *kp = data;
  hash_unlink(&kp->lookup.le);
  list_unlink(&kp->lsock_le);

  /* this must be last */
  sodium_memzero(kp, sizeof(*kp));
}

static int noise_keypair_create( struct noise_keypair **keypairp
                               , struct noise_session *ns )
{
  struct noise_keypair *keypair;

  if (!keypairp || !ns)
    return EINVAL;
  
  keypair = mem_zalloc(sizeof(*keypair), noise_keypair_destructor);
  if (!keypair)
    return ENOMEM;

  keypair->ns = ns;
  keypair->lookup.kind = NOISE_LOOKUP_KIND_KEYPAIR;

  *keypairp = keypair;

  return 0;
}

static void noise_engine_destructor(void *data)
{
  struct noise_engine *ne = data;
  list_flush(&ne->sessions_all);
  hash_flush(ne->idlookup);
  ne->idlookup = mem_deref(ne->idlookup);
}

int noise_engine_init( struct noise_engine **nenginep
                     , struct magi_eventdriver *ed )
{
  int err = 0;
  blake2s_ctx ctx;
  struct noise_engine *ne;

  if (!nenginep)
    return EINVAL;

  ne = mem_zalloc(sizeof(*ne), noise_engine_destructor);
  if (!ne)
    return ENOMEM;

  ne->ed = ed;
  
  blake2s( ne->hshake_chaining_key
         , NOISE_HASH_LEN
         , NULL
         , 0
         , g_hshake
         , sizeof(g_hshake));

  blake2s_init(&ctx, NOISE_HASH_LEN, NULL, 0);
  blake2s_update(&ctx, ne->hshake_chaining_key, NOISE_HASH_LEN);
  blake2s_update(&ctx, g_ident, sizeof(g_ident));
  blake2s_update(&ctx, g_identkey, sizeof(g_identkey));
  blake2s_final(&ctx, ne->hshake_hash);

  list_init(&ne->sessions_all);

  err = hash_alloc(&ne->idlookup, 8);
  if (err)
    goto out;

  ne->sessions_counter = 1; /* start at one */

out:
  if (!err) {
    *nenginep = ne;

#if defined(HAVE_GENDO)
  GENDO_INIT;
#endif

  } else {
    mem_deref(ne);
  }

  return err;
}


/**/

int noise_engine_test_counter(void)
{
  union rfc6479_counter counter;

  counter.counter = 0;

  sodium_memzero( counter.receive.backtrack
                , sizeof(counter.receive.backtrack) );

  noise_info( "%u [%W]\n", counter.counter, counter.receive.backtrack, 256);

  for (int i = 0; i < 1000; ++i)
  {
    if (rfc6479_counter_ok( &counter, i)) {
      return EINVAL;
    }
  }

  for (int i = 0; i < 1000; ++i)
  {
    if (!rfc6479_counter_ok( &counter, i)) {
      return EINVAL;
    }
  }

  return 0;
}
