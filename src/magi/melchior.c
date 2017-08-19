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

struct magi_melchior {
  struct hash *tickets;
  struct noise_engine *ne;
  struct magi *ctx;
};

struct magi_melchior_ticket {
  struct le le;
  struct tmr tmr;

  struct magi_melchior *ctx;

  uint8_t everip_addr[EVERIP_ADDRESS_LENGTH];
  uint32_t ticket_id;

  struct odict *od_sent;
  struct odict *od_recv;

  magi_melchior_h *callback;
  void *userdata;

};

static int magi_melchior_ticket_serialize( struct magi_melchior_ticket *mmt
                                         , struct mbuf *mb )
{
  int err = 0;
  size_t mb_pos;
  uint8_t public_sign_key[32];

  if (!mmt || !mb)
    return EINVAL;

  mb_pos = mb->pos;

  err = mbuf_printf(mb, "%H", bencode_encode_odict, mmt->od_sent);
  if (err)
    goto out;

  mbuf_set_pos(mb, mb_pos);

  /* sign */

  cryptosign_pk_fromskpk(public_sign_key, mmt->ctx->ne->sign_keys);

  /* header = 112U */
  /*[SIGNATURE 64U][PUBLIC_KEY 32U][TAI64N 12U][OPTIONS 4U]*/
  mbuf_advance(mb, -112);
  mb_pos = mb->pos;

  /* wait for sig later */
  mbuf_advance(mb, CRYPTOSIGN_SIGNATURE_LENGTH/* 64U */);

  /* write public key */
  mbuf_write_mem(mb, public_sign_key, 32);
  
  /* {t} */
  tai64n_now( mbuf_buf(mb) );
  mbuf_advance(mb, TAI64_N_LEN);

  /* options -- keep blank for now */
  mbuf_write_u32(mb, 0); 

  /* go back to top */
  mbuf_set_pos(mb, mb_pos);

  /* sign out */
  cryptosign_bytes(mmt->ctx->ne->sign_keys, mbuf_buf(mb), mbuf_get_left(mb));

out:
  return err;
}

static void magi_melchior_ticket_timeout(void *data)
{
  struct magi_melchior_ticket *mmt = data;

  mmt->callback( MAGI_MELCHIOR_RETURN_STATUS_TIMEDOUT
               , mmt->od_sent
               , NULL
               , mmt->everip_addr
               , 0
               , mmt->userdata );

  mem_deref(mmt);
}

static void magi_melchior_ticket_destructor(void *data)
{
  struct magi_melchior_ticket *mmt = data;

  list_unlink(&mmt->le);

  mmt->od_sent = mem_deref( mmt->od_sent );
  mmt->od_recv = mem_deref( mmt->od_recv );

  tmr_cancel(&mmt->tmr);
}

int magi_melchior_send( struct magi_melchior *mm
                      , struct odict *od
                      , struct pl *method
                      , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH]
                      , uint64_t timeout
                      , bool is_routable
                      , magi_melchior_h *callback
                      , void *userdata )
{
  int err = 0;
  struct mbuf *mb = NULL;
  struct magi_node *mnode = NULL;
  struct magi_melchior_ticket *mmt = NULL;

  if (!mm || !od || !method || !everip_addr || !callback)
    return EINVAL;

  mmt = mem_zalloc(sizeof(*mmt), magi_melchior_ticket_destructor);
  if (!mmt)
    return ENOMEM;

  mmt->ctx = mm;

  memcpy(mmt->everip_addr, everip_addr, EVERIP_ADDRESS_LENGTH);

  tmr_start(&mmt->tmr, timeout, magi_melchior_ticket_timeout, mmt);

  mmt->od_sent = mem_ref(od);

  mmt->callback = callback;
  mmt->userdata = userdata;

  /* assign ticket id */
  mmt->ticket_id = randombytes_uniform(UINT32_MAX);

  hash_append( mm->tickets
             , mmt->ticket_id
             , &mmt->le
             , mmt );

  odict_entry_add(mmt->od_sent, "_p", ODICT_INT, (int64_t)EVERIP_VERSION_PROTOCOL);
  odict_entry_add(mmt->od_sent, "_m", ODICT_STRING, method);
  odict_entry_add(mmt->od_sent, "_i", ODICT_INT, mmt->ticket_id);
  odict_entry_add(mmt->od_sent, "_t", ODICT_STRING, &(struct pl){.p=(const char *)everip_addr,.l=EVERIP_ADDRESS_LENGTH});
  
  /* sign and serialize */

  mb = mbuf_outward_alloc(0);
  if (!mb)
    goto out;

  err = magi_melchior_ticket_serialize(mmt, mb);
  if (err)
    goto out;

  /* send to subsystem */
  debug("magi_melchior_send: [%u][%W]\n", mbuf_get_left(mb), mbuf_buf(mb), mbuf_get_left(mb));

  if (is_routable) {
    error("magi_melchior_send: routable messages are not available;\n");
  } else {
    mnode = magi_node_lookup_by_eipaddr( mm->ctx, everip_addr );
    if (!mnode) {
      error("magi_melchior_send: hmm, no magi record!\n");
      goto out;
    }

    /* port zero is for melchior */
    magi_node_ledbat_send(mnode, mb, MAGI_LEDBAT_PORT_MELCHIOR);

  }

out:
  mb = mem_deref(mb);
  if (err)
    mmt = mem_deref( mmt );
  return err;
}

int magi_melchior_recv( struct magi_melchior *mm, struct mbuf *mb)
{

  size_t pos;
  struct odict *od;

  uint8_t signature[CRYPTOSIGN_SIGNATURE_LENGTH];
  uint8_t public_key[32];
  uint8_t tai64n[TAI64_N_LEN];
  uint8_t options[4];

  if (mbuf_get_left(mb) < 112)
    return ENODATA;

  pos = mb->pos;

  mbuf_read_mem(mb, signature, CRYPTOSIGN_SIGNATURE_LENGTH);
  mbuf_read_mem(mb, public_key, 32);
  mbuf_read_mem(mb, tai64n, TAI64_N_LEN);
  mbuf_read_mem(mb, options, 4);

  mbuf_set_pos(mb, pos + CRYPTOSIGN_SIGNATURE_LENGTH);

  /* check signature */
  if (cryptosign_bytes_verify( public_key
                             , signature
                             , mbuf_buf(mb)
                             , mbuf_get_left(mb) )) {
    return EBADMSG;
  }

  mbuf_set_pos(mb, pos + 112);

  if (bencode_decode_odict(&od, 8, mbuf_buf(mb), mbuf_get_left(mb), 3))
    return EBADMSG;

  error("ODICT: %H\n", odict_debug, od);

  od = mem_deref(od);

  return 0;
}

static void magi_melchior_destructor(void *data)
{
  struct magi_melchior *mm = data;
  hash_flush(mm->tickets);
  mm->tickets = mem_deref( mm->tickets );
}

int magi_melchior_alloc( struct magi_melchior **mmp
                       , struct magi *magi
                       , struct noise_engine *ne )
{
  int err = 0;
  struct magi_melchior *mm;

  if (!mmp || !magi || !ne)
    return EINVAL;

  mm = mem_zalloc(sizeof(*mm), magi_melchior_destructor);
  if (!mm)
    return ENOMEM;

  mm->ctx = magi;
  mm->ne = ne;

  hash_alloc(&mm->tickets, 16);

  *mmp = mm;

  return err;
}
