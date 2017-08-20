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

  struct hash *handlers;
};

struct magi_melchior_handler {
  struct le le;
  uint8_t prefix[4];

  magi_melchior_rpc_h *callback;
  void *userdata;
};

struct magi_melchior_ticket {
  struct le le;
  struct tmr tmr;

  struct magi_melchior *ctx;

  uint8_t everip_addr[EVERIP_ADDRESS_LENGTH];
  uint32_t ticket_id;

  uint64_t sent_jiffies;

  struct odict *od_sent;

  magi_melchior_h *callback;
  void *userdata;

};

static bool _magi_melchior_handle_lookup(struct le *le, void *arg)
{
  struct magi_melchior_handler *mmh = le->data;
  /*error("_magi_melchior_handle_lookup: %b %u %u\n", mmh->prefix, 4, *(uint32_t *)(void *)mmh->prefix, *(uint32_t *)arg);*/
  return *(uint32_t *)(void *)mmh->prefix == *(uint32_t *)arg;
}

static int magi_melchior_ticket_serialize( struct magi_melchior *mm
                                         , struct odict *od
                                         , struct mbuf *mb )
{
  int err = 0;
  size_t mb_pos;
  uint8_t public_sign_key[32];

  if (!mm || !od || !mb)
    return EINVAL;

  mb_pos = mb->pos;

  err = mbuf_printf(mb, "%H", bencode_encode_odict, od);
  if (err)
    goto out;

  mbuf_set_pos(mb, mb_pos);

  /* sign */

  cryptosign_pk_fromskpk(public_sign_key, mm->ne->sign_keys);

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
  cryptosign_bytes(mm->ne->sign_keys, mbuf_buf(mb), mbuf_get_left(mb));

out:
  return err;
}

static void magi_melchior_ticket_timeout(void *data)
{
  struct magi_melchior_ticket *mmt = data;

  if (mmt->callback)
    mmt->callback( MAGI_MELCHIOR_RETURN_STATUS_TIMEDOUT
                 , mmt->od_sent
                 , NULL
                 , mmt->everip_addr
                 , 0
                 , mmt->userdata );

  mem_deref(mmt);
}

/* serialize, sign and send */
static int magi_melchior_sss( struct magi_melchior *mm
                            , struct odict *od
                            , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH]
                            , bool is_routable )
{
  int err = 0;
  struct mbuf *mb = NULL;
  struct magi_node *mnode = NULL;

  if (!mm || !od || !everip_addr)
    return EINVAL;

  mb = mbuf_outward_alloc(0);
  if (!mb) {
    err = ENOMEM;
    goto out;
  }

  err = magi_melchior_ticket_serialize(mm, od, mb);
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

  mb = mem_deref(mb);

out:
  return err;
}

static bool _magi_melchior_ticket_lookup(struct le *le, void *arg)
{
  struct magi_melchior_ticket *mmt = le->data;
  return mmt->ticket_id == *(uint32_t *)arg;
}

static void magi_melchior_ticket_destructor(void *data)
{
  struct magi_melchior_ticket *mmt = data;

  list_unlink(&mmt->le);

  mmt->od_sent = mem_deref( mmt->od_sent );

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
  struct magi_melchior_ticket *mmt = NULL;

  if (!mm || !od || !method || !everip_addr)
    return EINVAL;

  mmt = mem_zalloc(sizeof(*mmt), magi_melchior_ticket_destructor);
  if (!mmt)
    return ENOMEM;

  mmt->ctx = mm;

  memcpy(mmt->everip_addr, everip_addr, EVERIP_ADDRESS_LENGTH);

  tmr_start(&mmt->tmr, timeout, magi_melchior_ticket_timeout, mmt);

  mmt->od_sent = mem_ref(od);

  if (callback) {
    mmt->callback = callback;
    mmt->userdata = userdata;    
  }

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
  
  mmt->sent_jiffies = tmr_jiffies();

  /* serialize, sign and send */
  err = magi_melchior_sss(mm, mmt->od_sent, everip_addr, is_routable);
  if (err)
    goto out;

out:
  if (err)
    mmt = mem_deref( mmt );
  return err;
}

static int magi_melchior_command_hello( struct magi_melchior_rpc *rpc
                                      , void *arg )
{

  /*error("\n\nmagi_melchior_command_hello <%p><%p><%W>\n\n", rpc->in, rpc->out, rpc->everip_addr, EVERIP_ADDRESS_LENGTH);*/

  return 0;
}

static int magi_melchior_command_res_or_err( struct magi_melchior_rpc *rpc
                                           , enum MAGI_MELCHIOR_RETURN_STATUS status
                                           , void *arg )
{
  int err = 0;
  const struct odict_entry *ode;
  struct magi_melchior *mm = arg;
  struct magi_melchior_ticket *mmt;

  uint32_t ticket_id;

  /* no reply */
  rpc->out = NULL;

  /*error("\n\n magi_melchior_command_res <%p><%p><%W>\n\n", rpc->in, rpc->out, rpc->everip_addr, EVERIP_ADDRESS_LENGTH);*/

  /* pull-out ticket id */
  ode = odict_lookup(rpc->in, "_i");
  if (!ode || ode->type != ODICT_INT) {
    err = EINVAL;
    goto out;
  }

  ticket_id = (uint32_t)ode->u.integer;

  /* lookup ticket id */
  mmt = list_ledata(hash_lookup( mm->tickets
                              , ticket_id
                              , _magi_melchior_ticket_lookup
                              , (void *)&ticket_id));
  if (!mmt) {
    err = EINVAL;
    goto out;
  }
  if (mmt->callback)
    mmt->callback( status
                 , mmt->od_sent
                 , rpc->in
                 , rpc->everip_addr
                 , tmr_jiffies() - mmt->sent_jiffies
                 , mmt->userdata );

  mmt = mem_deref( mmt );

out:
  return err;
}

int magi_melchior_recv( struct magi_melchior *mm, struct mbuf *mb)
{

  size_t pos;
  int err = 0;
  struct odict *od = NULL;
  struct odict *od_ret = NULL;

  uint8_t everip_addr[EVERIP_ADDRESS_LENGTH];
  uint8_t public_key_curve25519[NOISE_PUBLIC_KEY_LEN];

  uint8_t signature[CRYPTOSIGN_SIGNATURE_LENGTH];
  uint8_t public_key_ed25519[32];
  uint8_t tai64n[TAI64_N_LEN];
  uint8_t options[4];

  if (mbuf_get_left(mb) < 112)
    return ENODATA;

  pos = mb->pos;

  mbuf_read_mem(mb, signature, CRYPTOSIGN_SIGNATURE_LENGTH);
  mbuf_read_mem(mb, public_key_ed25519, 32);
  mbuf_read_mem(mb, tai64n, TAI64_N_LEN);
  mbuf_read_mem(mb, options, 4);

  mbuf_set_pos(mb, pos + CRYPTOSIGN_SIGNATURE_LENGTH);

  /* check signature */
  if (cryptosign_bytes_verify( public_key_ed25519
                             , signature
                             , mbuf_buf(mb)
                             , mbuf_get_left(mb) )) {
    return EBADMSG;
  }

  /* calculate everip address */
  if (crypto_sign_ed25519_pk_to_curve25519( public_key_curve25519
                                          , public_key_ed25519 ))
  {
    error("magi_melchior_recv: Invalid Identity\n");
    return EPROTO;
  }

  if (!addr_calc_pubkeyaddr( everip_addr, public_key_curve25519 )) {
    error("magi_melchior_recv: Invalid Identity\n");
    return EPROTO;
  }

  mbuf_set_pos(mb, pos + 112);

  if (bencode_decode_odict( &od
                          , 8
                          , (const char *)mbuf_buf(mb)
                          , mbuf_get_left(mb)
                          , 3 ))
    return EBADMSG;

  /*error("ODICT: %H\n", odict_debug, od);*/

  /* pull-out method */
  {
    int cmd_err = 0;
    int64_t ticket_id;
    struct pl ns_pre, ns_suf;
    const struct odict_entry *ode;
    struct magi_melchior_rpc rpc_obj;
    struct magi_melchior_handler *mmh = NULL;

    memset(&rpc_obj, 0, sizeof(rpc_obj));

    ode = odict_lookup(od, "_m");
    if (!ode || ode->type != ODICT_STRING)
      goto out;

    err = re_regex(ode->u.pl.p, ode->u.pl.l, "[^.]+.[^]*", &ns_pre, &ns_suf);
    if (err)
      goto out;

    ode = odict_lookup(od, "_i");
    if (!ode || ode->type != ODICT_INT)
      goto out;

    ticket_id = ode->u.integer;

    odict_alloc(&od_ret, 8);

    rpc_obj.in = od;
    rpc_obj.out = od_ret;
    rpc_obj.everip_addr = everip_addr;

    if (4 == ns_pre.l && !memcmp(ns_pre.p, "ever", 4)) {
      /* ever command */
      switch (ns_suf.l) {
        case 5:
          /* hello */
          if (!memcmp(ns_suf.p, "hello", 5))
          {
            cmd_err = magi_melchior_command_hello(&rpc_obj, mm);
          }
          break;
        case 3:
          /* res, err */
          if (!memcmp(ns_suf.p, "res", 3))
          {
            cmd_err = magi_melchior_command_res_or_err( &rpc_obj
                                                      , MAGI_MELCHIOR_RETURN_STATUS_OK
                                                      , mm);
          } 
          else if (!memcmp(ns_suf.p, "err", 3))
          {
            cmd_err = magi_melchior_command_res_or_err( &rpc_obj
                                                      , MAGI_MELCHIOR_RETURN_STATUS_ERR
                                                      , mm);
          }
          break;
        default:
          error("magi_melchior_recv: got unknown ever command [%b]\n", ns_suf.p, ns_suf.l);
          goto out;
      }
    } else {
      /*error("magi_melchior_recv: got command [%b.%b]\n", ns_pre.p, ns_pre.l, ns_suf.p, ns_suf.l);*/

      /* only support prefixes of 4 bytes */
      if (ns_pre.l != 4)
        goto out;

      mmh = list_ledata(hash_lookup( mm->handlers
                                   , *(uint32_t *)(void *)ns_pre.p
                                   , _magi_melchior_handle_lookup
                                   , (void *)ns_pre.p));
      if (!mmh) {
        goto out;
      }

      cmd_err = mmh->callback(&rpc_obj, &ns_suf, mmh->userdata);

    }

    if (rpc_obj.out) {
      odict_entry_add(rpc_obj.out, "_p", ODICT_INT, (int64_t)EVERIP_VERSION_PROTOCOL);

      if (cmd_err) {
        odict_entry_add(rpc_obj.out, "_m", ODICT_STRING, &(struct pl)PL("ever.err"));
        odict_entry_add(rpc_obj.out, "_e", ODICT_INT, (int64_t)cmd_err);
      } else {
        odict_entry_add(rpc_obj.out, "_m", ODICT_STRING, &(struct pl)PL("ever.res"));
      }

      odict_entry_add(rpc_obj.out, "_i", ODICT_INT, ticket_id);
      odict_entry_add(rpc_obj.out, "_t", ODICT_STRING, &(struct pl){.p=(const char *)everip_addr,.l=EVERIP_ADDRESS_LENGTH});

      /*error("ODICT RES: %H\n", odict_debug, rpc_obj.out);*/

      magi_melchior_sss(mm, rpc_obj.out, rpc_obj.everip_addr, false);
    }

  }

out:
  od = mem_deref(od);
  od_ret = mem_deref(od_ret);
  return 0;
}

static void magi_melchior_handle_destructor(void *data)
{
  struct magi_melchior_handler *mmh = data;
  list_unlink(&mmh->le);
}

int magi_melchior_register( struct magi_melchior *mm
                          , const uint8_t prefix[4]
                          , magi_melchior_rpc_h *callback
                          , void *userdata )
{
  int err = 0;
  struct magi_melchior_handler *mmh = NULL;

  if (!mm || !prefix || !callback)
    return EINVAL;

  mmh = list_ledata(hash_lookup( mm->handlers
                               , *(uint32_t *)(void *)prefix
                               , _magi_melchior_handle_lookup
                               , (void *)prefix));

  if (mmh)
    return EALREADY;

  mmh = mem_zalloc(sizeof(*mmh), magi_melchior_handle_destructor);
  if (!mmh)
    return ENOMEM;

  *(uint32_t *)(void *)mmh->prefix = *(uint32_t *)(void *)prefix;

  mmh->callback = callback;
  mmh->userdata = userdata;

  hash_append( mm->handlers
             , *(uint32_t *)(void *)prefix
             , &mmh->le
             , mmh );

  return err;
}

static void magi_melchior_destructor(void *data)
{
  struct magi_melchior *mm = data;
  hash_flush(mm->tickets);
  mm->tickets = mem_deref( mm->tickets );

  hash_flush(mm->handlers);
  mm->handlers = mem_deref( mm->handlers );
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
  hash_alloc(&mm->handlers, 8);

  *mmp = mm;

  return err;
}
