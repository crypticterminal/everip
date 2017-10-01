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

enum {
  BUFSIZE_MAX   = 131072,
};

struct magi {
  struct list nodes;
  struct hash *idx_key;
  struct hash *idx_addr;

  struct tmr maintenance;

  struct magi_eventdriver *ed;
};

struct magi_node {
  struct le le;
  struct le le_idx_key;
  struct le le_idx_addr;

  struct magi *ctx;

  uint8_t public_key[NOISE_PUBLIC_KEY_LEN];
  uint8_t everip_addr[EVERIP_ADDRESS_LENGTH];

  enum MAGI_NODE_STATUS status;


  struct odict *hello_pkt;
  uint64_t last_hello;

  struct ledbat_sock *ls;
  struct mbuf *mb;
};


struct magi_ledbat_frame {
  uint8_t options;
  uint16_t port;
  size_t len;
};

int magi_node_ledbat_sock_set( struct magi_node *mnode
                             , struct ledbat_sock *lsock )
{
  if (!mnode)
    return EINVAL;

  /*error("\nmagi_node_ledbat_sock_set <%p><%p>\n", mnode, lsock);*/

  mnode->ls = mem_deref(mnode->ls);

  if (lsock) {
    mnode->ls = lsock;
  } else {
    (void)magi_node_status_update(mnode, MAGI_NODE_STATUS_OFFLINE);
  }

  return 0;
}

struct ledbat_sock *
magi_node_ledbat_sock_get( struct magi_node *mnode )
{
  if (!mnode)
    return NULL;
  return mnode->ls;
}

int magi_node_ledbat_send( struct magi_node *mnode
                         , struct mbuf *mb
                         , uint16_t port )
{
  size_t len;
  ssize_t hsz = 1 /* options */ + 2 /* port */;
  if (!mnode || !mb)
    return EINVAL;

  if (!mnode->ls)
    return ENOTCONN;

  len = mbuf_get_left(mb);

  hsz += (len > 0xffff ? 9 : (len > 125 ? 3 : 1));

  mbuf_advance(mb, -(hsz));

  /* write option -- not used yet */
  mbuf_write_u8(mb, 0);
  /* port */
  mbuf_write_u16(mb, arch_htobe16(port));

  switch (hsz) {
    case 12:
      mbuf_write_u8(mb, 127);
      mbuf_write_u64(mb, arch_htobe64(len));
      break;
    case 6:
      mbuf_write_u8(mb, 126);
      mbuf_write_u16(mb, arch_htobe16(len));
      break;
    case 4:
      mbuf_write_u8(mb, len);
      break;
    default:
      BREAKPOINT;
      return EINVAL;
  }

  mbuf_advance(mb, -(hsz));

  return ledbat_sock_send(mnode->ls, mb);
}

static int magi_node_ledbat_recv_decode( struct magi_ledbat_frame *frame
                                       , struct mbuf *mb )
{
  if (!frame || !mb)
    return EINVAL;

  if (mbuf_get_left(mb) < 3)
    return ENODATA;

  frame->options = mbuf_read_u8(mb);
  frame->port = arch_betoh16(mbuf_read_u16(mb));

  frame->len = mbuf_read_u8(mb);

  if (frame->len == 126) {
    if (mbuf_get_left(mb) < 2)
      return ENODATA;
    frame->len = arch_betoh16(mbuf_read_u16(mb));
  }
  else if (frame->len == 127) {
    if (mbuf_get_left(mb) < 8)
      return ENODATA;
    frame->len = arch_betoh64(mbuf_read_u64(mb));
  }

  if (mbuf_get_left(mb) < frame->len)
    return ENODATA;

  return 0;
}

int magi_node_ledbat_recv( struct magi_node *mnode, struct mbuf *mb )
{
  int err = 0;
  struct mbuf *_mb;

  if (!mnode || !mb)
    return EINVAL;

  if (mnode->mb) {
    const size_t len = mbuf_get_left(mb), pos = mnode->mb->pos;
    if ((mbuf_get_left(mnode->mb) + len) > BUFSIZE_MAX) {
      err = EOVERFLOW;
      goto out;
    }

    mnode->mb->pos = mnode->mb->end;

    err = mbuf_write_mem(mnode->mb, mbuf_buf(mb), len);
    if (err)
      goto out;

    mnode->mb->pos = pos;
  }
  else {
    mnode->mb = mem_ref(mb);
  }

  while (mnode->mb) {
    struct magi_ledbat_frame frame;
    size_t pos, end;

    pos = mnode->mb->pos;

    err = magi_node_ledbat_recv_decode(&frame, mnode->mb);
    if (err) {
      if (err == ENODATA) {
        mnode->mb->pos = pos;
        err = 0;
        break;
      }

      goto out;
    }

    _mb = mnode->mb;

    end      = _mb->end;
    _mb->end = _mb->pos + (size_t)frame.len;

    if (end > _mb->end) {
      struct mbuf *mbn = mbuf_alloc(end - _mb->end);
      if (!mbn) {
        err = ENOMEM;
        goto out;
      }

      (void)mbuf_write_mem(mbn, _mb->buf + _mb->end, end - _mb->end);
      mbn->pos = 0;

      mnode->mb = mbn;
    }
    else {
      mnode->mb = NULL;
    }

    switch (frame.port) {
      case MAGI_LEDBAT_PORT_MELCHIOR:
        magi_melchior_recv(everip_magi_melchior(), _mb);
        break;
      case MAGI_LEDBAT_PORT_TREEOFLIFE:
        treeoflife_ledbat_recv( _mb );
        break;
      default:
        error("magi_node_ledbat_recv: unknown port: %u\n", frame.port);
        break;
    }

    _mb = mem_deref(_mb);
  }

out:
  return err;
}

int magi_node_everipaddr_copy( struct magi_node *mnode
                             , uint8_t everip_addr[EVERIP_ADDRESS_LENGTH] )
{
  if (!mnode || !everip_addr)
    return EINVAL;
  if (mnode->everip_addr[0] != 0xFC)
    return EINVAL;
  memcpy(everip_addr, mnode->everip_addr, EVERIP_ADDRESS_LENGTH);
  return 0;
}

static bool _magi_node_lookup_key(struct le *le, void *arg)
{
  struct magi_node *mnode = le->data;
  return 0 == memcmp(mnode->public_key, (uint8_t *)arg, NOISE_PUBLIC_KEY_LEN);
}

static bool _magi_node_lookup_addr(struct le *le, void *arg)
{
  struct magi_node *mnode = le->data;
  return 0 == memcmp(mnode->everip_addr, (uint8_t *)arg, EVERIP_ADDRESS_LENGTH);
}

static void magi_node_destructor(void *data)
{
  struct magi_node *mnode = data;
  
  (void)magi_node_status_update(mnode, MAGI_NODE_STATUS_REMOVAL);

  list_unlink(&mnode->le);
  list_unlink(&mnode->le_idx_key);
  list_unlink(&mnode->le_idx_addr);

  mnode->mb = mem_deref(mnode->mb);
}

struct magi_node *
magi_node_lookup_by_eipaddr( struct magi *magi
                           , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH] )
{
  struct magi_node *mnode;
  if (!magi || !everip_addr)
    return NULL;

  mnode = list_ledata(hash_lookup( magi->idx_addr
                                 , *(uint32_t *)(void *)everip_addr
                                 , _magi_node_lookup_addr
                                 , (void *)everip_addr));
  return mnode;
}

int magi_node_status_update( struct magi_node *mnode
                           , enum MAGI_NODE_STATUS status )
{
  bool push_event = true;
  struct magi_e2e_event event;

  memset(&event, 0, sizeof(event));

  if (!mnode)
    return EINVAL;

  if (status <= MAGI_NODE_STATUS_MINIMUM || status >= MAGI_NODE_STATUS_MAXIMUM)
    return EINVAL;

  if (mnode->status == status)
    push_event = false;

  mnode->status = status;

  event.status = mnode->status;
  event.everip_addr = mnode->everip_addr;

  if (push_event)
    magi_eventdriver_handler_run( mnode->ctx->ed
                                , MAGI_EVENTDRIVER_WATCH_E2E
                                , &event );

  return 0;
}

struct magi_node *
magi_node_lookup_or_create( struct magi *magi
                          , const uint8_t public_key[NOISE_PUBLIC_KEY_LEN] )
{
  int err = 0;
  struct magi_node *mnode;
  uint8_t everip_addr[EVERIP_ADDRESS_LENGTH];

  if (!magi || !public_key)
    return NULL;

  /* hash it and make sure it starts with fc */
  if (!addr_calc_pubkeyaddr( everip_addr
                           , public_key ))
  {
    return NULL;
  }

  /* check to see if we have key in our database */
  mnode = list_ledata(hash_lookup( magi->idx_key
                                 , *(uint32_t *)(void *)public_key
                                 , _magi_node_lookup_key
                                 , (void *)public_key));

  if (mnode) {
    return mnode;
  }

  /* seems good -- add to magi */
  mnode = mem_zalloc(sizeof(*mnode), magi_node_destructor);
  if (!mnode)
    return NULL;

  /* initiate */
  mnode->ctx = magi;

  memcpy(mnode->public_key, public_key, NOISE_PUBLIC_KEY_LEN);
  memcpy(mnode->everip_addr, everip_addr, EVERIP_ADDRESS_LENGTH);

  /* link to rest of magi */
  list_append(&magi->nodes, &mnode->le, mnode);

  hash_append( magi->idx_key
             , *(uint32_t *)(void *)public_key
             , &mnode->le_idx_key
             , mnode);

  hash_append( magi->idx_addr
             , *(uint32_t *)(void *)everip_addr
             , &mnode->le_idx_addr
             , mnode);

  if (err) {
    mnode = mem_deref( mnode );
  } else {
    /* notify of new node */
    (void)magi_node_status_update(mnode, MAGI_NODE_STATUS_CREATED);
  }
  return mnode;
}

static void magi_maintenance_hello_cb( enum MAGI_MELCHIOR_RETURN_STATUS status
                                     , struct odict *od_sent
                                     , struct odict *od_recv
                                     , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH]
                                     , uint64_t timediff
                                     , void *userdata)
{
  struct magi_node *mnode = userdata;
  debug("magi_maintenance_hello_cb\n");

  if (status != MAGI_MELCHIOR_RETURN_STATUS_OK)
    return; /* ignore for now */

  magi_node_status_update(mnode, MAGI_NODE_STATUS_OPERATIONAL);

}

static void magi_maintenance_cb(void *data)
{
  int err = 0;
  struct le *le;
  struct odict *od = NULL;
  struct magi_node *mnode;
  struct magi *magi = data;
  uint64_t now = tmr_jiffies();

  /*error("magi_maintenance_cb\n");*/

  LIST_FOREACH(&magi->nodes, le) {
    mnode = le->data;
    if (!mnode->ls) {
      error("ATTEMPTING TO CONNECT VIA LEDBAT\n");
      
      magi_node_status_update(mnode, MAGI_NODE_STATUS_SEARCHING);

      ledbat_sock_alloc(&mnode->ls, everip_ledbat());
      if (!mnode->ls)
        continue;

      ledbat_sock_userdata_set(mnode->ls, mnode);
      ledbat_sock_connect(mnode->ls, mnode->everip_addr);
      continue;
    }

    if (mnode->last_hello < now - 7000) {
      /* send hello! */

      odict_alloc(&od, 8);

      err = magi_melchior_send( everip_magi_melchior()
                              , od
                              , &(struct pl){.p="ever.hello",.l=10}
                              , mnode->everip_addr
                              , 5000
                              , false /* is not routable */
                              , magi_maintenance_hello_cb
                              , mnode );

      od = mem_deref(od);
      mnode->last_hello = now;
    }
  }

  tmr_start(&magi->maintenance, 1000, magi_maintenance_cb, magi);

}

static void magi_destructor(void *data)
{
  struct magi *magi = data;
  list_flush(&magi->nodes);
  magi->idx_key = mem_deref( magi->idx_key );
  magi->idx_addr = mem_deref( magi->idx_addr );

  tmr_cancel(&magi->maintenance);
}

int magi_alloc(struct magi **magip, struct magi_eventdriver *med)
{
  int err = 0;
  struct magi *magi;

  if (!magip || !med)
    return EINVAL;

  magi = mem_zalloc(sizeof(*magi), magi_destructor);
  if (!magi)
    return ENOMEM;

  err = hash_alloc(&magi->idx_key, 16);
  if (err)
    goto out;

  err = hash_alloc(&magi->idx_addr, 16);
  if (err)
    goto out;

  magi->ed = med;

  tmr_start(&magi->maintenance, 1000, magi_maintenance_cb, magi);

out:
  if (!err)
    *magip = magi;
  return err;
}

