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

struct magi {
  struct list nodes;
  struct hash *idx_key;
  struct hash *idx_addr;
};

struct magi_node {
  struct le le;
  struct le le_idx_key;
  struct le le_idx_addr;

  uint8_t public_key[NOISE_PUBLIC_KEY_LEN];
  uint8_t everip_addr[EVERIP_ADDRESS_LENGTH];

  struct magi *ctx;

  struct ledbat_sock *ls;
};

static uint64_t ledbat_callback_h(ledbat_callback_arguments *a, void *arg )
{
  struct magi_node *mnode = arg;

  if (!mnode)
    return 0;

  debug("ledbat_callback_h:\n");

  switch (a->callback_type) {
    case LEDBAT_ON_ERROR:
      debug("ledbat_callback_h: error: %d\n", a->u1.error_code);
      ledbat_sock_reconnect(mnode->ls);
      break;
    case LEDBAT_ON_STATE_CHANGE:
      debug("ledbat_callback_h: state: %d\n", a->u1.state);
      break;
    default:
      debug("ledbat_callback_h: unknown: %d\n", a->callback_type);
      break;
  }

  return 0;
}

int magi_node_ledbat_sock_set( struct magi_node *mnode
                             , struct ledbat_sock *lsock )
{
  if (!mnode)
    return EINVAL;

  mnode->ls = mem_deref(mnode->ls);

  if (lsock)
    mnode->ls = lsock;

  return 0;
}

struct ledbat_sock *
magi_node_ledbat_sock_get( struct magi_node *mnode )
{
  if (!mnode)
    return NULL;
  return mnode->ls;
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
  (void)mnode;
  list_unlink(&mnode->le);
  list_unlink(&mnode->le_idx_key);
  list_unlink(&mnode->le_idx_addr);
}

struct magi_node *
magi_node_lookup_by_eipaddr( struct magi *magi
                           , uint8_t everip_addr[EVERIP_ADDRESS_LENGTH] )
{
  struct magi_node *mnode;
  if (!magi || !everip_addr)
    return NULL;

  mnode = list_ledata(hash_lookup( magi->idx_addr
                                 , *(uint32_t *)(void *)everip_addr
                                 , _magi_node_lookup_addr
                                 , everip_addr));
  return mnode;
}

struct magi_node *
magi_node_lookup_or_create( struct magi *magi
                          , uint8_t public_key[NOISE_PUBLIC_KEY_LEN] )
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
                                 , public_key));

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
  }
  return mnode;
}

static void magi_destructor(void *data)
{
  struct magi *magi = data;
  list_flush(&magi->nodes);
  magi->idx_key = mem_deref( magi->idx_key );
  magi->idx_addr = mem_deref( magi->idx_addr );
}

int magi_alloc(struct magi **magip)
{
  int err = 0;
  struct magi *magi;

  magi = mem_zalloc(sizeof(*magi), magi_destructor);
  if (!magi)
    return ENOMEM;

  err = hash_alloc(&magi->idx_key, 16);
  if (err)
    goto out;

  err = hash_alloc(&magi->idx_addr, 16);
  if (err)
    goto out;

out:
  if (!err)
    *magip = magi;
  return err;
}

