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
};

struct magi_melchior_ticket {
  struct le le;
  struct tmr tmr;

  uint8_t everip_addr[EVERIP_ADDRESS_LENGTH];
  uint32_t ticket_id;

  struct odict *od_sent;
  struct odict *od_recv;

  magi_melchior_h *callback;
  void *userdata;

};

static void magi_melchior_ticket_timeout(void *data)
{
  struct magi_melchior_ticket *mmt = data;

  warning("timed-out!\n");

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

}

int magi_melchior_send( struct magi_melchior *mm
                      , struct odict *od
                      , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH]
                      , uint64_t timeout
                      , magi_melchior_h *callback
                      , void *userdata )
{

  struct magi_melchior_ticket *mmt = NULL;

  if (!mm || !od || !everip_addr || !callback)
    return EINVAL;

  mmt = mem_zalloc(sizeof(*mmt), magi_melchior_ticket_destructor);
  if (!mmt)
    return ENOMEM;

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

  odict_entry_add(mmt->od_sent, "_t", ODICT_INT, mmt->ticket_id);

  /* sign and serialize */

  /* send to subsystem */

  return 0;
}

static void magi_melchior_destructor(void *data)
{
  struct magi_melchior *mm = data;
  hash_flush(mm->tickets);
  mm->tickets = mem_deref( mm->tickets );
}

int magi_melchior_alloc(struct magi_melchior **mmp)
{
  int err = 0;
  struct magi_melchior *mm;

  mm = mem_zalloc(sizeof(*mm), magi_melchior_destructor);
  if (!mm)
    return ENOMEM;

  hash_alloc(&mm->tickets, 16);

  *mmp = mm;

  return err;
}
