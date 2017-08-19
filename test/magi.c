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
#include "test.h"

static void test_magi_m_cb( enum MAGI_MELCHIOR_RETURN_STATUS status
                          , struct odict *od_sent
                          , struct odict *od_recv
                          , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH]
                          , uint64_t timediff
                          , void *userdata)
{
  int *err = userdata;
  info("test_magi_m_cb\n");
  
  *err = 0;
  re_cancel();
}

int test_magi(void)
{
  int err = 0;
  struct odict *od = NULL;
  struct magi_melchior *mm;
  uint8_t everip_addr[EVERIP_ADDRESS_LENGTH] = {0};

  /* melchior */
  err = magi_melchior_alloc(&mm);
  TEST_ERR(err);

  /* create dict */
  odict_alloc(&od, 8);

  err = magi_melchior_send( mm
                          , od
                          , everip_addr
                          , 1 /* 1 ms */
                          , false /* is not routable */
                          , test_magi_m_cb
                          , &err );
  TEST_ERR(err);
  od = mem_deref(od);

  err |= re_main_timeout(5);
  TEST_ERR(err); /* includes tests for callback */

out:
  mm = mem_deref(mm);
  return err;
}
