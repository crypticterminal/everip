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

#define PRIVATEKEY "355dd5874b2f0cbd45bb82c7ed61ebb1f0f9f8ca0b287efe0951cd11635aac37"

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
  struct magi *magi = NULL;
  struct magi_melchior *mm = NULL;
  struct noise_engine *ne;
  uint8_t everip_addr[EVERIP_ADDRESS_LENGTH] = {0};
  uint8_t prv_key[NOISE_SECRET_KEY_LEN];

  str_hex(prv_key, NOISE_SECRET_KEY_LEN, PRIVATEKEY);

  /* dummy noise engine */
  err = noise_engine_init(&ne, NULL);
  TEST_ERR(err);

  noise_si_private_key_set( &ne->si, prv_key );
  cryptosign_skpk_fromcurve25519(ne->sign_keys, prv_key);

  /* core */
  err = magi_alloc( &magi, NULL);
  TEST_ERR(err);

  /* melchior */
  err = magi_melchior_alloc(&mm, magi, ne);
  TEST_ERR(err);

  /* create dict */
  odict_alloc(&od, 8);

  err = magi_melchior_send( mm
                          , od
                          , &(struct pl){.p="hello",.l=5}
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
  ne = mem_deref(ne);
  magi = mem_deref(magi);
  return err;
}
