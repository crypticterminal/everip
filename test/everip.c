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
#include "test.h"

#define PRIVATEKEY "355dd5874b2f0cbd45bb82c7ed61ebb1f0f9f8ca0b287efe0951cd11635aac37"

int test_everip(void)
{
  int err = 0;
  uint8_t prv[NOISE_PUBLIC_KEY_LEN];

  warning("NOTICE: It is okay if the tunnel fails for this test;\n");

  str_hex(prv, 32, PRIVATEKEY);

  err = everip_init(prv, 1988);
  TEST_ERR(err);

  everip_close();

  mod_close();
out:
  return err;
}
