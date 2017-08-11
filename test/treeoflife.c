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

int test_treeoflife(void)
{
  int err = 0;
  char buf[2048];

  uint8_t root_binrep[ROUTE_LENGTH];
  memset(root_binrep, 0, ROUTE_LENGTH);

  re_snprintf(buf, 2048, "%H", stack_debug, root_binrep);

  ASSERT_STREQ("[0]", buf);

  stack_layer_add(root_binrep, 1);

  re_snprintf(buf, 2048, "%H", stack_debug, root_binrep);
  ASSERT_STREQ("[-1-1-1-1-1-1+1]", buf);

  error("\n");

  stack_layer_add(root_binrep, 2);
  re_snprintf(buf, 2048, "%H", stack_debug, root_binrep);
  ASSERT_STREQ("[-2-2-2-2-2-2+2-1-1-1-1-1+1-1]", buf);

  stack_layer_add(root_binrep, 3);
  re_snprintf(buf, 2048, "%H", stack_debug, root_binrep);
  ASSERT_STREQ("[-3-3-3-3-3-3+3-2-2-2-2-2+2-2-1-1-1-1-1+1+1]", buf);


out:
  return err;
}
