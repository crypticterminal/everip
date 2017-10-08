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

#include "tol.h"

int tol_command_callback( struct magi_melchior_rpc *rpc
                        , struct pl *method
                        , void *arg )
{
  struct this_module *mod = arg;

  if (!rpc || !mod || !method)
    return EINVAL;

  error( "[TREE] treeoflife_command_callback: [%r] from %w\n"
      , method
      , rpc->everip_addr, EVERIP_ADDRESS_LENGTH
      );

  switch (method->l) {
//    case 3:
//      /* dht */
//      if (!memcmp(method->p, "dht", 3))
//      {
//        return treeoflife_command_cb_dht(tol_c, rpc);
//      }
    case 4:
      /* zone */
      if (!memcmp(method->p, "zone", 4))
      {
        return tol_command_cb_zone(mod, rpc);
      }
    case 5:
      /* child */
      if (!memcmp(method->p, "child", 5))
      {
        return tol_command_cb_child(mod, rpc);
      }
//    case 6:
//      /* update */
//      if (!memcmp(method->p, "update", 6))
//      {
//        return treeoflife_command_cb_update(tol_c, rpc);
//      }
    default:
      return EPROTO;
  }
  /* failsafe */
  return EPROTO;
}
