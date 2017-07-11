/*
 * EVER/IP(R)
 * Copyright (c) 2017 kristopher tate & connectFree Corporation.
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * This project may be licensed under the terms of the GNU AFFERO General
 * Public License version 3. Corporate and Academic licensing terms are also
 * available. Contact <licensing@connectfree.co.jp> for details.
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

int test_tun(void)
{
  int err;
  struct sa tmp_sa;
  struct tunif *tunif;
  struct netevent *netevent;

  sa_init(&tmp_sa, AF_INET6);
  sa_set_str(&tmp_sa, "fc1c:7124:2ab8:687b:4e3e:fac1:8de6:1dc0", 0);

  err = netevent_init( &netevent );
  TEST_ERR(err);

#if !defined(WIN32) && !defined(CYGWIN)
    err = tunif_init( &tunif );
    TEST_ERR(err);

    err = net_if_setaddr( tunif->name
                        , &tmp_sa
                        , 8 );
    TEST_ERR(err);

    err = net_if_setmtu( tunif->name
                       , 1304);
    TEST_ERR(err);

#endif

 out:
  mem_deref(tunif);
  mem_deref(netevent);
  return err;
}
