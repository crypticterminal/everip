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
#include "test.h"

/*
0000   00 ff fb 8d 62 56 fc 00 00 00 00 00 86 dd 60 00  ....bV........`.
0010   00 00 00 20 3a ff fc 1c 71 24 2a b8 68 7b 4e 3e  ... :...q$*.h{N>
0020   fa c1 8d e6 1d c0 fc 47 02 9f 42 8a 3a 2c c3 b2  .......G..B.:,..
0030   25 a4 35 60 95 38 88 00 58 4e e0 00 00 00 fc 1c  %.5`.8..XN......
0040   71 24 2a b8 68 7b 4e 3e fa c1 8d e6 1d c0 02 01  q$*.h{N>........
0050   fc 00 00 00 00 00                                ......
*/

#define ICMP6_PACKET_HEX \
    "6000""0000""0020""3aff" \
    "fc1c""7124""2ab8""687b""4e3e""fac1""8de6""1dc0" \
    "fc47""029f""428a""3a2c""c3b2""25a4""3560""9538" \
    "8800""7fdd" \
    "e000""0000""fc1c""7124""2ab8""687b""4e3e""fac1" \
    "8de6""1dc0""0201""fc00""0000""0000"
static const char *icmp6PacketHex = ICMP6_PACKET_HEX;
#define ICMP6_PACKET_SIZE ((sizeof(ICMP6_PACKET_HEX)-1)/2)

static int icmp6ChecksumTest(void)
{
  int err = 0;
  uint16_t checksum;
  uint16_t checksum_calc;
  uint8_t packet[ICMP6_PACKET_SIZE];
  str_hex(packet, ICMP6_PACKET_SIZE, icmp6PacketHex);
  memcpy(&checksum, &packet[42], 2);

  /* zero out */
  packet[42] = 0;
  packet[43] = 0;

  re_printf("%W\n", &packet[40], 32);

  checksum_calc = chksum_ipv6(&packet[8], &packet[40], 32, arch_htobe32(58));

  ASSERT_TRUE(checksum == checksum_calc);
out:
  return err;
}


int test_checksum(void)
{
  int err = 0;
  err = icmp6ChecksumTest();
  TEST_ERR(err);
out:
  return err;
}