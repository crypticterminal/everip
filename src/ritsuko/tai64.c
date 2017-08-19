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

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
typedef struct timeval {
    long tv_sec;
    long tv_usec;
} timeval;

static int __gettimeofday(struct timeval * tp, struct timezone * tzp)
{
  /*
   * Note: some broken versions only have 8 trailing zero's, the correct epoch
   * has 9 trailing zero's This magic number is the number of 100 nanosecond
   * intervals since January 1, 1601 (UTC) until 00:00:00 January 1, 1970
   */
  static const uint64_t EPOCH = ((uint64_t) 116444736000000000ULL);

  SYSTEMTIME  system_time;
  FILETIME    file_time;
  uint64_t    time;

  GetSystemTime( &system_time );
  SystemTimeToFileTime( &system_time, &file_time );
  time =  ((uint64_t)file_time.dwLowDateTime )      ;
  time += ((uint64_t)file_time.dwHighDateTime) << 32;

  tp->tv_sec  = (long) ((time - EPOCH) / 10000000L);
  tp->tv_usec = (long) (system_time.wMilliseconds * 1000);
  return 0;
}
#define gettimeofday __gettimeofday
#else
#include <time.h>
#endif

void tai64n_now( uint8_t output[TAI64_N_LEN] )
{
  struct timeval now;

  if (0 != gettimeofday(&now, NULL)) {
    warning("_tai64n_now: gettimeofday() failed (%m)\n", errno);
    return;
  }

  /* https://cr.yp.to/libtai/tai64.html */
  *(uint64_t *)(void *)output = \
      arch_htobe64(4611686018427387914ULL + now.tv_sec);
  *(uint32_t *)(void *)(output + sizeof(uint64_t)) = \
      arch_htobe32(1000 * now.tv_usec + 500);
}

