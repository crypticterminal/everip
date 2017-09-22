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

#include <sys/uio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <fcntl.h>

struct netevent {
  int fd;
  struct magi_eventdriver *ed;
};

static void _read_handler(int flags, void *arg)
{
  struct netevent_event event;
  struct netevent *ne = arg;
  ssize_t n;
  uint8_t msg[2048];
  char _ifname[IF_NAMESIZE] = {0};
  struct rt_msghdr *hdr = NULL;
  struct if_msghdr *ifm = NULL;

  n = read(ne->fd, msg, 2048);
  if (n < 0) {
    goto out;
  }

  hdr = (struct rt_msghdr *)(void *)msg;

  if (hdr->rtm_type != RTM_IFINFO) {
    return;
  }

  ifm = (struct if_msghdr *)hdr;

  if_indextoname(ifm->ifm_index, _ifname);

  if (ne->ed) {
    event.ne = ne;
    event.type = hdr->rtm_flags & RTF_UP ? NETEVENT_EVENT_DEV_UP
                                         : NETEVENT_EVENT_DEV_DOWN;
    event.if_name = _ifname;
    event.if_index = ifm->ifm_index;

    magi_eventdriver_handler_run( ne->ed
                                , MAGI_EVENTDRIVER_WATCH_NETEVENT
                                , &event );
  }

 out:
  return;
}

static void netevent_destructor(void *data)
{
  struct netevent *netevent = data;
  struct netevent_event event;

  if (netevent->ed) {
    event.ne = netevent;
    event.type = NETEVENT_EVENT_CLOSE;
    event.if_name = NULL;
    event.if_index = 0;

    magi_eventdriver_handler_run( netevent->ed
                                , MAGI_EVENTDRIVER_WATCH_NETEVENT
                                , &event );    
  }

  if (netevent->fd > 0) {
    fd_close(netevent->fd);
    (void)close(netevent->fd);
  }
}

int netevent_init( struct netevent **neteventp, struct magi_eventdriver *ed )
{
  int err = 0;
  struct netevent *netevent;
  struct netevent_event event;

  if (!neteventp)
    return EINVAL;

  netevent = mem_zalloc(sizeof(*netevent), netevent_destructor);
  if (!netevent) {
      netevent = mem_deref(netevent);
    return ENOMEM;
  }

  netevent->fd = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
  if (netevent->fd < 0) {
      netevent = mem_deref(netevent);
      return EINVAL;
  }

  net_sockopt_blocking_set(netevent->fd, false);

  err = fcntl(netevent->fd, F_SETFD, FD_CLOEXEC);
  if (err) {
    goto err;
  }

  err = fd_listen( netevent->fd
               , FD_READ
               , _read_handler
               , netevent);
  if (err) {
    goto err;
  }

  netevent->ed = ed;

  if (ed) {
    event.ne = netevent;
    event.type = NETEVENT_EVENT_INIT;
    event.if_name = NULL;
    event.if_index = 0;

    magi_eventdriver_handler_run( ed
                                , MAGI_EVENTDRIVER_WATCH_NETEVENT
                                , &event );

  }

err:
  if (err) {
    netevent = mem_deref(netevent);
  } else {
    *neteventp = netevent;
  }
  return err;
}
