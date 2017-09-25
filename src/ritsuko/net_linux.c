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

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <fcntl.h>
#include <unistd.h>

struct netevents_runner {
  struct mqueue *mq;
  int fd;
};

static void _read_handler(int flags, void *arg)
{
  ssize_t n;
  uint8_t buf[2048];
  bool action = false;
  struct  nlmsghdr *nlh;
  struct netevents_runner *ner = arg;

  (void)flags;

  n = read(ner->fd, buf, 2048);
  if (n < 0) {
    goto out;
  }

  nlh = (struct nlmsghdr *)buf;

  for ( ; NLMSG_OK(nlh, n); nlh = NLMSG_NEXT(nlh, n) ) {

    switch (nlh->nlmsg_type) {
      case NLMSG_DONE:
        return;
      case NLMSG_ERROR:
      {
        const struct nlmsgerr* msg = (struct nlmsgerr*)(NLMSG_DATA(nlh));
        error("[NETEVENTS] Unexpected netlink error: %s\n",  msg->error);
        return;
      }
      case RTM_NEWADDR:
        /*@FALLTHROUGH@*/
      case RTM_DELADDR:
        action = true;
        break;
      case RTM_NEWLINK:
        /*@FALLTHROUGH@*/
      case RTM_DELLINK:
      {
        /*const struct ifinfomsg* msg = (struct ifinfomsg*)(NLMSG_DATA(nlh));*/
        /* do check ignore? */
        /* do check ignore for wireless? */
        action = true;
        break;
      }
      default:
        break;
    }
  }

if (action)
  mqueue_push(ner->mq, 1, NULL);

out:
  return;

}

static void netevents_runner_destructor(void *data)
{
  struct netevents_runner *ner = data;

  ner->mq = mem_deref( ner->mq );

}

int netevents_runner_alloc( struct netevents_runner **nerp, struct mqueue *mq )
{
  int err = 0;
  struct sockaddr_nl addr;
  struct netevents_runner *ner;

  if (!nerp || !mq)
    return EINVAL;

  ner = mem_zalloc(sizeof(*ner), netevents_runner_destructor);
  if (!ner) {
    return ENOMEM;
  }

  ner->mq = mq;
  mem_ref( ner->mq );

  memset(&addr, 0, sizeof(addr));

  ner->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

  if (ner->fd < 0) {
    err = errno;
    goto out;
  }

  addr.nl_family = AF_NETLINK;
  addr.nl_pid = getpid();
  addr.nl_groups =
        RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR | RTMGRP_NOTIFY | RTMGRP_LINK;

  if (bind(ner->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    err = errno;
    goto out;
  }

  net_sockopt_blocking_set(ner->fd, false);

  err = fcntl(ner->fd, F_SETFD, FD_CLOEXEC);
  if (err) {
    goto out;
  }

  err = fd_listen( ner->fd
                 , FD_READ
                 , _read_handler
                 , ner);
  if (err) {
    goto out;
  }

out:
  if (err) {
    ner = mem_deref(ner);
  } else {
    *nerp = ner;
  }
  return err;
}
