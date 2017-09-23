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

struct netevents {
  struct magi_eventdriver *ed;
  struct netevents_runner *ner;

  struct mqueue *mq;
};


static void mqueue_handler(int id, void *data, void *arg)
{
  struct netevents *ne = arg;
  (void)data;

}

static void netevents_destructor(void *data)
{
  struct netevents *netevents = data;
  struct netevent_event event;

  if (netevents->ed) {
    event.ne = netevents;
    event.type = NETEVENT_EVENT_CLOSE;

    magi_eventdriver_handler_run( netevents->ed
                                , MAGI_EVENTDRIVER_WATCH_NETEVENT
                                , &event );    
  }

  netevents->ner = mem_deref( netevents->ner );
  netevents->mq = mem_deref( netevents->mq );
}

int netevents_alloc( struct netevents **neteventsp
                   , struct magi_eventdriver *ed )
{
  int err = 0;

  struct netevents *netevents;
  struct netevent_event event;

  if (!neteventsp)
    return EINVAL;

  netevents = mem_zalloc(sizeof(*netevents), netevents_destructor);
  if (!netevents) {
    return ENOMEM;
  }

  err = mqueue_alloc(&netevents->mq, mqueue_handler, netevents);
  if (err)
    goto out;

  err = netevents_runner_alloc(&netevents->ner, netevents->mq);
  if (err)
    goto out;


  error("netevents_alloc\n");

out:
  if (err) {
    netevents = mem_deref(netevents);
  } else {
    *neteventsp = netevents;
  }
  return err;
}
