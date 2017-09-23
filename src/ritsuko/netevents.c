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

  struct tmr tmr_update;
};



static bool _if_handler( const char *ifname
                       , const struct sa *sa
                       , void *arg )
{
  struct netevents *ne = arg;
  error("%s %j\n", ifname, sa);
  return false;
}

static void _tmr_update_handler(void *arg)
{
  int err = 0;
  struct netevents *ne = arg;

  error("got network update event\n");

#ifdef HAVE_GETIFADDRS
    err |= net_getifaddrs(_if_handler, ne);
#else
    err |= net_if_list(_if_handler, ne);
#endif
}

static void mqueue_handler(int id, void *data, void *arg)
{
  struct netevents *ne = arg;
  (void)data;

  if (id == 1) {
    /* we get multiple events when something changes,
       so wait until last change and then fire.
     */
    tmr_start(&ne->tmr_update, 200, _tmr_update_handler, ne);
  }

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

  tmr_cancel(&netevents->tmr_update);

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

  tmr_init(&netevents->tmr_update);

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
