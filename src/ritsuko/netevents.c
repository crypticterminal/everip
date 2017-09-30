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

#include <net/if.h>

struct netevents {
  struct magi_eventdriver *ed;
  struct netevents_runner *ner;
  struct mqueue *mq;

  struct tmr tmr_update;
  struct list interfaces;
};

struct _interface {
  struct le le;
  char *ifname;
  unsigned int ifindex;
  enum NETEVENTS_IFACE_KIND ifkind;
  struct sa sa;
  bool touch_if;
  bool touch_sa;
  bool ifmarker;
};

struct interfaces_needle {
  const char *ifname;
  const struct sa *sa;
  bool exists_if;
  bool exists_sa;
};

static void _interface_destructor(void *arg)
{
  struct _interface *iface = arg;
  list_unlink(&iface->le);
  iface->ifname = mem_deref( iface->ifname );
}

static bool interfaces_needle_apply_h(struct le *le, void *arg)
{
  struct _interface *iface = le->data;
  struct interfaces_needle *need = arg;

  if (!str_cmp(iface->ifname, need->ifname)) {
    need->exists_if = true;
    iface->touch_if = true;
    if ( sa_isset(need->sa, SA_ADDR)
      && sa_cmp(&iface->sa, need->sa, SA_ADDR)) {
      need->exists_sa = true;
      iface->touch_sa = true;
    }
  }
  return false;
}

static bool _if_handler( const char *ifname
                       , const struct sa *sa
                       , void *arg )
{
  struct netevents *ne = arg;
  struct interfaces_needle need;
  struct netevent_event event;

  struct _interface *_iface = NULL;

  memset(&need, 0, sizeof(need));

  need.ifname = ifname;
  need.sa = sa;

  (void)list_apply( &ne->interfaces
                  , true
                  , &interfaces_needle_apply_h
                  , &need );

  if (!need.exists_if || !need.exists_sa) {
    /*error("adding%s: %s %j\n", !need.exists_if ? " FOR FIRST" : "", ifname, sa);*/
    if (!need.exists_if) {
      /* set marker to see if we still have interface later */
      _iface = mem_zalloc(sizeof(*_iface), _interface_destructor);
      str_dup(&_iface->ifname, ifname);
      _iface->ifmarker = true;
      _iface->ifindex = if_nametoindex(ifname);
      (void)netevents_platform_getkind(ifname, &_iface->ifkind );
      /* set touch to true because we reset on the sweep */
      _iface->touch_if = true;
      _iface->touch_sa = true;
      list_append(&ne->interfaces, &_iface->le, _iface);

      memset(&event, 0, sizeof(event));

      event.ne = ne;
      event.type = NETEVENT_EVENT_DEV_UP;
      event.if_options = NETEVENT_EVENT_OPT_NAME;
      event.if_name = ifname;
      if (_iface->ifindex) {
        event.if_options |= NETEVENT_EVENT_OPT_INDEX;
        event.if_index = _iface->ifindex;
      }

      if (_iface->ifkind != NETEVENTS_IFACE_KIND_UNKNOWN) {
        event.if_options |= NETEVENT_EVENT_OPT_KIND;
        event.if_kind = _iface->ifkind;
      }

      magi_eventdriver_handler_run( ne->ed
                                  , MAGI_EVENTDRIVER_WATCH_NETEVENT
                                  , &event );
    }

    _iface = mem_zalloc(sizeof(*_iface), _interface_destructor);
    str_dup(&_iface->ifname, ifname);
    sa_cpy(&_iface->sa, sa);
    _iface->ifindex = if_nametoindex(ifname);
    (void)netevents_platform_getkind(ifname, &_iface->ifkind );
    /* set touch to true because we reset on the sweep */
    _iface->touch_if = true;
    _iface->touch_sa = true;
    list_append(&ne->interfaces, &_iface->le, _iface);

    /* notify under layers here */
    memset(&event, 0, sizeof(event));

    event.ne = ne;
    event.type = NETEVENT_EVENT_ADDR_NEW;
    event.if_options = NETEVENT_EVENT_OPT_NAME | NETEVENT_EVENT_OPT_ADDR;
    event.if_name = ifname;
    sa_cpy(&event.sa, sa);
    if (_iface->ifindex) {
      event.if_options |= NETEVENT_EVENT_OPT_INDEX;
      event.if_index = _iface->ifindex;
    }
    if (_iface->ifkind != NETEVENTS_IFACE_KIND_UNKNOWN) {
      event.if_options |= NETEVENT_EVENT_OPT_KIND;
      event.if_kind = _iface->ifkind;
    }

    magi_eventdriver_handler_run( ne->ed
                                , MAGI_EVENTDRIVER_WATCH_NETEVENT
                                , &event );
  }
  /*error("%s %j\n", ifname, sa);*/
  return false;
}

static bool interfaces_sweep_apply_h(struct le *le, void *arg)
{
  struct _interface *iface = le->data;
  struct netevents *ne = arg;
  struct netevent_event event;

  memset(&event, 0, sizeof(event));

  if (iface->ifmarker) {
    if (!iface->touch_if) {
      /* interface no longer exists */

      event.ne = ne;
      event.type = NETEVENT_EVENT_DEV_DOWN;
      event.if_options = NETEVENT_EVENT_OPT_NAME;
      event.if_name = iface->ifname;
      if (iface->ifindex) {
        event.if_options |= NETEVENT_EVENT_OPT_INDEX;
        event.if_index = iface->ifindex;
      }
      if (iface->ifkind != NETEVENTS_IFACE_KIND_UNKNOWN) {
        event.if_options |= NETEVENT_EVENT_OPT_KIND;
        event.if_kind = iface->ifkind;
      }

      magi_eventdriver_handler_run( ne->ed
                                  , MAGI_EVENTDRIVER_WATCH_NETEVENT
                                  , &event );

      /*error("interface [%s] no longer exists!\n", iface->ifname);*/
      iface = mem_deref( iface );
      goto out;
    }
  } else if (!iface->touch_sa) {
    /* address no longer exists */
    event.ne = ne;
    event.type = NETEVENT_EVENT_ADDR_DEL;
    event.if_options = NETEVENT_EVENT_OPT_NAME | NETEVENT_EVENT_OPT_ADDR;
    event.if_name = iface->ifname;
    sa_cpy(&event.sa, &iface->sa);
    if (iface->ifindex) {
      event.if_options |= NETEVENT_EVENT_OPT_INDEX;
      event.if_index = iface->ifindex;
    }
    if (iface->ifkind != NETEVENTS_IFACE_KIND_UNKNOWN) {
      event.if_options |= NETEVENT_EVENT_OPT_KIND;
      event.if_kind = iface->ifkind;
    }

    magi_eventdriver_handler_run( ne->ed
                                , MAGI_EVENTDRIVER_WATCH_NETEVENT
                                , &event );
    /*error("address %s:%j no longer exists!\n", iface->ifname, &iface->sa);*/
    iface = mem_deref( iface );
    goto out;
  } 

out:
  if (iface) {
    iface->touch_if = false;
    iface->touch_sa = false;    
  }
  return false;
}

struct _interfaces_apply_s {
  struct netevents *ne;
  netevents_interfaces_apply_h *fn;
  void *arg;
};

static bool _interfaces_apply_h(struct le *le, void *arg)
{
  struct netevent_event event;
  struct _interface *iface = le->data;
  struct _interfaces_apply_s *apply = arg;

  memset(&event, 0, sizeof(event));

  event.ne = apply->ne;
  event.type = NETEVENT_EVENT_ADDR_EXISTS;
  event.if_options |= NETEVENT_EVENT_OPT_NAME;
  event.if_name = iface->ifname;
  if (!iface->ifmarker) {
    event.if_options |= NETEVENT_EVENT_OPT_ADDR;
    sa_cpy(&event.sa, &iface->sa);
  }
  if (iface->ifindex) {
    event.if_options |= NETEVENT_EVENT_OPT_INDEX;
    event.if_index = iface->ifindex;
  }

  return apply->fn(&event, apply->arg);
}

int netevents_interfaces_apply( struct netevents *ne
                              , netevents_interfaces_apply_h *fn
                              , void *arg)
{
  struct _interfaces_apply_s apply;

  if (!ne || !fn)
    return EINVAL;

  apply.ne = ne;
  apply.fn = fn;
  apply.arg = arg;

  (void)list_ledata(list_apply( &ne->interfaces
                              , true
                              , &_interfaces_apply_h
                              , &apply ));

  return 0;
}

static void _tmr_update_handler(void *arg)
{
  int err = 0;
  struct netevents *ne = arg;

  /*error("got network update event\n");*/

#ifdef HAVE_GETIFADDRS
  err |= net_getifaddrs(_if_handler, ne);
#else
  err |= net_if_list(_if_handler, ne);
#endif

  /* do sweep */

  (void)list_apply( &ne->interfaces
                  , true
                  , &interfaces_sweep_apply_h
                  , ne );

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
    memset(&event, 0, sizeof(event));
    event.ne = netevents;
    event.type = NETEVENT_EVENT_CLOSE;

    magi_eventdriver_handler_run( netevents->ed
                                , MAGI_EVENTDRIVER_WATCH_NETEVENT
                                , &event );
    netevents->ed = NULL;
  }

  netevents->ner = mem_deref( netevents->ner );
  netevents->mq = mem_deref( netevents->mq );

  tmr_cancel(&netevents->tmr_update);

  list_flush(&netevents->interfaces);

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

  list_init(&netevents->interfaces);

  tmr_init(&netevents->tmr_update);

  err = mqueue_alloc(&netevents->mq, mqueue_handler, netevents);
  if (err)
    goto out;

  err = netevents_runner_alloc(&netevents->ner, netevents->mq);
  if (err)
    goto out;

  netevents->ed = ed;

  memset(&event, 0, sizeof(event));

  event.ne = netevents;
  event.type = NETEVENT_EVENT_INIT;

  magi_eventdriver_handler_run( netevents->ed
                              , MAGI_EVENTDRIVER_WATCH_NETEVENT
                              , &event );

  tmr_start(&netevents->tmr_update, 200, _tmr_update_handler, netevents);

out:
  if (err) {
    netevents = mem_deref(netevents);
  } else {
    *neteventsp = netevents;
  }
  return err;
}
