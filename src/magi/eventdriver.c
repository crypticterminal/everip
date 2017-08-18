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

struct magi_eventdriver {
  struct list handlers[MAGI_EVENTDRIVER_WATCH_MAX];
};

struct magi_eventdriver_handler {
  struct le le;
  struct magi_eventdriver *driver;

  uint32_t flags;

  magi_eventdriver_h *handler;
  void *userdata;

};

static inline struct list * _grab_handler( struct magi_eventdriver *ed
                                         , enum MAGI_EVENTDRIVER_WATCH handler )
{
  if (!ed)
    return NULL;

  if (handler > MAGI_EVENTDRIVER_WATCH_MAX)
    return NULL;
  else
    return &ed->handlers[handler];
}

int magi_eventdriver_handler_run( struct magi_eventdriver *ed
                                , enum MAGI_EVENTDRIVER_WATCH type
                                , void *data )
{
  struct le *le;
  struct list *handlers;
  struct magi_eventdriver_handler *edh;

  handlers = _grab_handler(ed, type);
  if (!handlers)
    return EINVAL;

  LIST_FOREACH(handlers, le) {
    edh = le->data;
    edh->handler(type, data, edh->userdata);
  }
  return 0;
}

static void magi_eventdriver_handler_destructor(void *data)
{
  struct magi_eventdriver_handler *edh = data;
  list_unlink(&edh->le);
}

int magi_eventdriver_handler_register( struct magi_eventdriver *ed
                                     , enum MAGI_EVENTDRIVER_WATCH type
                                     , magi_eventdriver_h *handler
                                     , void *userdata )
{
  struct list *list;
  struct magi_eventdriver_handler *edh;

  if (!ed || !handler)
    return EINVAL;

  edh = mem_zalloc(sizeof(*edh), magi_eventdriver_handler_destructor);
  if (!edh)
    return ENOMEM;

  list = _grab_handler(ed, type);
  if (!list)
    return EINVAL;

  edh->handler = handler;
  edh->userdata = userdata;

  list_append(list, &edh->le, edh);

  return 0;
}

static void magi_eventdriver_destructor(void *data)
{
  struct magi_eventdriver *ed = data;
  for (int i = 0; i < MAGI_EVENTDRIVER_WATCH_MAX; ++i) {
    list_flush( _grab_handler(ed, i) );
  }
}

int magi_eventdriver_alloc(struct magi_eventdriver **edp)
{
  struct magi_eventdriver *ed;

  if (!edp)
    return EINVAL;

  ed = mem_zalloc(sizeof(*ed), magi_eventdriver_destructor);
  if (!ed)
    return ENOMEM;

  for (int i = 0; i < MAGI_EVENTDRIVER_WATCH_MAX; ++i) {
    list_init( _grab_handler(ed, i) );
  }

  *edp = ed;

  return 0;
}
