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

static void atfield_item_destructor(void *data)
{
  struct atfield_item *ati = data;
  list_unlink(&ati->le);
}

static struct atfield_item * atfield_get( struct atfield *at
                                        , uint8_t ip6[ADDR_SEARCH_TARGET_SIZE] )
{
  struct le *le;
  struct atfield_item *ati;
  LIST_FOREACH(&at->list, le) {
    ati = le->data;
    if (!memcmp(ati->ip6.b, ip6, ADDR_SEARCH_TARGET_SIZE)) {
      return ati;
    }
  }
  return NULL;
}


/* 0 == black; 1 == white */
static int atfield_wb_autoset( struct atfield *at )
{
  struct le *le;
  struct atfield_item *ati;

  LIST_FOREACH(&at->list, le) {
    ati = le->data;
    if (ati->mode & ATFIELD_MODE_WHITE) {
      atfield_gowhite(everip_atfield(), true);
      return 1;
    }
  }

  atfield_gowhite(everip_atfield(), false);
  return 0;
}

int atfield_add( struct atfield *at
               , uint8_t ip6[ADDR_SEARCH_TARGET_SIZE]
               , uint8_t mode )
{
  struct atfield_item *ati;

  if (!at || !ip6 || !mode)
    return EINVAL;

  if (atfield_get(at, ip6)) {
    return EINVAL;
  }

  ati = mem_zalloc(sizeof(*ati), atfield_item_destructor);
  if (!ati)
    return ENOMEM;

  memcpy(&ati->ip6.b, ip6, ADDR_SEARCH_TARGET_SIZE);

  ati->mode = mode;
  list_append(&at->list, &ati->le, ati);

  atfield_wb_autoset( at );

  return 0;
}

uint8_t atfield_check( struct atfield *at
                     , uint8_t ip6[ADDR_SEARCH_TARGET_SIZE] )
{
  struct le *le;
  struct atfield_item *ati;
  LIST_FOREACH(&at->list, le) {
    ati = le->data;
    if (!memcmp(ati->ip6.b, ip6, ADDR_SEARCH_TARGET_SIZE)) {
      if (at->white) {
        return ati->mode & ATFIELD_MODE_WHITE ? 1 : 0;
      } else {
        return ati->mode & ATFIELD_MODE_BLACK ? 0 : 1;
      }
    }
  }
  return at->white ? 0 : 1;
}

int atfield_remove( struct atfield *at
                  , uint8_t ip6[ADDR_SEARCH_TARGET_SIZE] )
{
  struct le *le;
  struct atfield_item *ati;

  if (!at || !ip6)
    return EINVAL;

  LIST_FOREACH(&at->list, le) {
    ati = le->data;
    if (!memcmp(ati->ip6.b, ip6, ADDR_SEARCH_TARGET_SIZE)) {
      if (ati->mode & ATFIELD_MODE_LOCKL)
        return EINVAL;
      ati = mem_deref(ati);
      return 0;
    }
  }
  return 0;
}

void atfield_gowhite( struct atfield *at, bool gowhite)
{
  if (!at)
    return;
  at->white = gowhite ? 1 : 0;
}

static void atfield_destructor(void *data)
{
  struct atfield *at = data;
  list_flush(&at->list);
}

int atfield_debug(struct re_printf *pf, const struct atfield *atfield)
{
  int err;
  struct le *le;
  if (!atfield)
    return 0;

  err  = re_hprintf(pf, "[A.T. FIELD]\n");
  err  = re_hprintf(pf, "[PATTERN: %s]\n", atfield->white ? "WHITE" : "BLACK");

  if (!atfield->list.head) {
    err  = re_hprintf(pf, "    ■ {NO ITEMS REGISTERED}\n");
  }

  struct atfield_item *ati;
  LIST_FOREACH(&atfield->list, le) {
      ati = le->data;
      err  = re_hprintf( pf
               , "  [%W%s%s%s]\n"
               , ati->ip6.b, ADDR_SEARCH_TARGET_SIZE
               , ati->mode & ATFIELD_MODE_BLACK ? " BLACK " : ""
               , ati->mode & ATFIELD_MODE_WHITE ? " WHITE " : ""
               , ati->mode & ATFIELD_MODE_LOCKL ? " LOCKED " : "");
  }

  return err;
}

int atfield_init( struct atfield **atfieldp )
{
  struct atfield *at;

  if (!atfieldp)
    return EINVAL;

  at = mem_zalloc(sizeof(*at), atfield_destructor);
  if (!at)
    return ENOMEM;

  list_init(&at->list);

  *atfieldp = at;

  return 0;
}
