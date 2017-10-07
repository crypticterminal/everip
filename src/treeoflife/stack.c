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
#include <stdlib.h> /* abs */

uint8_t stack_height_get(const uint8_t *binrep)
{
  return binrep[0];
}

void stack_height_set(uint8_t *binrep, uint8_t height)
{
  if (!height) return;
  binrep[0] = height;
}

uint16_t stack_calc_size(uint8_t *binrep, uint8_t *height)
{
  int pos; /* size in bytes */
  uint8_t size;
  size = stack_height_get(binrep);
  if (height) *height = size;
  if (!size) return 1;
  pos = 1;
  while (size--) {
    if (binrep[pos] == 0xFE) { /* 11111110 */
      pos += 8;
    } else if ((binrep[pos] & 0xFE) == 0xFC) { /* 1111110x */
      pos += 7;
    } else if ((binrep[pos] & 0xFC) == 0xF8) { /* 111110xx */
      pos += 6;
    } else if ((binrep[pos] & 0xF8) == 0xF0) { /* 11110xxx */
      pos += 5;
    } else if ((binrep[pos] & 0xF0) == 0xE0) { /* 1110xxxx */
      pos += 4;
    } else if ((binrep[pos] & 0xE0) == 0xC0) { /* 110xxxxx */
      pos += 3;
    } else if ((binrep[pos] & 0xC0) == 0x80) { /* 10xxxxxx */
      pos += 2;
    } else if ((binrep[pos] & 0x80) == 0x00) { /* 0xxxxxxx */
      pos += 1; /* our data is included here */
    }
  }

  return pos;
}

size_t stack_layer_add(uint8_t *binrep, uint64_t nodeid)
{
  size_t size;
  uint8_t height;
  size = stack_calc_size(binrep, &height);
  int layersize;
  uint8_t layer_data[8] = {0};

  /* calculate size of the slot that we want to create */

  if (nodeid <= 0x7f) {
    layer_data[0] = nodeid;
    layersize = 1;
  } else {
    return 0;
  }

  if (size + layersize > 128)
    return 0;

  memcpy(&binrep[size], layer_data, layersize);

  /* set new size header */
  stack_height_set(binrep, height + 1);

  return size + layersize;
}

struct stack_needle {
  int pos;
  uint8_t height;
  uint8_t start;
  uint8_t stop;
  const uint8_t *binrep;
  int i;
  bool setup;
  bool inloop;
  bool end;
  int data;
};

int stack_step(struct stack_needle *needle)
{
  uint8_t b;
  if (needle->end) return 1;
  if (!needle->setup) {
    needle->setup = true;
    needle->height = stack_height_get(needle->binrep);
    needle->pos = 1;
  }
  if (!needle->height) {
    if (++needle->i == 1) {
      needle->end = true;
    }
    needle->data = 0;
    return 0;
  }
  if (needle->inloop) {
    goto loop;
  }
/*main*/
  {
    if (needle->binrep[needle->pos] == 0xFE) { /* 11111110 */
      needle->stop = 8;
    } else if ((needle->binrep[needle->pos] & 0xFE) == 0xFC) { /* 1111110x */
      needle->stop = 7;
    } else if ((needle->binrep[needle->pos] & 0xFC) == 0xF8) { /* 111110xx */
      needle->stop = 6;
    } else if ((needle->binrep[needle->pos] & 0xF8) == 0xF0) { /* 11110xxx */
      needle->stop = 5;
    } else if ((needle->binrep[needle->pos] & 0xF0) == 0xE0) { /* 1110xxxx */
      needle->stop = 4;
    } else if ((needle->binrep[needle->pos] & 0xE0) == 0xC0) { /* 110xxxxx */
      needle->stop = 3;
    } else if ((needle->binrep[needle->pos] & 0xC0) == 0x80) { /* 10xxxxxx */
      needle->stop = 2;
    } else if ((needle->binrep[needle->pos] & 0x80) == 0x00) { /* 0xxxxxxx */
      needle->stop = 1; /* our data is included here */
    }

    needle->start = 0;
    needle->inloop = true;
    needle->i = needle->stop;
loop:
    //while (needle->i < (needle->stop*8)) {
    b = b_val(&(needle->binrep[needle->pos]), needle->i);
    //error("HEIGHT = %u; POS=%u; i=%u; b=%u\n", needle->height, needle->pos, needle->i, b);
    ++needle->i;
    //needle->start = 1;
    needle->data = b ? needle->height : -1 * needle->height;
    goto check_end;
    //};
  }

check_end:
  if ( needle->i >= (needle->stop*8) ) {
    needle->inloop = false;
    needle->pos += needle->stop;
    --needle->height;
    if (!needle->height) {
    needle->end = true;
    }
  }
  return 0;
}

#if 0
static int stack_link_count(uint8_t binrep[ROUTE_LENGTH])
{
  int count = 0;
  struct stack_needle needle;
  memset(&needle, 0, sizeof(struct stack_needle));
  needle.binrep = binrep;
  while (stack_step(&needle)) {
  count++;
  }
  return count;
}
#endif

int stack_linf_diff(const uint8_t left[ROUTE_LENGTH], const uint8_t right[ROUTE_LENGTH], int *places)
{
  int i = 0;
  int tmp = 0;
  int out = 0;
  struct stack_needle lneedle;
  struct stack_needle rneedle;

  memset(&lneedle, 0, sizeof(struct stack_needle));
  memset(&rneedle, 0, sizeof(struct stack_needle));

  lneedle.binrep = left;
  rneedle.binrep = right;

  stack_step(&lneedle);
  stack_step(&rneedle);
  tmp = abs(lneedle.data - rneedle.data);
  if (tmp > out)
    out = tmp;
  i++;
  while (!lneedle.end && !rneedle.end ) {
    if (stack_step(&lneedle))
      break;
    if (stack_step(&rneedle))
      break;
    /*debug("lval = %d; rval = %d\n", lval, rval);*/
    tmp = abs(lneedle.data - rneedle.data);
    if (tmp > out)
      out = tmp;
    i++;
  }
  if (places)
    *places = i;
  return out;
}

int stack_debug(struct re_printf *pf, const uint8_t *binrep)
{
  int err = 0;
  struct stack_needle needle;
  memset(&needle, 0, sizeof(struct stack_needle));
  needle.binrep = binrep;
  err |= re_hprintf(pf, "[");
  stack_step(&needle);
  err |= re_hprintf(pf, "%s%d", (needle.data>0?"+":""), needle.data);
  while (!needle.end) {
  if (stack_step(&needle))
    break;
    err |= re_hprintf(pf, "%s%d", (needle.data>0?"+":""), needle.data);
  }

  err |= re_hprintf(pf, "]");

  return err;
}


