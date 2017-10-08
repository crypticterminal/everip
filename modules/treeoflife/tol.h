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

#define TOL_ZONE_COUNT 1
#define TOL_ROUTE_LENGTH 16 /* 128 bytes */

#define TOL_MAINTAIN_MS 5000
#define TOL_MAINTAIN_CHILDREN_MS 5000


struct tol_peer;
struct this_module;

struct tol_neighbor {
  struct le le_mod; /* this_module */
  uint8_t everip[EVERIP_ADDRESS_LENGTH];

  /* zone */
  struct {
    uint8_t binlen;
    uint8_t binrep[TOL_ROUTE_LENGTH];
    uint16_t child_id;
    struct le le_child;
  } z[TOL_ZONE_COUNT];
};

#if 0
struct tol_peer {
  struct conduit_peer cp;

  struct this_module *ctx;

  struct le le_peer;
  struct le le_zone[TOL_ZONE_COUNT];
  struct le le_idx_addr;
};
#endif

struct tol_zone {
  uint8_t root[EVERIP_ADDRESS_LENGTH];
  struct tol_neighbor *parent;

  uint8_t binlen;
  uint8_t binlen_calc;
  uint8_t binrep[TOL_ROUTE_LENGTH];

  struct list children;
  uint32_t child_refresh_count;
};

struct this_module {
  struct conduit *conduit;
  struct tmr tmr_maintain;
  struct tmr tmr_maintain_children;

  uint8_t my_everip[EVERIP_ADDRESS_LENGTH];
  uint8_t my_public_key[NOISE_PUBLIC_KEY_LEN];

  struct tol_zone zone[TOL_ZONE_COUNT];

  uint16_t child_counter;

  struct list all_neighbors;

};

int tol_command_callback( struct magi_melchior_rpc *rpc
                        , struct pl *method
                        , void *arg );

int tol_command_send_zone( struct this_module *mod
                         , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH] );


/**/

struct tol_neighbor *
tol_neighbor_find_byeverip( struct this_module *mod
                          , const uint8_t everip[EVERIP_ADDRESS_LENGTH] );

int tol_neighbor_alloc( struct tol_neighbor **tnp
                      , struct this_module *mod
                      , const uint8_t everip[EVERIP_ADDRESS_LENGTH] );

/**/

