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

#define TOL_VERSION_ID 1U

#define TOL_ZONE_COUNT 1
#define TOL_ROUTE_LENGTH 16 /* 128 bytes */

#define TOL_MAINTAIN_MS 3000
#define TOL_MAINTAIN_CHILDREN_MS 3000
#define TOL_DHT_TIMEOUT_MS 15000

struct tol_peer;
struct this_module;

struct tol_dhti {
  struct le le;
  uint8_t binlen;
  uint8_t binrep[TOL_ROUTE_LENGTH];
  uint8_t everip_addr[EVERIP_ADDRESS_LENGTH];
  uint8_t public_key[NOISE_PUBLIC_KEY_LEN];

  struct tmr tmr;
};

struct tol_neighbor {
  struct le le_mod; /* this_module */
  uint8_t everip[EVERIP_ADDRESS_LENGTH];

  /* zone */
  struct {
    uint8_t binlen;
    uint8_t binrep[TOL_ROUTE_LENGTH];
    uint16_t child_id;
    bool child_id_chosen;
    struct le le_child;
  } z[TOL_ZONE_COUNT];
};


struct tol_peer {
  struct conduit_peer cp;
  struct this_module *ctx;

  uint8_t zoneid;
  uint8_t binlen;
  uint8_t binrep[TOL_ROUTE_LENGTH];

  struct le le_mod;
  struct le le_mod_addr;
};

struct tol_zone {
  bool active;
  uint8_t root[EVERIP_ADDRESS_LENGTH];
  struct tol_neighbor *parent;

  uint8_t binlen;
  uint8_t binrep[TOL_ROUTE_LENGTH];

  struct list children;
  uint32_t child_refresh_count;

  struct list dhti_all;
};

struct this_module {
  struct tmr tmr_maintain;
  struct tmr tmr_maintain_children;

  uint8_t my_everip[EVERIP_ADDRESS_LENGTH];
  uint8_t my_public_key[NOISE_PUBLIC_KEY_LEN];

  struct tol_zone zone[TOL_ZONE_COUNT];

  uint16_t child_counter;

  struct list all_neighbors;


  /* conduit stuff */
  struct conduit *conduit;
  struct list peers;
  struct hash *peers_addr;

};

/**/

struct tol_peer *tol_peer_lookup_byeverip( struct this_module *mod
                                         , const uint8_t everip[EVERIP_ADDRESS_LENGTH] );

int tol_peer_alloc( struct tol_peer **tpp
                  , struct this_module *mod
                  , const uint8_t everip[EVERIP_ADDRESS_LENGTH] );

/**/

int tol_conduit_debug(struct re_printf *pf, void *arg);

int tol_conduit_search( const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH]
                      , void *arg );

int tol_conduit_sendto_virtual( struct conduit_peer *peer
                              , struct mbuf *mb
                              , void *arg );

int tol_conduit_incoming( struct this_module *mod, struct conduit_peer *cp, struct mbuf *mb );

/**/

int tol_command_send_dht_notify( const uint8_t everip_forward[EVERIP_ADDRESS_LENGTH]
                               , const uint8_t everip_record[EVERIP_ADDRESS_LENGTH]
                               , const uint8_t public_key[NOISE_PUBLIC_KEY_LEN]
                               , uint8_t zoneid
                               , uint8_t root[EVERIP_ADDRESS_LENGTH]
                               , uint8_t binrep[TOL_ROUTE_LENGTH]
                               , uint8_t binlen );

int tol_command_send_dht_found( const uint8_t everip_forward[EVERIP_ADDRESS_LENGTH]
                              , const uint8_t everip_aquire[EVERIP_ADDRESS_LENGTH]
                              , const uint8_t public_key[NOISE_PUBLIC_KEY_LEN]
                              , uint8_t zoneid
                              , uint8_t root[EVERIP_ADDRESS_LENGTH]
                              , uint8_t from_binrep[TOL_ROUTE_LENGTH]
                              , uint8_t from_binlen
                              , uint8_t record_binrep[TOL_ROUTE_LENGTH]
                              , uint8_t record_binlen );

int tol_command_send_dht_aquire( const uint8_t everip_forward[EVERIP_ADDRESS_LENGTH]
                               , const uint8_t everip_aquire[EVERIP_ADDRESS_LENGTH]
                               , uint8_t zoneid
                               , uint8_t root[EVERIP_ADDRESS_LENGTH]
                               , uint8_t from_binrep[TOL_ROUTE_LENGTH]
                               , uint8_t from_binlen );

int tol_command_cb_dht( struct this_module *mod
                      , struct magi_melchior_rpc *rpc );

int tol_command_send_child( struct tol_neighbor *tn
                          , uint8_t zoneid );

int tol_command_cb_child( struct this_module *mod
                        , struct magi_melchior_rpc *rpc );

int tol_command_send_zone( struct this_module *mod
                         , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH] );

int tol_command_cb_zone( struct this_module *mod
                       , struct magi_melchior_rpc *rpc );

int tol_command_callback( struct magi_melchior_rpc *rpc
                        , struct pl *method
                        , void *arg );


/**/

struct tol_neighbor *
tol_neighbor_find_byeverip( struct this_module *mod
                          , const uint8_t everip[EVERIP_ADDRESS_LENGTH] );

int tol_neighbor_alloc( struct tol_neighbor **tnp
                      , struct this_module *mod
                      , const uint8_t everip[EVERIP_ADDRESS_LENGTH] );

/**/

int tol_everip_for_route( struct this_module *mod
                        , const uint8_t route[TOL_ROUTE_LENGTH]
                        , uint8_t everip_addr[EVERIP_ADDRESS_LENGTH]);

uint16_t tol_get_childid(struct this_module *mod);

int tol_zone_reset(struct this_module *mod, struct tol_zone *zone);

