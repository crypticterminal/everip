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

#include <sodium.h>

#if defined(HAVE_GENDO)
#include <gendo.h>
#endif

static struct everip {
    /* ritsuko */
    struct network *net;
    struct commands *commands;

    /* geofront */
    struct conduits *conduits;

    /* central dogma */
    struct caengine *caengine;

    /* terminal dogma */
    struct tmldogma *tmldogma;
    struct tunif *tunif;

    struct netevent *netevent;

    /* treeoflife */
    struct atfield *atfield;
    struct treeoflife *treeoflife;

    uint16_t udp_port;

    char *license_filename;

} everip;

int everip_init(void)
{
    int err;

    memset(&everip, 0, sizeof(struct everip));

    if (sodium_init() == -1) {
        return EINVAL;
    }

    /* Initialise Network */
    err = net_alloc(&everip.net);
    if (err) {
        return err;
    }

    err = cmd_init(&everip.commands);
    if (err)
        return err;

    err = caengine_init(&everip.caengine);
    if (err)
        return err;

#if defined(HAVE_GENDO)
    GENDO_INIT;
#endif

    if (!everip.caengine->activated) {
        error("CAE: could not be activated...\n");
        err = EBADMSG;
        return err;
    }

    caengine_authtoken_add(everip.caengine, "EVERIP", "DEFAULT" );

    if (!everip.udp_port)
        everip.udp_port = 1988;

    /* atfield */
    err = atfield_init( &everip.atfield );
    if (err) {
      error("everip_init: atfield_init\n");
      return err;
    }

    /* tree of life */
    err = treeoflife_init( &everip.treeoflife
                         , everip.caengine->my_ipv6+1 );
    if (err) {
      error("everip_init: treeoflife_init\n");
      return err;
    }

    err = conduits_init( &everip.conduits
                       , everip.treeoflife );
    if (err) {
      error("everip_init: conduits_init\n");
      return err;
    }

    err = netevent_init( &everip.netevent );
    if (err) {
      error("everip_init: netevent_init\n");
      return err;
    }

    struct sa tmp_sa;
    sa_init(&tmp_sa, AF_INET6);
    sa_set_in6(&tmp_sa, everip.caengine->my_ipv6, 0);

    info("UNLOCKING LICENSED EVER/IP(R) ADDRESS\n%j\n", &tmp_sa, 16);

#if 1
    err = tunif_init( &everip.tunif );
    if (err) {
      error("everip_init: tunif_init\n");
      return err;
    }

    info("tunnel device: %s init;\n", everip.tunif->name);


    for (int i = 0; i < 10; ++i) {
      err = net_if_setaddr( everip.tunif->name
                          , &tmp_sa
                          , 8 );
      if (!err) break;
      sys_msleep(10);
    }

    if (err) {
      error("everip_init: net_if_setaddr\n");
      return err;
    }

    for (int i = 0; i < 10; ++i) {
      err = net_if_setmtu( everip.tunif->name
                         , 1304);
      if (!err) break;
      sys_msleep(10);
    }

    if (err) {
      error("everip_init: net_if_setmtu\n");
      return err;
    }

    conduits_connect_tunif(everip.conduits, &everip.tunif->tmldogma_cs);
#endif

#if !defined(WIN32) && !defined(CYGWIN)
    module_preload("stdio");
#else
    module_preload("wincon");
#endif
    module_preload("dcmd");

    /* wui: web ui*/
    module_preload("wui");

    /* conduits*/
    module_preload("udp");
    module_preload("eth");

#if defined(HAVE_GENDO)
    GENDO_MID;
#endif

    return 0;
}


void everip_close(void)
{

#if defined(HAVE_GENDO)
    GENDO_DEINIT;
#endif

    everip.netevent = mem_deref(everip.netevent);

    /* reverse from init */
    everip.tunif = mem_deref(everip.tunif);
    everip.conduits = mem_deref(everip.conduits);
    everip.caengine = mem_deref(everip.caengine);
    everip.commands = mem_deref(everip.commands);
    everip.net = mem_deref(everip.net);
    everip.atfield = mem_deref(everip.atfield);
    everip.treeoflife = mem_deref(everip.treeoflife);

    everip.license_filename = mem_deref(everip.license_filename);
}


struct network *everip_network(void)
{
    return everip.net;
}

struct commands *everip_commands(void)
{
    return everip.commands;
}

struct caengine *everip_caengine(void)
{
    return everip.caengine;
}

struct conduits *everip_conduits(void)
{
    return everip.conduits;
}

struct atfield *everip_atfield(void)
{
    return everip.atfield;
}

struct treeoflife *everip_treeoflife(void)
{
    return everip.treeoflife;
}

void everip_udpport_set(uint16_t port)
{
    everip.udp_port = port;
}

uint16_t everip_udpport_get(void)
{
    return everip.udp_port;
}

