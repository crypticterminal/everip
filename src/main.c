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

#ifdef SOLARIS
#define __EXTENSIONS__ 1
#endif
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_GETOPT
#include <getopt.h>
#endif
#include <re.h>
#include <everip.h>

#if defined(HAVE_GENDO)
#include <gendo.h>
#else
#define GENDO_OPTIONS_STR ""
#define GENDO_OPTIONS
#endif

static void signal_handler(int sig)
{
  static bool term = false;

  if (term) {
    mod_close();
    exit(0);
  }

  term = true;
  info("terminated by signal %d\n", sig);
  main_goodbye();
}

static int cmd_quit(struct re_printf *pf, void *unused)
{
  (void)pf;
  (void)unused;
  main_goodbye();
  return 0;
}

static const struct cmd cmdv[] = {
  {"quit", 'q', 0, "Quit", cmd_quit},
};

int main(int argc, char *argv[])
{
  int err;
  uint8_t utility = 0;
  uint8_t secret_key[32];
  uint16_t port_default = 1988;

#if 0 && !defined(WIN32) && !defined(CYGWIN)
  if(getuid() != 0 || geteuid() != 0) {
    error( "EVER/IP(R) requires you to be a super user on %s/%s.\n"
         , sys_os_get(), sys_arch_get());
    info("Hint: Please run `everip` again as a super user to continue.\n");
    return EINVAL;
  }
#endif

  (void)sys_coredump_set(false);

  err = libre_init();
  if (err)
    goto out;

#ifdef HAVE_GETOPT
  for (;;) {
    const int c = getopt(argc, argv, GENDO_OPTIONS_STR "vk:U:");
    if (0 > c)
      break;

    switch (c) {

      GENDO_OPTIONS

      case 'v':
        log_enable_debug(true);
        break;

      case 'k': /* key */
        str_hex(secret_key, 32, optarg);
        break;

      case 'U': /* udp port */
        port_default = atoi(optarg);
        break;

      default:
        break;
    }
  }
#else
  (void)argc;
  (void)argv;
#endif

  if (err)
    goto out;

  if (utility)
    goto out;

  (void)re_fprintf( stderr
          , "\nStarting connectFree(R) EVER/IP(R) for %s/%s [%s]\n"
            "Copyright 2016-2017 Kristopher Tate and connectFree Corporation.\n"
            "All Rights Reserved. Protected by International Patent Treaties.\n"
            "More information: select \"Legal Information\" from the main menu.\n"
          , sys_os_get(), sys_arch_get()
          , EVERIP_VERSION);

#if defined(GITVERSION)
  (void)re_fprintf(stderr, "GIT Version: " GITVERSION "\n");
#endif

  (void)re_fprintf(stderr, "\n");

  err = everip_init( secret_key, port_default );
  if (err) {
    warning("main: core init failed (%m)\n", err);
    goto out;
  }

  err = cmd_register(everip_commands(), cmdv, ARRAY_SIZE(cmdv));
  if (err)
    goto out;

  info("EVER/IP(R) is READY.\n\n");

  err = re_main(signal_handler);

 out:
  cmd_unregister(everip_commands(), cmdv);
  everip_close();
  debug("main: unloading modules..\n");
  mod_close();
  libre_close();

  /* Check for memory leaks */
  tmr_debug();
  mem_debug();
  return err;
}
