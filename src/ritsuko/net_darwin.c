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

#include <pthread.h>

#include <SystemConfiguration/SystemConfiguration.h>

struct netevents_runner {
  bool run;
  struct mqueue *mq;
  pthread_t thread;
  CFRunLoopRef cfrl_ref;
};

static void netevents_runner_thread_cb(SCDynamicStoreRef store, CFArrayRef changedKeys, void *arg)
{
  struct netevents_runner *ner = arg;
  mqueue_push(ner->mq, 1, NULL);
}

static void *netevents_runner_thread(void *arg)
{
  struct netevents_runner *ner = arg;
  
  /* here we go jumping into the weird world of apple */
  SCDynamicStoreRef sc_ref = NULL;
  CFRunLoopSourceRef run_ref = NULL;
  CFMutableArrayRef keys = NULL, patterns = NULL;
  CFStringRef key = NULL;

  SCDynamicStoreContext context = {
        0 // version
      , (void *)ner // user data
      , NULL // retain
      , NULL // release
      , NULL // copyDescription
    };

  ner->cfrl_ref = CFRunLoopGetCurrent();

  sc_ref = SCDynamicStoreCreate(kCFAllocatorDefault, CFSTR("network.ever"), &netevents_runner_thread_cb, &context);
  if (sc_ref == NULL) {
    error("netevents_runner: could not create dynamic store;\n");
    goto out;
  }

  keys = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
  patterns = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);

  key = SCDynamicStoreKeyCreateNetworkGlobalEntity(kCFAllocatorDefault, kSCDynamicStoreDomainState, kSCEntNetIPv4);
  CFArrayAppendValue(keys, key);
  CFRelease(key);

  key = SCDynamicStoreKeyCreateNetworkGlobalEntity(kCFAllocatorDefault, kSCDynamicStoreDomainState, kSCEntNetIPv6);
  CFArrayAppendValue(keys, key);
  CFRelease(key);

  key = SCDynamicStoreKeyCreateNetworkInterfaceEntity(kCFAllocatorDefault, kSCDynamicStoreDomainState, kSCCompAnyRegex, kSCEntNetIPv4);
  CFArrayAppendValue(patterns, key);
  CFRelease(key);

  key = SCDynamicStoreKeyCreateNetworkInterfaceEntity(kCFAllocatorDefault, kSCDynamicStoreDomainState, kSCCompAnyRegex, kSCEntNetIPv6);
  CFArrayAppendValue(patterns, key);
  CFRelease(key);

  key = SCDynamicStoreKeyCreateNetworkGlobalEntity(kCFAllocatorDefault, kSCDynamicStoreDomainState, kSCEntNetDNS);
  CFArrayAppendValue(keys, key);
  CFRelease(key);

  if(!SCDynamicStoreSetNotificationKeys(sc_ref, (CFArrayRef)keys, (CFArrayRef)patterns)) {
    error("netevents_runner: could not create dynamic store notification keys;\n");
    goto out;
  }

  run_ref = SCDynamicStoreCreateRunLoopSource(NULL, sc_ref, 0);
  if(run_ref == NULL) {
    error("netevents_runner: could not create dynamic runloop source;\n");
    goto out;
  }

  CFRunLoopAddSource(ner->cfrl_ref, run_ref, kCFRunLoopDefaultMode);

  while (ner->run) {
    CFRunLoopRun();
  }

  CFRunLoopRemoveSource(ner->cfrl_ref, run_ref, kCFRunLoopDefaultMode);

out:
  CFRelease(run_ref);
  CFRelease(keys);
  CFRelease(patterns);
  return NULL;
}

static void netevents_runner_destructor(void *data)
{
  struct netevents_runner *ner = data;

  if (ner->run) {
    debug("netevents_runner: stopping thread\n");
    ner->run = false;
    CFRunLoopStop(ner->cfrl_ref);
    (void)pthread_join(ner->thread, NULL);
  }

  ner->mq = mem_deref( ner->mq );

}

int netevents_runner_alloc( struct netevents_runner **nerp, struct mqueue *mq )
{
  int err = 0;
  struct netevents_runner *ner;

  if (!nerp || !mq)
    return EINVAL;

  ner = mem_zalloc(sizeof(*ner), netevents_runner_destructor);
  if (!ner) {
    return ENOMEM;
  }

  ner->mq = mq;
  mem_ref( ner->mq );

  ner->run = true;
  err = pthread_create(&ner->thread, NULL, netevents_runner_thread, ner);
  if (err) {
    ner->run = false;
    goto out;
  }

out:
  if (err) {
    ner = mem_deref(ner);
  } else {
    *nerp = ner;
  }
  return err;
}

/* platform stuff*/

int netevents_platform_getkind( const char* ifname
                              , enum NETEVENTS_IFACE_KIND *kindp )
{
  int err = 0;
  err = re_regex(ifname, strlen(ifname), "lo[a-z0-9]+", NULL);
  if (!err) {
    *kindp = NETEVENTS_IFACE_KIND_LOOPBACK;
    goto out;
  }

  err = re_regex(ifname, strlen(ifname), "utun[a-z0-9]+", NULL);
  if (!err) {
    *kindp = NETEVENTS_IFACE_KIND_IPTUNNEL;
    goto out;
  }

  /* special detection for wireless? */


  /* default should be ethernet */
  err = re_regex(ifname, strlen(ifname), "en[a-z0-9]+", NULL);
  if (!err) {
    *kindp = NETEVENTS_IFACE_KIND_ETHERNET;
    goto out;
  }

  *kindp = NETEVENTS_IFACE_KIND_UNKNOWN;
  err = 0;

out:
  return err;
}

