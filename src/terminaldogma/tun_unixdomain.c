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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/stat.h>

struct tunif_un {
  struct tunif pub;
  struct sockaddr_un claddr;
};

static struct csock *_from_terminaldogma( struct csock *csock
                                        , enum CSOCK_TYPE type
                                        , void *data )
{
  ssize_t n;
  struct mbuf *mb = data;
  struct tunif *tun_pub = container_of(csock, struct tunif, cs_tmldogma);
  struct tunif_un *tun = container_of(tun_pub, struct tunif_un, pub);

  socklen_t len;

  if (!csock || type != CSOCK_TYPE_DATA_MB || !mb)
    return NULL;

  if (mbuf_get_left(mb) < 4) {
    return NULL;
  }

  /* hack; we only support ipv6 */
  ((uint16_t*)(void *)mbuf_buf(mb))[0] = 0;
  ((uint16_t*)(void *)mbuf_buf(mb))[1] = 7680;

  /*error("attempting send to: %s\n", tun->claddr.sun_path);*/

  len = sizeof(struct sockaddr_un);
  n = sendto( tun_pub->fd
            , mbuf_buf(mb)
            , mbuf_get_left(mb)
            , 0
            , (struct sockaddr*)&tun->claddr
            , len);

  if (n < 0) {
    goto out;
  }

out:
  return NULL;
}

static void tun_read_handler(int flags, void *arg)
{
  struct tunif_un *tun = arg;
  ssize_t n;
  socklen_t len;

  struct mbuf *mb = mbuf_alloc(EVER_OUTWARD_MBE_LENGTH*2);

  (void)flags;

  if (!mb)
    return;

  /*error("got somethin: [%s]\n", tun->claddr.sun_path);*/

  len = sizeof(struct sockaddr_un);
  memset(&tun->claddr, 0, len);
  n = recvfrom( tun->pub.fd
              , mb->buf + EVER_OUTWARD_MBE_POS
              , mb->size - EVER_OUTWARD_MBE_POS
              , 0
              , (struct sockaddr*)&tun->claddr
              , &len);

  if (n < 0) {
    goto out;
  }

  mb->pos = EVER_OUTWARD_MBE_POS;
  mb->end = n + EVER_OUTWARD_MBE_POS;

  (void)mbuf_resize(mb, mb->end);

  if (mbuf_get_left(mb) < 4) {
    goto out;
  }

  uint16_t af_be = ((uint16_t*)(void *)mbuf_buf(mb))[1];

  if (af_be != 7680) { /* only handle ipv6 */
    goto out;
  }

  ((uint16_t*)(void *)mbuf_buf(mb))[0] = 0;
  ((uint16_t*)(void *)mbuf_buf(mb))[1] = arch_htobe16(0x86DD);

  csock_forward(&tun->pub.cs_tmldogma, CSOCK_TYPE_DATA_MB, mb);

out:
  mem_deref(mb);

}

static int tunif_un_checkpath(const char *path)
{
  struct stat s;
  if (0 == stat(path, &s)) {
    if ((s.st_mode & S_IFMT) == S_IFSOCK) {
      if (unlink(path) != 0) {
        return errno;
      }
    } else {
      return EEXIST;
    }
  } else {
    if (errno != ENOENT)
      return errno;
  }
  return 0;
}

static void tunif_destructor(void *data)
{
  struct tunif_un *tun = data;
  if (tun->pub.fd > 0) {
    fd_close(tun->pub.fd);
    (void)close(tun->pub.fd);
  }
}

int tunif_un_init( struct tunif **tunifp
                 , const char *socket_path )
{
  int err = 0;
  struct sockaddr_un name;

  struct tunif_un *tunif;

  if (!tunifp)
    return EINVAL;

  memset(&name, 0, sizeof(struct sockaddr_un));

  tunif = mem_zalloc(sizeof(*tunif), tunif_destructor);
  if (!tunif) {
    tunif = mem_deref(tunif);
    return ENOMEM;
  }

  tunif->pub.fd = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (tunif->pub.fd < 0) {
    tunif = mem_deref(tunif);
    return EINVAL;
  }

  /* Create name. */

  err = tunif_un_checkpath( socket_path );
  if (err)
    goto err;

  name.sun_family = AF_UNIX;
  strcpy(name.sun_path, socket_path);

  if (bind(tunif->pub.fd, (struct sockaddr *)&name, sizeof(struct sockaddr_un)))
  {
    err = errno;
    goto err;
  }
  
  str_ncpy(tunif->pub.name, socket_path, TUN_IFNAMSIZ);

  net_sockopt_blocking_set(tunif->pub.fd, false);

  err = fcntl(tunif->pub.fd, F_SETFD, FD_CLOEXEC);
  if (err) {
    goto err;
  }

  err = fd_listen( tunif->pub.fd
                 , FD_READ
                 , tun_read_handler
                 , tunif);
  if (err) {
    goto err;
  }

  tunif->pub.cs_tmldogma.send = _from_terminaldogma;

  *tunifp = &tunif->pub;

  return err;

err:
  tunif = mem_deref(tunif);
  return err;

}
