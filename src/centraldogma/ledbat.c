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

typedef struct UTPSocket utp_socket;
typedef struct struct_utp_context utp_context;

enum {
  UTP_UDP_DONTFRAG = 2, // Used to be a #define as UDP_IP_DONTFRAG
};

enum {
  // socket has reveived syn-ack (notification only for outgoing connection completion)
  // this implies writability
  UTP_STATE_CONNECT = 1,
  // socket is able to send more data
  UTP_STATE_WRITABLE = 2,
  // connection closed
  UTP_STATE_EOF = 3,
  // socket is being destroyed, meaning all data has been sent if possible.
  // it is not valid to refer to the socket after this state change occurs
  UTP_STATE_DESTROYING = 4,
};

extern const char *utp_state_names[];

// Errors codes that can be passed to UTP_ON_ERROR callback
enum {
  UTP_ECONNREFUSED = 0,
  UTP_ECONNRESET,
  UTP_ETIMEDOUT,
};

extern const char *utp_error_code_names[];

enum {
  // callback names
  UTP_ON_FIREWALL = 0,
  UTP_ON_ACCEPT = 1,
  UTP_ON_CONNECT = 2,
  UTP_ON_ERROR = 3,
  UTP_ON_READ = 4,
  UTP_ON_OVERHEAD_STATISTICS = 5,
  UTP_ON_STATE_CHANGE = 6,
  UTP_GET_READ_BUFFER_SIZE = 7,
  UTP_ON_DELAY_SAMPLE = 8,
  UTP_GET_UDP_MTU = 9,
  UTP_GET_UDP_OVERHEAD = 10,
  UTP_GET_MILLISECONDS = 11,
  UTP_GET_MICROSECONDS = 12,
  UTP_GET_RANDOM = 13,
  UTP_LOG = 14,
  UTP_SENDTO = 15,
  // context and socket options that may be set/queried
  UTP_LOG_NORMAL = 16,
  UTP_LOG_MTU = 17,
  UTP_LOG_DEBUG = 18,
  UTP_SNDBUF = 19,
  UTP_RCVBUF = 20,
  UTP_TARGET_DELAY = 21,
  UTP_ARRAY_SIZE = 22, // must be last
};

extern const char *utp_callback_names[];

typedef struct {
  utp_context *context;
  utp_socket *socket;
  size_t len;
  uint32_t flags;
  int callback_type;
  const uint8_t *buf;

  union {
    const struct sockaddr *address;
    int send;
    int sample_ms;
    int error_code;
    int state;
  } u1;
  union {
    socklen_t address_len;
    int type;
  } u2;
} utp_callback_arguments;

typedef uint64_t utp_callback_t(utp_callback_arguments *);

// Returned by utp_get_context_stats()
typedef struct {
  uint32_t _nraw_recv[5]; // total packets recieved less than 300/600/1200/MTU bytes fpr all connections (context-wide)
  uint32_t _nraw_send[5]; // total packets sent     less than 300/600/1200/MTU bytes for all connections (context-wide)
} utp_context_stats;

// Returned by utp_get_stats()
typedef struct {
  uint64_t nbytes_recv; // total bytes received
  uint64_t nbytes_xmit; // total bytes transmitted
  uint32_t rexmit;    // retransmit counter
  uint32_t fastrexmit;  // fast retransmit counter
  uint32_t nxmit;   // transmit counter
  uint32_t nrecv;   // receive counter (total)
  uint32_t nduprecv;  // duplicate receive counter
  uint32_t mtu_guess; // Best guess at MTU
} utp_socket_stats;

#define UTP_IOV_MAX 1024

// For utp_writev, to writes data from multiple buffers
struct utp_iovec {
  void *iov_base;
  size_t iov_len;
};

// Public Functions
utp_context *utp_init(int version);
void      utp_destroy(utp_context *ctx);
void      utp_set_callback(utp_context *ctx, int callback_name, utp_callback_t *proc);
void *     utp_context_set_userdata(utp_context *ctx, void *userdata);
void *     utp_context_get_userdata(utp_context *ctx);
int       utp_context_set_option(utp_context *ctx, int opt, int val);
int       utp_context_get_option(utp_context *ctx, int opt);
int       utp_process_udp(utp_context *ctx, const uint8_t *buf, size_t len, const struct sockaddr *to, socklen_t tolen);
int       utp_process_icmp_error(utp_context *ctx, const uint8_t *buffer, size_t len, const struct sockaddr *to, socklen_t tolen);
int       utp_process_icmp_fragmentation(utp_context *ctx, const uint8_t *buffer, size_t len, const struct sockaddr *to, socklen_t tolen, uint16_t next_hop_mtu);
void      utp_check_timeouts(utp_context *ctx);
void      utp_issue_deferred_acks(utp_context *ctx);
utp_context_stats *utp_get_context_stats(utp_context *ctx);
utp_socket *utp_create_socket(utp_context *ctx);
void *    utp_set_userdata(utp_socket *s, void *userdata);
void *    utp_get_userdata(utp_socket *s);
int       utp_setsockopt(utp_socket *s, int opt, int val);
int       utp_getsockopt(utp_socket *s, int opt);
int       utp_connect(utp_socket *s, const struct sockaddr *to, socklen_t tolen);
ssize_t   utp_write(utp_socket *s, void *buf, size_t count);
ssize_t   utp_writev(utp_socket *s, struct utp_iovec *iovec, size_t num_iovecs);
int       utp_getpeername(utp_socket *s, struct sockaddr *addr, socklen_t *addrlen);
void      utp_read_drained(utp_socket *s);
int       utp_get_delays(utp_socket *s, uint32_t *ours, uint32_t *theirs, uint32_t *age);
utp_socket_stats *utp_get_stats(utp_socket *s);
utp_context *utp_get_context(utp_socket *s);
void      utp_close(utp_socket *s);

/**/

struct ledbat {
  utp_context *utp;
  struct list socks;
  struct tmr tmr;

  ledbat_callback_t *callback;
  void *callback_arg;
};

#define LEDBAT_BUF_LIMIT 32U

struct ledbat_buf {
  struct le le;
  struct mbuf *mb;
};

struct ledbat_sock {
  struct le le;
  struct sa laddr;

  struct ledbat *ctx;
  utp_socket *sock;

  ledbat_callback_t *callback;
  void *callback_arg;

  /*struct mbuf *bufs[LEDBAT_BUF_LIMIT];*/

  struct list bufs; /* struct ledbat_buf */

  bool inside_write;

};

static int _ledbat_sock_alloc( struct ledbat_sock **lsockp
                             , struct ledbat *l
                             , utp_socket *socket );


static void ledbat_buf_destructor(void *data)
{
  struct ledbat_buf *lb = data;
  lb->mb = mem_deref( lb->mb );
  list_unlink( &lb->le );
}

static
int ledbat_buf_alloc( struct ledbat_buf **lbp
                    , struct ledbat_sock *lsock
                    , struct mbuf *mb )
{
  int err = 0;
  struct ledbat_buf *lb = NULL;

  if (!lbp || !lsock || !mb)
    return EINVAL;

  lb = mem_zalloc(sizeof(*lb), ledbat_buf_destructor);
  if (!lb)
    return ENOMEM;

  lb->mb = mb;
  mem_ref(lb->mb);

  list_append(&lsock->bufs, &lb->le, lb);

  if (err) {
    lb = mem_deref(lb);
  } else {
    *lbp = lb;
  }
  return err;
}

static bool _ledbat_sock_write_h(struct ledbat_sock *lsock, struct ledbat_buf *lb)
{
  size_t sent;

  if (!lb)
    return true;

  lsock->inside_write = true;
  sent = utp_write(lsock->sock, mbuf_buf(lb->mb), mbuf_get_left(lb->mb));
  lsock->inside_write = false;
  if (sent <= 0) {
    debug("socket no longer writable\n");
    return true;
  }

  mbuf_advance(lb->mb, sent);

  if (0 == mbuf_get_left(lb->mb)) {
    lb = mem_deref( lb );
    
  }

  return false;
}


static int _ledbat_sock_write(struct ledbat_sock *lsock)
{

  if (!lsock)
    return EINVAL;

  if (!lsock->sock)
    return ENOTCONN;

  while (lsock->bufs.head) {
    if (_ledbat_sock_write_h( lsock
                            , (struct ledbat_buf *)lsock->bufs.head->data))
      break;
  }

  return 0;
}

int ledbat_sock_send(struct ledbat_sock *lsock, struct mbuf *mb)
{
  struct ledbat_buf *lb = NULL;

  if (!lsock || !mb)
    return EINVAL;

  /* sometimes we get caught in a virtual loop -- drop these packets */
  if (lsock->inside_write)
    return EALREADY;

  ledbat_buf_alloc(&lb, lsock, mb);

  /* attempt to write-out */
  _ledbat_sock_write(lsock);

  return 0;

}

static void _handle_outside_cb(utp_callback_arguments *a)
{
  struct ledbat *ledbat = NULL;
  struct ledbat_sock *lsock = NULL;
  ledbat_callback_arguments callback_obj;

  memcpy(&callback_obj, a, sizeof(ledbat_callback_arguments));

  if (a->socket)
    lsock = utp_get_userdata(a->socket);

  if (a->socket) {
    if (!lsock || !lsock->callback)
      goto ctx;

    callback_obj.context = lsock->ctx;
    callback_obj.socket = lsock;

    lsock->callback(&callback_obj, lsock->callback_arg);
  }

ctx:

  if (!a->context)
    return;

  ledbat = utp_context_get_userdata(a->context);
  if (!ledbat || !ledbat->callback)
    return;

  callback_obj.context = ledbat;
  callback_obj.socket = lsock;

  if (a->callback_type == LEDBAT_ON_ACCEPT) {
    /* create lsock from accept */
    _ledbat_sock_alloc( &callback_obj.socket
                      , ledbat
                      , a->socket );
  }

  ledbat->callback(&callback_obj, ledbat->callback_arg);
}

static uint64_t callback_log(utp_callback_arguments *a)
{
  debug("log: %s\n", a->buf);
  return 0;
}

static uint64_t callback_sendto(utp_callback_arguments *a)
{
  _handle_outside_cb(a);
  return 0;
}

static uint64_t callback_on_error(utp_callback_arguments *a)
{
  struct ledbat_sock *lsock;
  lsock = utp_get_userdata(a->socket);

  /*error("LEDBAT Error: %s\n", utp_error_code_names[a->u1.error_code]);*/

  if (!lsock) {
    utp_close( a->socket );
    return 0;
  }
  
  /* we have callback, so let them handle it... */
  _handle_outside_cb(a);

  return 0;
}

static uint64_t callback_on_state_change(utp_callback_arguments *a)
{
  utp_socket_stats *stats;
  struct ledbat_sock *lsock;

  debug("state %d: %s\n", a->u1.state, utp_state_names[a->u1.state]);

  switch (a->u1.state) {
    case UTP_STATE_CONNECT:
    case UTP_STATE_WRITABLE:
      lsock = utp_get_userdata(a->socket);
      _ledbat_sock_write( lsock );
      break;

    case UTP_STATE_EOF:
      lsock = utp_get_userdata(a->socket);
      if (!lsock)
        break;
      list_flush( &lsock->bufs );
      break;

    case UTP_STATE_DESTROYING:
      debug("UTP socket is being destroyed; exiting\n");
      stats = utp_get_stats(a->socket);
      if (stats) {
        debug("Socket Statistics:\n");
        debug("    Bytes sent:          %d\n", stats->nbytes_xmit);
        debug("    Bytes received:      %d\n", stats->nbytes_recv);
        debug("    Packets received:    %d\n", stats->nrecv);
        debug("    Packets sent:        %d\n", stats->nxmit);
        debug("    Duplicate receives:  %d\n", stats->nduprecv);
        debug("    Retransmits:         %d\n", stats->rexmit);
        debug("    Fast Retransmits:    %d\n", stats->fastrexmit);
        debug("    Best guess at MTU:   %d\n", stats->mtu_guess);
      } else {
        debug("No socket statistics available\n");
      }
      break;
  }

  _handle_outside_cb(a);

  return 0;
}

static uint64_t callback_on_read(utp_callback_arguments *a)
{
  _handle_outside_cb(a);

  utp_issue_deferred_acks(a->context);
  utp_read_drained(a->socket);
  return 0;
}

static uint64_t callback_on_accept(utp_callback_arguments *a)
{
  debug("Accepted inbound socket %p\n", a->socket);
  _handle_outside_cb(a);
  return 0;
}

static void ledbat_timer(void *data)
{
  struct ledbat *ledbat = data;
  utp_check_timeouts(ledbat->utp);
  utp_issue_deferred_acks(ledbat->utp);
  tmr_start(&ledbat->tmr, 300, ledbat_timer, ledbat);
}

int ledbat_sock_connect( struct ledbat_sock *lsock
                       , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH] )
{
  if (!lsock || !addr_calc_isvalid(everip_addr))
    return EINVAL;

  sa_init(&lsock->laddr, AF_INET6);
  sa_set_in6(&lsock->laddr, everip_addr, 0);

  utp_issue_deferred_acks(lsock->ctx->utp);

  list_flush( &lsock->bufs );

  if (utp_connect( lsock->sock
                 , (const struct sockaddr *)&lsock->laddr.u.in6
                 , lsock->laddr.len))
    return EINVAL;
  return 0;
}

int ledbat_sock_reconnect( struct ledbat_sock *lsock )
{
  if (!lsock)
    return EINVAL;

  if (lsock->sock) {
    utp_set_userdata(lsock->sock, NULL);
    utp_close( lsock->sock );
    lsock->sock = NULL;
  }
  
  lsock->sock = utp_create_socket(lsock->ctx->utp);
  if (!lsock->sock) /* TODO: perhaps handle this better? */
    return EINVAL;

  utp_set_userdata(lsock->sock, lsock);

  list_flush( &lsock->bufs );

  if (utp_connect( lsock->sock
                 , (const struct sockaddr *)&lsock->laddr.u.in6
                 , lsock->laddr.len))
    return EINVAL;

  return 0;
}

void *ledbat_sock_userdata_get( struct ledbat_sock *lsock )
{
  if (!lsock)
    return NULL;
  return lsock->callback_arg;
}

int ledbat_sock_userdata_set( struct ledbat_sock *lsock, void *userdata )
{
  if (!lsock)
    return EINVAL;
  lsock->callback_arg = userdata;
  return 0;
}

int ledbat_sock_callback_register( struct ledbat_sock *lsock
                                 , ledbat_callback_t *callback
                                 , void *userdata )
{
  if (!lsock || !callback)
    return EINVAL;

  lsock->callback = callback;
  lsock->callback_arg = userdata;

  return 0;
}

int ledbat_callback_register( struct ledbat *ledbat
                            , ledbat_callback_t *callback
                            , void *userdata )
{
  if (!ledbat || !callback)
    return EINVAL;

  ledbat->callback = callback;
  ledbat->callback_arg = userdata;

  return 0;
}

static void ledbat_sock_destructor(void *data)
{
  struct ledbat_sock *lsock = data;
  utp_set_userdata(lsock->sock, NULL);
  utp_close( lsock->sock );
  list_unlink( &lsock->le );

  list_flush( &lsock->bufs );

}


static int _ledbat_sock_alloc( struct ledbat_sock **lsockp
                             , struct ledbat *l
                             , utp_socket *socket )
{
  int err = 0;
  struct ledbat_sock *lsock = NULL;

  if (!lsockp || !l)
    return EINVAL;

  lsock = mem_zalloc(sizeof(*lsock), ledbat_sock_destructor);
  if (!lsock)
    return ENOMEM;

  lsock->ctx = l;

  if (socket) { /* for accept */
    lsock->sock = socket;
  } else {
    lsock->sock = utp_create_socket(l->utp);
    if (!lsock->sock)
      goto out;
  }

  utp_set_userdata(lsock->sock, lsock);
  list_append(&l->socks, &lsock->le, lsock);

out:
  if (err)
    lsock = mem_deref( lsock );
  else
    *lsockp = lsock;
  return err;
}

int ledbat_sock_alloc( struct ledbat_sock **lsockp
                     , struct ledbat *l )
{
  return _ledbat_sock_alloc(lsockp, l, NULL);
}

int ledbat_process_incoming( struct ledbat *l
                           , const uint8_t everip_addr[EVERIP_ADDRESS_LENGTH]
                           , struct mbuf *mb )
{
  struct sa laddr;

  if (!l || !everip_addr || !mb)
    return EINVAL;

  sa_init(&laddr, AF_INET6);
  sa_set_in6(&laddr, everip_addr, 0);

  utp_issue_deferred_acks(l->utp);

  if (!utp_process_udp( l->utp
                      , mbuf_buf(mb)
                      , mbuf_get_left(mb)
                      , (struct sockaddr *)&laddr.u.in6
                      , laddr.len ))
    return EBADMSG;
  return 0;
}

static void ledbat_destructor(void *data)
{
  struct ledbat *ledbat = data;
  tmr_cancel(&ledbat->tmr);
  list_flush(&ledbat->socks);
  utp_check_timeouts(ledbat->utp);
  /*utp_context_set_userdata(ledbat->utp, NULL);*/
  utp_destroy(ledbat->utp);
}

int ledbat_alloc( struct ledbat **ledbatp )
{
  int err = 0;
  struct ledbat *ledbat = NULL;

  if (!ledbatp)
    return EINVAL;

  ledbat = mem_zalloc(sizeof(*ledbat), ledbat_destructor);
  if (!ledbat)
    return ENOMEM;

  ledbat->utp = utp_init(2);
  if (!ledbat->utp) {
    err = ENOMEM;
    goto out;
  }

  utp_context_set_userdata(ledbat->utp, ledbat);

  utp_set_callback(ledbat->utp, UTP_LOG, &callback_log);
  utp_set_callback(ledbat->utp, UTP_SENDTO, &callback_sendto);
  utp_set_callback(ledbat->utp, UTP_ON_ERROR, &callback_on_error);
  utp_set_callback(ledbat->utp, UTP_ON_STATE_CHANGE, &callback_on_state_change);
  utp_set_callback(ledbat->utp, UTP_ON_READ, &callback_on_read);
  utp_set_callback(ledbat->utp, UTP_ON_ACCEPT, &callback_on_accept);

  /* why not? */
  utp_context_set_option(ledbat->utp, UTP_LOG_NORMAL, 1);
  utp_context_set_option(ledbat->utp, UTP_LOG_MTU,    1);
  utp_context_set_option(ledbat->utp, UTP_LOG_DEBUG,  1);

  tmr_init(&ledbat->tmr);
  tmr_start(&ledbat->tmr, 500, ledbat_timer, ledbat);

out:
  if (err) {
    ledbat = mem_deref( ledbat );
  } else {
    *ledbatp = ledbat;
  }
  return err;
}


