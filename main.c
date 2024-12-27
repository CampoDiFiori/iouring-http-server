#include "errors.h"
#include "userdata.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <liburing.h>
#include <liburing/io_uring.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_CONNECTIONS 5
#define FMT_ADDRLEN 32

struct buffer_ring_init_params {
  size_t entries;
  size_t entry_size;
  int bgid;
};

struct buffer_ring {
  struct io_uring_buf_ring *br;
  struct iovec *bufs;
  struct buffer_ring_init_params params;
};

struct buffer_ring buffer_ring_init(struct io_uring *ring,
                                    struct buffer_ring_init_params params) {
  struct io_uring_buf_ring *br;
  size_t i;
  int err;

  uint8_t *_bufs = malloc(params.entries * params.entry_size);
  struct iovec *bufs = malloc(params.entries * sizeof(struct iovec));

  /* allocate mem for sharing buffer ring */
  err = posix_memalign((void **)&br, 4096,
                       params.entries * sizeof(struct io_uring_buf_ring));
  err_handler(-err);

  /* assign and register buffer ring */
  struct io_uring_buf_reg reg = {.ring_addr = (unsigned long)br,
                                 .ring_entries = params.entries,
                                 .bgid = params.bgid};
  err = io_uring_register_buf_ring(ring, &reg, 0);
  err_handler(err);

  /* add initial buffers to the ring */
  io_uring_buf_ring_init(br);
  for (i = 0; i < params.entries; i++) {
    bufs[i].iov_base = _bufs + (i * params.entry_size);
    bufs[i].iov_len = params.entry_size;

    /* add each buffer, we'll use i buffer ID */
    io_uring_buf_ring_add(br, bufs[i].iov_base, bufs[i].iov_len, i,
                          io_uring_buf_ring_mask(params.entries), i);
  }

  /* we've supplied buffers, make them visible to the kernel */
  io_uring_buf_ring_advance(br, params.entries);

  return (struct buffer_ring){
      .br = br,
      .bufs = bufs,
      .params = params,
  };
}

void format_inet_addr_from_sockfd(int sockfd, char *buf, size_t buf_sz) {
  int err;
  int ip_len;
  struct sockaddr_in sender;
  socklen_t sender_sz = sizeof(struct sockaddr_in);

  err = getpeername(sockfd, (struct sockaddr *)&sender, &sender_sz);
  err_handler(-err, "getpeername()");

  memset(buf, 0, buf_sz);
  inet_ntop(AF_INET, &sender.sin_addr, buf, buf_sz);

  ip_len = strlen(buf);
  snprintf(buf + ip_len, buf_sz - ip_len, ":%d", ntohs(sender.sin_port));
}

void tcp_server(struct io_uring *ring) {
  int err;
  struct io_uring_cqe *cqe;
  struct io_uring_sqe *sqe;
  struct msghdr msg = {};

  struct buffer_ring_init_params params = {
      .entries = 16, .entry_size = 1024, .bgid = 1};
  struct buffer_ring br = buffer_ring_init(ring, params);

  char fmt_addr[FMT_ADDRLEN];

  for (;;) {
    err = io_uring_wait_cqe(ring, &cqe);
    err_handler(err);

    struct userdata ud = decode_userdata(cqe);
    switch (ud.op) {
    case OP_ACCEPT: {
      int clientfd = cqe->res;
      err_handler(clientfd);

      sqe = io_uring_get_sqe(ring);
      io_uring_prep_recvmsg_multishot(sqe, clientfd, &msg, 0);
      sqe->flags |= IOSQE_BUFFER_SELECT;
      sqe->buf_group = params.bgid;
      encode_userdata(sqe, clientfd, OP_RECVMSG);

      err = io_uring_submit(ring);
      err_handler(err);

      format_inet_addr_from_sockfd(clientfd, fmt_addr, FMT_ADDRLEN);
      break;
    }
    case OP_RECVMSG: {
      int bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
      int msglen = cqe->res;
      err_handler(msglen);

      struct io_uring_recvmsg_out *out =
          io_uring_recvmsg_validate(br.bufs[bid].iov_base, cqe->res, &msg);
      null_handler(out, "recvmsg validation failed.");

      char *buf = io_uring_recvmsg_payload(out, &msg);
      int len = io_uring_recvmsg_payload_length(out, cqe->res, &msg);

      printf("Packet from %s, len: %d, content: %.*s\n", fmt_addr, cqe->res,
             len, buf);
      break;
    }
    default: {
      err_handler(-ENOSYS);
      break;
    }
    }
    io_uring_cqe_seen(ring, cqe);
  }
}

int main() {
  int err;
  int socketfd;
  struct io_uring_sqe *sqe;
  struct io_uring ring;

  socketfd = socket(AF_INET, SOCK_STREAM, 0);
  err_handler(socketfd);

  int optval = 1;
  err = setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
                   sizeof(int));
  err_handler(err);

  struct sockaddr_in serveraddr = {
      .sin_family = AF_INET,
      .sin_port = htons(3000),
      .sin_addr = {INADDR_ANY},
  };
  err =
      bind(socketfd, (const struct sockaddr *)&serveraddr, sizeof(serveraddr));
  err_handler(err);

  err = listen(socketfd, MAX_CONNECTIONS);
  err_handler(err);

  err = io_uring_queue_init(16, &ring, 0);
  err_handler(err);

  sqe = io_uring_get_sqe(&ring);
  io_uring_prep_multishot_accept(sqe, socketfd, NULL, NULL, 0);
  encode_userdata(sqe, socketfd, OP_ACCEPT);

  err = io_uring_submit(&ring);
  err_handler(err);

  tcp_server(&ring);

  return 0;
}
