#include <liburing.h>
#include <netinet/in.h>

struct userdata {
  union {
    struct {
      uint32_t fd;
      uint8_t op;
    };
    uint64_t val;
  };
};

enum opcode {
  OP_ACCEPT = 1,
  OP_RECVMSG = 2,
};

static inline void encode_userdata(struct io_uring_sqe *sqe,uint16_t fd, uint8_t op) {
  struct userdata ud = {.fd = fd, .op = op, };

  io_uring_sqe_set_data64(sqe, ud.val);
}

static inline struct userdata decode_userdata(struct io_uring_cqe *cqe) {
  return (struct userdata){.val = cqe->user_data};
}
