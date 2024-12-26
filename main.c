#include <asm-generic/socket.h>
#include <assert.h>
#include <fcntl.h>
#include <liburing.h>
#include <liburing/io_uring.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "errors.c"

#define MAX_CONNECTIONS 5

struct io_uring_buf_ring*
setup_buffer_ring(struct io_uring *ring, int id, uint8_t* buffers, int buf_ring_size, int buf_size)
{
	struct io_uring_buf_ring *br;
	int i;
	int err;

	/* allocate mem for sharing buffer ring */
	if (posix_memalign((void **) &br, 4096,
			   buf_ring_size * sizeof(struct io_uring_buf_ring)))
		return NULL;

	/* assign and register buffer ring */
	struct io_uring_buf_reg reg = {
	  .ring_addr = (unsigned long) br,
	  .ring_entries = buf_ring_size,
	  .bgid = id
	};
	err = io_uring_register_buf_ring(ring, &reg, 0);
  err_handler(err, "Register buffer ring");

	/* add initial buffers to the ring */
	io_uring_buf_ring_init(br);
	for (i = 0; i < buf_ring_size; i++) {
		/* add each buffer, we'll use i buffer ID */
		io_uring_buf_ring_add(br, buffers + (i * buf_size), buf_size, i,
				      io_uring_buf_ring_mask(buf_ring_size), i);
	}

	/* we've supplied buffers, make them visible to the kernel */
	io_uring_buf_ring_advance(br, buf_ring_size);
	return br;
}

int
main() {
  int err;
  int socketfd;
  struct io_uring_sqe *sqe;
  struct io_uring_cqe *cqe;
  struct io_uring ring;
  
  err = io_uring_queue_init(16, &ring, 0);
  err_handler(err, "Init");

  uint8_t* buffers = malloc(16 * 1024);
  struct io_uring_buf_ring *buf_ring = 
    setup_buffer_ring(&ring, 1, buffers, 16, 1024); 

	{  
  	socketfd = socket(AF_INET, SOCK_STREAM, 0);
  	err_handler(socketfd, "Error opening socket");

		int optval = 1;
	  err = setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int));
	  err_handler(err, "Error opening socket");

		struct sockaddr_in serveraddr = {
			.sin_family = AF_INET,
			.sin_port = htons(3000), 
			.sin_addr = INADDR_ANY,
		};
	  err = bind(socketfd, (const struct sockaddr*) &serveraddr, sizeof(serveraddr));
	  err_handler(err, "Error binding socket to address");
	}

	err = listen(socketfd, MAX_CONNECTIONS);
	err_handler(err, "listen()");

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_multishot_accept(sqe, socketfd, NULL, NULL, 0);
	err = io_uring_submit(&ring);
	err_handler(err, "submit accept");
	err = io_uring_wait_cqe(&ring, &cqe);
  err_handler(err, "Wait CQE");
  err_handler(cqe->res, "Accept");
  int clientfd = cqe->res;
  io_uring_cqe_seen(&ring, cqe);

	sqe = io_uring_get_sqe(&ring);
	struct msghdr msg = {};
	io_uring_prep_recvmsg_multishot(sqe, clientfd, &msg, 0);
	sqe->flags |= IOSQE_BUFFER_SELECT;	
	sqe->buf_group = 1;
	err = io_uring_submit(&ring);
	err_handler(err, "submit recvmsg");

  for (;;) {
		err = io_uring_wait_cqe(&ring, &cqe);
  	err_handler(err, "Wait CQE recvmsg");
  	err_handler(cqe->res, "recvmsg");

  	// socklen_t nbytes = cqe->res;
  	int buffer_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
  	void* buf = buffers + 1024 * buffer_id;

  	struct io_uring_recvmsg_out* out = io_uring_recvmsg_validate(buf, cqe->res, &msg);
  	if (out == NULL) {
  		fprintf(stderr, "YO!");
  		exit(1);
  	}

  	buf = io_uring_recvmsg_payload(out, &msg);
  	size_t len = io_uring_recvmsg_payload_length(out, cqe->res, &msg);
 
  	printf("Packet len: %d, content: %.*s\n", cqe->res, len, buf);
  	io_uring_cqe_seen(&ring, cqe);
  }

  return 0;
}

void
tcp_server(struct io_uring_buf_ring* buf_ring) {
	
}

