/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/coredump.h>
#include <sys/pidfd.h>

#include "sd-daemon.h"
#include "sd-event.h"

#include "coredump-config.h"
#include "coredump-context.h"
#include "coredump-kernel-helper.h"
#include "coredumpd-worker.h"
#include "errno-list.h"
#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "socket-util.h"
#include "string-util.h"

#define COREDUMP_REQ_SIZE_MAX 4096u

typedef enum WorkerRequestState {
        WORKER_WAITING_REQUEST,
        WORKER_SENDING_ACK,
        WORKER_WAITING_MARKER,
        _WORKER_REQUEST_STATE_MAX,
        _WORKER_REQUEST_STATE_INVALID = -EINVAL,
} WorkerRequestState;

typedef struct Worker {
        WorkerRequestState state;
        struct coredump_req req;
} Worker;

static int worker_process_request(Worker *worker, int fd, uint32_t revents) {
        assert(worker);
        assert(worker->state == WORKER_WAITING_REQUEST);
        assert(fd >= 0);

        if (!FLAGS_SET(revents, EPOLLIN))
                return 0;

        /* Peek the size of the coredump request. */
        ssize_t n = next_datagram_size_fd(fd);
        if (n < 0) {
                if (ERRNO_IS_NEG_TRANSIENT(n))
                        return 0;
                return log_debug_errno(n, "Failed to determine coredump request size: %m");
        }
        if (n < COREDUMP_REQ_SIZE_VER0)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Acquired coredump request size is too small (%zi < %i)",
                                       n, COREDUMP_REQ_SIZE_VER0);
        if ((size_t) n > COREDUMP_REQ_SIZE_MAX)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Acquired coredump request size is too large (%zi > %u)",
                                       n, COREDUMP_REQ_SIZE_MAX);

        union coredump_req_union {
                struct coredump_req req;
                uint8_t buf[COREDUMP_REQ_SIZE_MAX];
        } req = {};

        n = recv(fd, &req, n, /* flags = */ 0);
        if (n < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return 0;
                return log_debug_errno(errno, "Failed to receive coredump request size: %m");
        }
        if (n < COREDUMP_REQ_SIZE_VER0)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Received coredump request size is too small (%zi < %i)",
                                       n, COREDUMP_REQ_SIZE_VER0);
        if ((size_t) n != req.req.size)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Received coredump request size does not match with the size specified in the request (%zi != %"PRIu32")",
                                       n, req.req.size);

        /* Minimum verification of the request. */
        if (req.req.size < COREDUMP_REQ_SIZE_VER0)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Received coredump request with too small size (%"PRIu32" < %i)",
                                       req.req.size, COREDUMP_REQ_SIZE_VER0);
        if (req.req.size_ack < COREDUMP_ACK_SIZE_VER0)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Received coredump request with too small ack size (%"PRIu32" < %i)",
                                       req.req.size_ack, COREDUMP_ACK_SIZE_VER0);
        if (!FLAGS_SET(req.req.mask, COREDUMP_KERNEL | COREDUMP_USERSPACE | COREDUMP_REJECT | COREDUMP_WAIT))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Received coredump request with insufficient flags (%"PRIx64")",
                                       (uint64_t) req.req.mask);

        worker->req = req.req;

        log_debug("Received coredump request, sending coredump ack.");
        worker->state = WORKER_SENDING_ACK;
        return 0;
}

static int worker_send_ack(Worker *worker, int fd, uint32_t revents) {
        assert(worker);
        assert(worker->state == WORKER_SENDING_ACK);
        assert(fd >= 0);

        if (!FLAGS_SET(revents, EPOLLOUT))
                return 0;

        struct coredump_ack ack = {
                .size = MIN(sizeof(struct coredump_ack), worker->req.size_ack),
                .mask = COREDUMP_KERNEL | COREDUMP_USERSPACE | COREDUMP_WAIT,
        };

        ssize_t n = send(fd, &ack, ack.size, MSG_NOSIGNAL);
        if (n < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return 0;
                return log_debug_errno(errno, "Failed to send coredump ack: %m");
        }
        if ((size_t) n != ack.size)
                return log_debug_errno(SYNTHETIC_ERRNO(ESTALE),
                                       "Sent size does not match with the size of coredump ack (%zi != %"PRIu32"): %m",
                                       n, ack.size);

        log_debug("Sent coredump ack, waiting for marker.");
        worker->state = WORKER_WAITING_MARKER;
        return 0;
}

static int worker_process_marker(Worker *worker, int fd, uint32_t revents) {
        assert(worker);
        assert(worker->state == WORKER_WAITING_MARKER);
        assert(fd >= 0);

        if (!FLAGS_SET(revents, EPOLLIN))
                return 0;

        enum coredump_mark mark;
        ssize_t n = recv(fd, &mark, sizeof(mark), /* flags = */ 0);
        if (n < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return 0;
                return log_debug_errno(errno, "Failed to receive marker: %m");
        }
        if ((size_t) n != sizeof(mark))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Received marker with invalid size (%zi).", n);

        switch (mark) {
        case COREDUMP_MARK_REQACK:
                log_debug("Sent coredump ack message is accepted, reading coredump data.");
                return 1;
        case COREDUMP_MARK_MINSIZE:
                return log_debug_errno(SYNTHETIC_ERRNO(ENOBUFS),
                                       "Sent coredump ack message is refused as its size is too small.");
        case COREDUMP_MARK_MAXSIZE:
                return log_debug_errno(SYNTHETIC_ERRNO(EMSGSIZE),
                                       "Sent coredump ack message is refused as its size is too large.");
        case COREDUMP_MARK_UNSUPPORTED:
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Sent coredump ack message is refused as it contains unsupported flags.");
        case COREDUMP_MARK_CONFLICTING:
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Sent coredump ack message is refused as it contains conflicting flags.");
        default:
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Sent coredump ack message is refused with unknown reason (%u).", mark);
        }
}

static int on_coredump_io(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Worker *worker = ASSERT_PTR(userdata);
        int r;

        assert(s);
        assert(fd >= 0);

        switch (worker->state) {
        case WORKER_WAITING_REQUEST:
                r = worker_process_request(worker, fd, revents);
                break;
        case WORKER_SENDING_ACK:
                r = worker_send_ack(worker, fd, revents);
                break;
        case WORKER_WAITING_MARKER:
                r = worker_process_marker(worker, fd, revents);
                break;
        default:
                assert_not_reached();
        }
        if (r != 0)
                return sd_event_exit(sd_event_source_get_event(s), r < 0 ? r : 0);

        return 0;
}

int coredump_worker_main(const CoredumpConfig *config, bool request_mode, int coredump_fd) {
        int r;

        assert(config);
        assert(coredump_fd >= 0);

        /* First, log to a safe place, since we don't know what crashed and it might be journald which we'd
         * rather not log to then. */
        LogTarget saved_target = log_get_target();
        log_set_target_and_open(LOG_TARGET_KMSG);

        _cleanup_(coredump_context_done) CoredumpContext context = COREDUMP_CONTEXT_NULL;
        context.by_kernel_socket = true;

        r = coredump_context_parse_from_socket(&context, coredump_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire metadata: %m");

        if (!context.is_journald)
                log_set_target_and_open(saved_target);

        if (request_mode) {
                _cleanup_(sd_event_unrefp) sd_event *e = NULL;
                r = sd_event_new(&e);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate sd-event object: %m");

                Worker worker = {};
                r = sd_event_add_io(e, NULL, coredump_fd, EPOLLIN | EPOLLOUT, on_coredump_io, &worker);
                if (r < 0)
                        return log_error_errno(r, "Failed to add IO event source for kernel coredump socket: %m");

                r = sd_event_set_signal_exit(e, true);
                if (r < 0)
                        return log_error_errno(r, "Failed to enable signal event sources: %m");

                r = sd_event_loop(e);
                if (r < 0)
                        return log_error_errno(r, "Worker event loop failed: %m");
        }

        r = coredump_send_or_submit(config, &context, coredump_fd);
        if (r < 0)
                return r;

        r = sd_notify(/* unset_environment = */ false, "PROCESSED=1");
        if (r < 0)
                return log_error_errno(r, "Failed to send notification message to manager process: %m");

        return 0;
}
