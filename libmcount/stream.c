/*
 * Streaming trace output for uftrace
 *
 * Copyright (C) 2024, uftrace contributors
 *
 * Released under the GPL v2.
 */

#include <stdio.h>
#include <sys/uio.h>
#include <unistd.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "mcount"
#define PR_DOMAIN DBG_MCOUNT

#include "libmcount/internal.h"
#include "libmcount/mcount.h"
#include "uftrace.h"

/* Global flag to enable streaming mode */
bool mcount_stream_mode = false;

/*
 * stream_trace_entry - send a streaming trace record to uftrace
 * @mtdp: thread data
 * @rstack: return stack entry
 * @type: UFTRACE_ENTRY or UFTRACE_EXIT
 *
 * This function sends trace records in real-time through the pipe
 * to the uftrace process for immediate display.
 */
void stream_trace_entry(struct mcount_thread_data *mtdp,
			struct mcount_ret_stack *rstack,
			int type)
{
	struct uftrace_msg_stream msg;
	struct uftrace_msg hdr = {
		.magic = UFTRACE_MSG_MAGIC,
		.type = UFTRACE_MSG_STREAM_TRACE,
		.len = sizeof(msg),
	};
	struct iovec iov[2] = {
		{
			.iov_base = &hdr,
			.iov_len = sizeof(hdr),
		},
		{
			.iov_base = &msg,
			.iov_len = sizeof(msg),
		},
	};
	ssize_t len;

	if (mcount_pfd < 0)
		return;

	msg.time = (type == UFTRACE_ENTRY) ? rstack->start_time : rstack->end_time;
	msg.addr = rstack->child_ip;
	msg.tid = mcount_gettid(mtdp);
	msg.depth = rstack->depth;
	msg.type = type;
	msg.flags = 0;

	if (type == UFTRACE_EXIT && rstack->end_time > rstack->start_time)
		msg.duration = rstack->end_time - rstack->start_time;
	else
		msg.duration = 0;

	len = sizeof(hdr) + sizeof(msg);
	if (writev(mcount_pfd, iov, 2) != len) {
		if (!mcount_should_stop())
			pr_dbg("failed to send stream trace record\n");
	}
}
