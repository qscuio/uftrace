/*
 * Stream command for uftrace
 *
 * Copyright (C) 2024, uftrace contributors
 *
 * Released under the GPL v2.
 *
 * This command is a wrapper around record with streaming enabled by default.
 */

#include "uftrace.h"

int command_stream(int argc, char *argv[], struct uftrace_opts *opts)
{
/* Enable streaming mode */
opts->stream = true;

/* Call the record command */
return command_record(argc, argv, opts);
}
