/*	$OpenBSD: scheduler_backend.c,v 1.13 2014/02/04 14:56:03 eric Exp $	*/

/*
 * Copyright (c) 2012 Gilles Chehade <gilles@poolp.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/socket.h>

#include <ctype.h>
#include <err.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smtpd.h"
#include "log.h"

extern struct scheduler_backend scheduler_backend_null;
extern struct scheduler_backend scheduler_backend_proc;
extern struct scheduler_backend scheduler_backend_ramqueue;

struct scheduler_backend *
scheduler_backend_lookup(const char *name)
{
	if (!strcmp(name, "null"))
		return &scheduler_backend_null;
	if (!strcmp(name, "proc"))
		return &scheduler_backend_proc;
	if (!strcmp(name, "ramqueue"))
		return &scheduler_backend_ramqueue;

	return NULL;
}

void
scheduler_info(struct scheduler_info *sched, struct envelope *evp)
{
	sched->evpid = evp->id;
	sched->type = evp->type;
	sched->creation = evp->creation;
	sched->retry = evp->retry;
	sched->expire = evp->expire;
	sched->lasttry = evp->lasttry;
	sched->lastbounce = evp->lastbounce;
	sched->nexttry	= 0;
}

time_t
scheduler_compute_schedule(struct scheduler_info *sched)
{
	time_t		delay;
	uint32_t	retry;

	if (sched->type == D_MTA)
		delay = 800;
	else
		delay = 10;

	retry = sched->retry;
	delay = ((delay * retry) * retry) / 2;

	return (sched->creation + delay);
}
