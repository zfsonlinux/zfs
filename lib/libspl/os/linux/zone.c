/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2006 Ricardo Correia.  All rights reserved.
 * Use is subject to license terms.
 */

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

#include <zone.h>

zoneid_t
getzoneid()
{
	zoneid_t z = 0;
	char path[PATH_MAX];
	char buf[128] = { '\0' };
	char *cp, *cp_end;
	unsigned long n;
	int c;
	ssize_t r;

	c = snprintf(path, sizeof (path), "/proc/%d/ns/user", getpid());
	/* This API doesn't have any error checking... */
	if ((size_t)c >= sizeof (path))
		goto out;

	r = readlink(path, buf, sizeof (buf) - 1);
	if ((size_t)r >= sizeof (buf))
		goto out;

	cp = strchr(buf, '[');
	if (cp == NULL)
		goto out;
	cp++;
	cp_end = strchr(cp, ']');
	if (cp_end == NULL)
		goto out;

	*cp_end = '\0';
	n = strtoul(cp, NULL, 10);
	if (errno == ERANGE)
		goto out;
	z = (zoneid_t)n;

out:
	return (z);
}
