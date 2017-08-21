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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2014 by Delphix. All rights reserved.
 */

#ifndef	_DMU_ZFETCH_H
#define	_DMU_ZFETCH_H

#include <sys/zfs_context.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct dnode;				/* so we can reference dnode */
struct range_tree;

typedef struct zfetch {
	kmutex_t		zf_lock;    /* protects zfetch structure */
	struct dnode		*zf_dnode;  /* dnode that owns this zfetch */
	struct range_tree	*zf_pftree; /* range tree of prefetched blkid */
	hrtime_t		zf_atime;   /* time last prefetch issued */
} zfetch_t;

void		zfetch_init(void);
void		zfetch_fini(void);

void		dmu_zfetch_init(zfetch_t *, struct dnode *);
void		dmu_zfetch_fini(zfetch_t *);
void		dmu_zfetch(zfetch_t *, uint64_t, uint64_t, boolean_t);


#ifdef	__cplusplus
}
#endif

#endif	/* _DMU_ZFETCH_H */
