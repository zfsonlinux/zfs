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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, 2018 by Delphix. All rights reserved.
 * Copyright 2011 Nexenta Systems, Inc. All rights reserved.
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */

#ifndef _DMU_RECV_H
#define	_DMU_RECV_H

#include <sys/inttypes.h>
#include <sys/dsl_bookmark.h>
#include <sys/dsl_dataset.h>
#include <sys/spa.h>
#include <sys/objlist.h>
#include <sys/dsl_bookmark.h>

extern const char *recv_clone_name;

typedef struct dmu_recv_cookie {
	struct dsl_dataset *drc_ds;
	struct dmu_replay_record *drc_drr_begin;
	struct drr_begin *drc_drrb;
	const char *drc_tofs;
	const char *drc_tosnap;
	boolean_t drc_newfs;
	boolean_t drc_byteswap;
	uint64_t drc_featureflags;
	boolean_t drc_force;
	boolean_t drc_resumable;
	boolean_t drc_raw;
	boolean_t drc_clone;
	boolean_t drc_spill;
	struct avl_tree *drc_guid_to_ds_map;
	nvlist_t *drc_keynvl;
	uint64_t drc_fromsnapobj;
	uint64_t drc_newsnapobj;
	uint64_t drc_ivset_guid;
	void *drc_owner;
	cred_t *drc_cred;
	nvlist_t *drc_begin_nvl;

	objset_t *drc_os;
	file_t *drc_fp; /* The file to read the stream from */
	uint64_t drc_voff; /* The current offset in the stream */
	uint64_t drc_bytes_read;
	/*
	 * A record that has had its payload read in, but hasn't yet been handed
	 * off to the worker thread.
	 */
	struct receive_record_arg *drc_rrd;
	/* A record that has had its header read in, but not its payload. */
	struct receive_record_arg *drc_next_rrd;
	zio_cksum_t drc_cksum;
	zio_cksum_t drc_prev_cksum;
	int drc_err;
	/* Sorted list of objects not to issue prefetches for. */
	objlist_t *drc_ignore_objlist;
} dmu_recv_cookie_t;

int dmu_recv_begin(char *tofs, char *tosnap, dmu_replay_record_t *drr_begin,
    boolean_t force, boolean_t resumable, nvlist_t *localprops,
    nvlist_t *hidden_args, char *origin, dmu_recv_cookie_t *drc,
    file_t *fp, offset_t *voffp);
int dmu_recv_stream(dmu_recv_cookie_t *drc, int cleanup_fd,
    uint64_t *action_handlep, offset_t *voffp);
int dmu_recv_end(dmu_recv_cookie_t *drc, void *owner);
boolean_t dmu_objset_is_receiving(objset_t *os);
int dmu_restore_bytes(dmu_recv_cookie_t *drc, void *buf, int len,
    ssize_t *resid);


#endif /* _DMU_RECV_H */
