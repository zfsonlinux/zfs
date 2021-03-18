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


#include <sys/dmu.h>
#include <sys/dmu_impl.h>
#include <sys/dbuf.h>
#include <sys/dnode.h>
#include <sys/zfs_context.h>
#include <sys/zfs_racct.h>
#include <sys/dsl_dataset.h>
#include <sys/dmu_objset.h>

/*
 * Normally the db_blkptr points to the most recent on-disk content for the
 * dbuf (and anything newer will be cached in the dbuf). However, a recent
 * Direct IO write could leave newer content on disk and the dbuf uncached.
 * In this case we must return the (as yet unsynced) pointer to the latest
 * on-disk content.
 */
static blkptr_t *
dmu_get_bp_from_dbuf(dmu_buf_impl_t *db)
{
	ASSERT(MUTEX_HELD(&db->db_mtx));

	if (db->db_level != 0) {
		return (db->db_blkptr);
	}

	blkptr_t *bp = db->db_blkptr;

	dbuf_dirty_record_t *dr_dio = dbuf_get_dirty_direct(db);
	if (dr_dio && dr_dio->dt.dl.dr_override_state == DR_OVERRIDDEN &&
	    dr_dio->dt.dl.dr_data == NULL) {
		/* we have a Direct IO write, use it's bp */
		ASSERT(db->db_state != DB_NOFILL);
		bp = &dr_dio->dt.dl.dr_overridden_by;
	}

	return (bp);
}

static abd_t *
make_abd_for_dbuf(dmu_buf_impl_t *db, abd_t *data, uint64_t offset,
    uint64_t size)
{
	size_t buf_size = db->db.db_size;
	abd_t *pre_buf = NULL, *post_buf = NULL, *mbuf = NULL;
	size_t buf_off = 0;

	ASSERT(MUTEX_HELD(&db->db_mtx));

	if (offset > db->db.db_offset) {
		size_t pre_size = offset - db->db.db_offset;
		pre_buf = abd_alloc_for_io(pre_size, B_TRUE);
		buf_size -= pre_size;
		buf_off = 0;
	} else {
		buf_off = db->db.db_offset - offset;
		size -= buf_off;
	}

	if (size < buf_size) {
		size_t post_size = buf_size - size;
		post_buf = abd_alloc_for_io(post_size, B_TRUE);
		buf_size -= post_size;
	}

	ASSERT3U(buf_size, >, 0);
	abd_t *buf = abd_get_offset_size(data, buf_off, buf_size);

	if (pre_buf || post_buf) {
		mbuf = abd_alloc_gang();
		if (pre_buf)
			abd_gang_add(mbuf, pre_buf, B_TRUE);
		abd_gang_add(mbuf, buf, B_TRUE);
		if (post_buf)
			abd_gang_add(mbuf, post_buf, B_TRUE);
	} else {
		mbuf = buf;
	}

	return (mbuf);
}

static void
dmu_read_abd_done(zio_t *zio)
{
	abd_free(zio->io_abd);
}

static void
dmu_write_direct_ready(zio_t *zio)
{
	dmu_sync_ready(zio, NULL, zio->io_private);
}

static void
dmu_write_direct_done(zio_t *zio)
{
	dmu_sync_arg_t *dsa = zio->io_private;
	dbuf_dirty_record_t *dr = dsa->dsa_dr;
	dmu_buf_impl_t *db = dr->dr_dbuf;

	abd_free(zio->io_abd);

	mutex_enter(&db->db_mtx);
	if (db->db_buf) {
		/*
		 * The current contents of the dbuf are now stale.
		 */
		db->db.db_data = NULL;
		dr->dt.dl.dr_data = NULL;

		/*
		 * We must remove any dirty data that might attempt to write
		 * out the contents of an associated ARC buf with this dbuf.
		 *
		 * Since we only allow block aligned Direct IO writes we
		 * can iterate through dirty record list of the dbuf since
		 * the rangelocks will prevent another writer from adding
		 * to the db_dirty_records.
		 */
		dbuf_dirty_record_t *dr_next = list_tail(&db->db_dirty_records);
		while (dr_next && dr_next != dr) {
			dr_next = dmu_buf_undirty(db, dr_next);
		}

		arc_buf_destroy(db->db_buf, db);
		db->db_buf = NULL;
		ASSERT3U(db->db_dirtycnt, ==, 1);
	} else {
		/*
		 * Direct IO performed by dmu_assign_arcbuf_by_dnode() for
		 * loaned arc_buf_t's do not set db->db_buf, they are
		 * returned on success in dmu_assign_arcbuf_by_dnode().
		 */
	}

	ASSERT(db->db.db_data == NULL);
	db->db_state = DB_UNCACHED;
	mutex_exit(&db->db_mtx);

	dmu_sync_done(zio, NULL, zio->io_private);
	kmem_free(zio->io_bp, sizeof (blkptr_t));
}

int
dmu_write_direct(zio_t *pio, dmu_buf_impl_t *db, abd_t *data, dmu_tx_t *tx)
{
	objset_t *os = db->db_objset;
	dsl_dataset_t *ds = dmu_objset_ds(os);
	zbookmark_phys_t zb;

	SET_BOOKMARK(&zb, ds->ds_object,
	    db->db.db_object, db->db_level, db->db_blkid);

	DB_DNODE_ENTER(db);
	dnode_t *dn = DB_DNODE(db);
	zio_prop_t zp;
	dmu_write_policy(os, dn, db->db_level, WP_DMU_SYNC | WP_DIRECT_WR, &zp);

	DB_DNODE_EXIT(db);

	/*
	 * Dirty this dbuf with DB_NOFILL since we will not have any data
	 * associated with the dbuf.
	 */
	dmu_buf_will_not_fill(&db->db, tx);

	mutex_enter(&db->db_mtx);

	uint64_t txg = dmu_tx_get_txg(tx);
	ASSERT3U(txg, >, spa_last_synced_txg(os->os_spa));
	ASSERT3U(txg, >, spa_syncing_txg(os->os_spa));

	dbuf_dirty_record_t *dr_head = dbuf_get_dirty_direct(db);
	ASSERT3U(dr_head->dr_txg, ==, txg);

	blkptr_t *bp = kmem_alloc(sizeof (blkptr_t), KM_SLEEP);
	if (db->db_blkptr != NULL) {
		/*
		 * Fill in bp with the current block pointer so that
		 * the nopwrite code can check if we're writing the same
		 * data that's already on disk.
		 */
		*bp = *db->db_blkptr;
	} else {
		bzero(bp, sizeof (blkptr_t));
	}

	/*
	 * Disable nopwrite if the current block pointer could change
	 * before this TXG syncs.
	 */
	if (list_next(&db->db_dirty_records, dr_head) != NULL)
		zp.zp_nopwrite = B_FALSE;

	ASSERT3S(dr_head->dt.dl.dr_override_state, ==, DR_NOT_OVERRIDDEN);
	dr_head->dt.dl.dr_override_state = DR_IN_DMU_SYNC;
	mutex_exit(&db->db_mtx);

	/*
	 * We will not be writing this block in syncing context, so
	 * update the dirty space accounting.
	 */
	dsl_pool_undirty_space(dmu_objset_pool(os), dr_head->dr_accounted, txg);

	dmu_sync_arg_t *dsa = kmem_zalloc(sizeof (dmu_sync_arg_t), KM_SLEEP);
	dsa->dsa_dr = dr_head;

	zio_t *zio = zio_write(pio, os->os_spa, txg, bp, data,
	    db->db.db_size, db->db.db_size, &zp,
	    dmu_write_direct_ready, NULL, NULL, dmu_write_direct_done, dsa,
	    ZIO_PRIORITY_SYNC_WRITE, ZIO_FLAG_CANFAIL, &zb);

	if (pio == NULL)
		return (zio_wait(zio));

	zio_nowait(zio);

	return (0);
}

int
dmu_write_abd(dnode_t *dn, uint64_t offset, uint64_t size,
    abd_t *data, uint32_t flags, dmu_tx_t *tx)
{
	dmu_buf_t **dbp;
	int numbufs, err;

	ASSERT(flags & DMU_DIRECTIO);

	err = dmu_buf_hold_array_by_dnode(dn, offset,
	    size, B_FALSE, FTAG, &numbufs, &dbp, flags);
	if (err)
		return (err);

	zio_t *pio = zio_root(dn->dn_objset->os_spa, NULL, NULL,
	    ZIO_FLAG_CANFAIL);

	for (int i = 0; i < numbufs; i++) {
		dmu_buf_impl_t *db = (dmu_buf_impl_t *)dbp[i];

		abd_t *abd = abd_get_offset_size(data,
		    db->db.db_offset - offset, dn->dn_datablksz);

		err = dmu_write_direct(pio, db, abd, tx);
		ASSERT0(err);
	}

	dmu_buf_rele_array(dbp, numbufs, FTAG);

	return (zio_wait(pio));
}

int
dmu_read_abd(dnode_t *dn, uint64_t offset, uint64_t size,
    abd_t *data, uint32_t flags)
{
	objset_t *os = dn->dn_objset;
	spa_t *spa = os->os_spa;
	dmu_buf_t **dbp;
	int numbufs, err;

	ASSERT(flags & DMU_DIRECTIO);

	err = dmu_buf_hold_array_by_dnode(dn, offset,
	    size, B_FALSE, FTAG, &numbufs, &dbp, flags);
	if (err)
		return (err);

	zio_t *rio = zio_root(spa, NULL, NULL, ZIO_FLAG_CANFAIL);

	for (int i = 0; i < numbufs; i++) {
		dmu_buf_impl_t *db = (dmu_buf_impl_t *)dbp[i];
		abd_t *mbuf;
		zbookmark_phys_t zb;

		mutex_enter(&db->db_mtx);

		SET_BOOKMARK(&zb, dmu_objset_ds(os)->ds_object,
		    db->db.db_object, db->db_level, db->db_blkid);
		blkptr_t *bp = dmu_get_bp_from_dbuf(db);

		/*
		 * There is no need to read if this is a hole or the data is
		 * cached.  This will not be considered a direct read for IO
		 * accounting in the same way that an ARC hit is not counted.
		 */
		if (bp == NULL || BP_IS_HOLE(bp) || db->db_state == DB_CACHED) {
			size_t aoff = offset < db->db.db_offset ?
			    db->db.db_offset - offset : 0;
			size_t boff = offset > db->db.db_offset ?
			    offset - db->db.db_offset : 0;
			size_t len = MIN(size - aoff, db->db.db_size - boff);

			if (db->db_state == DB_CACHED) {
				abd_copy_from_buf_off(data,
				    (char *)db->db.db_data + boff, aoff, len);
			} else {
				abd_zero_off(data, aoff, len);
			}

			mutex_exit(&db->db_mtx);
			continue;
		}

		mbuf = make_abd_for_dbuf(db, data, offset, size);
		ASSERT3P(mbuf, !=, NULL);
		mutex_exit(&db->db_mtx);

		zfs_racct_read(spa, db->db.db_size, 1, flags);
		zio_nowait(zio_read(rio, spa, bp, mbuf, db->db.db_size,
		    dmu_read_abd_done, NULL, ZIO_PRIORITY_SYNC_READ, 0, &zb));
	}

	dmu_buf_rele_array(dbp, numbufs, FTAG);

	return (zio_wait(rio));
}

#ifdef _KERNEL
int
dmu_read_uio_direct(dnode_t *dn, zfs_uio_t *uio, uint64_t size)
{
	offset_t offset = zfs_uio_offset(uio);
	offset_t page_index = (offset - zfs_uio_soffset(uio)) >> PAGESHIFT;
	int err;

	ASSERT(uio->uio_extflg & UIO_DIRECT);
	ASSERT3U(page_index, <, uio->uio_dio.npages);

	abd_t *data = abd_alloc_from_pages(&uio->uio_dio.pages[page_index],
	    offset & (PAGESIZE - 1), size);
	err = dmu_read_abd(dn, offset, size, data, DMU_DIRECTIO);
	abd_free(data);

	if (err == 0)
		zfs_uioskip(uio, size);

	return (err);
}

int
dmu_write_uio_direct(dnode_t *dn, zfs_uio_t *uio, uint64_t size, dmu_tx_t *tx)
{
	offset_t offset = zfs_uio_offset(uio);
	offset_t page_index = (offset - zfs_uio_soffset(uio)) >> PAGESHIFT;
	int err;

	ASSERT(uio->uio_extflg & UIO_DIRECT);
	ASSERT3U(page_index, <, uio->uio_dio.npages);

	abd_t *data = abd_alloc_from_pages(&uio->uio_dio.pages[page_index],
	    offset & (PAGESIZE - 1), size);
	err = dmu_write_abd(dn, offset, size, data, DMU_DIRECTIO, tx);
	abd_free(data);

	if (err == 0)
		zfs_uioskip(uio, size);

	return (err);
}
#endif /* _KERNEL */
