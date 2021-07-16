/*
 * Copyright (c) 2021 Klara Systems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/zfs_context.h>
#include <sys/zone.h>

static kmutex_t zone_datasets_lock;
static struct list_head zone_datasets;

typedef struct zone_datasets {
	struct list_head zds_list;	/* zone_datasets linkage */
	unsigned int zds_nsnum;		/* namespace identifier */
	struct list_head zds_datasets;	/* datasets for the namespace */
} zone_datasets_t;

typedef struct zone_dataset {
	struct list_head zd_list;	/* zone_dataset linkage */
	size_t zd_dsnamelen;		/* length of name */
	char zd_dsname[0];		/* name of the member dataset */
} zone_dataset_t;

static struct zone_datasets *
zone_datasets_lookup(unsigned int nsnum)
{
	zone_datasets_t *zds;

	list_for_each_entry(zds, &zone_datasets, zds_list) {
		if (zds->zds_nsnum == nsnum)
			return (zds);
	}
	return (NULL);
}

static struct zone_dataset *
zone_dataset_lookup(zone_datasets_t *zds, const char *dataset, size_t dsnamelen)
{
	zone_dataset_t *zd;

	list_for_each_entry(zd, &zds->zds_datasets, zd_list) {
		if (zd->zd_dsnamelen != dsnamelen)
			continue;
		if (strncmp(zd->zd_dsname, dataset, dsnamelen) == 0)
			return (zd);
	}

	return (NULL);
}

static int
zone_dataset_cred_check(cred_t *cred)
{

	if (!uid_eq(cred->uid, GLOBAL_ROOT_UID))
		return (EPERM);

	return (0);
}

static int
zone_dataset_name_check(const char *dataset, size_t *dsnamelen)
{

	if (dataset[0] == '\0' || dataset[0] == '/')
		return (ENOENT);

	*dsnamelen = strlen(dataset);
	/* Ignore trailing slash, if supplied. */
	if (dataset[*dsnamelen - 1] == '/')
		(*dsnamelen)--;

	return (0);
}

int
zone_dataset_attach(cred_t *cred, const char *dataset, unsigned int nsnum)
{
	zone_datasets_t *zds;
	zone_dataset_t *zd;
	int error;
	size_t dsnamelen;

#if defined(CONFIG_USER_NS)
	if ((error = zone_dataset_cred_check(cred)) != 0)
		return (error);
	if ((error = zone_dataset_name_check(dataset, &dsnamelen)) != 0)
		return (error);

	mutex_enter(&zone_datasets_lock);
	zds = zone_datasets_lookup(nsnum);
	if (zds == NULL) {
		zds = kmem_alloc(sizeof (zone_datasets_t), KM_SLEEP);
		INIT_LIST_HEAD(&zds->zds_list);
		INIT_LIST_HEAD(&zds->zds_datasets);
		zds->zds_nsnum = nsnum;
		list_add_tail(&zds->zds_list, &zone_datasets);
	}
	zd = zone_dataset_lookup(zds, dataset, dsnamelen);
	if (zd != NULL) {
		error = EEXIST;
		goto done;
	}

	zd = kmem_alloc(sizeof (zone_dataset_t) + dsnamelen + 1, KM_SLEEP);
	zd->zd_dsnamelen = dsnamelen;
	strncpy(zd->zd_dsname, dataset, dsnamelen);
	zd->zd_dsname[dsnamelen] = '\0';
	INIT_LIST_HEAD(&zd->zd_list);
	list_add_tail(&zd->zd_list, &zds->zds_datasets);
	error = 0;

done:
	mutex_exit(&zone_datasets_lock);
	return (error);
#else
	return (ENXIO);
#endif
}
EXPORT_SYMBOL(zone_dataset_attach);

int
zone_dataset_detach(cred_t *cred, const char *dataset, unsigned int nsnum)
{
	zone_datasets_t *zds;
	zone_dataset_t *zd;
	int error;
	size_t dsnamelen;

#if defined(CONFIG_USER_NS)
	if ((error = zone_dataset_cred_check(cred)) != 0)
		return (error);
	if ((error = zone_dataset_name_check(dataset, &dsnamelen)) != 0)
		return (error);

	mutex_enter(&zone_datasets_lock);
	zds = zone_datasets_lookup(nsnum);
	if (zds != NULL)
		zd = zone_dataset_lookup(zds, dataset, dsnamelen);
	if (zds == NULL || zd == NULL) {
		error = ENOENT;
		goto done;
	}

	list_del(&zd->zd_list);
	kmem_free(zd, sizeof (*zd) + zd->zd_dsnamelen + 1);

	/* Prune the namespace entry if it has no more delegations. */
	if (list_empty(&zds->zds_datasets)) {
		list_del(&zds->zds_list);
		kmem_free(zds, sizeof (*zds));
	}
	error = 0;

done:
	mutex_exit(&zone_datasets_lock);
	return (error);
#else
	return (ENXIO);
#endif
}
EXPORT_SYMBOL(zone_dataset_detach);

int
zone_dataset_visible(const char *dataset, int *write)
{
	zone_datasets_t *zds;
	zone_dataset_t *zd;
	int visible;
	size_t dsnamelen, zd_len;

	/* Default to read-only, in case visible is returned. */
	if (write != NULL)
		*write = 0;
	if (zone_dataset_name_check(dataset, &dsnamelen) != 0)
		return (0);
	if (INGLOBALZONE(curproc)) {
		if (write != NULL)
			*write = 1;
		return (1);
	}

	mutex_enter(&zone_datasets_lock);
	visible = 0;
	zds = zone_datasets_lookup(crgetzoneid(curproc->cred));
	if (zds == NULL)
		goto done;

	list_for_each_entry(zd, &zds->zds_datasets, zd_list) {
		zd_len = strlen(zd->zd_dsname);
		/*
		 * The dataset is visible only if it matches one of the
		 * namespace's entries.  If it does, it's writable if it's
		 * an exact match for or deeper than a namespace entry,
		 * otherwise it's read-only.
		 */
		if (zd_len > dsnamelen) {
			visible = bcmp(zd->zd_dsname, dataset,
			    dsnamelen) == 0 &&
			    zd->zd_dsname[dsnamelen] == '/';
		} else {
			visible = bcmp(zd->zd_dsname, dataset, zd_len) == 0;
			if (visible && zd_len > dsnamelen)
				visible = dataset[zd_len] == '/';
			if (visible) {
				if (write != NULL)
					*write = 1;
			}
		}
	}

done:
	mutex_exit(&zone_datasets_lock);
	return (visible);
}
EXPORT_SYMBOL(zone_dataset_visible);

#if defined(CONFIG_USER_NS)
static unsigned int
user_ns_zoneid(struct user_namespace *user_ns)
{
	unsigned int r;

#ifdef HAVE_USER_NS_COMMON_INUM
	r = user_ns->ns.inum;
#else
	r = user_ns->proc_inum;
#endif

	return (r);
}
#endif

unsigned int
global_zoneid(void)
{
	unsigned int z = 0;

#if defined(CONFIG_USER_NS)
	z = user_ns_zoneid(&init_user_ns);
#endif

	return (z);
}
EXPORT_SYMBOL(global_zoneid);

unsigned int
crgetzoneid(const cred_t *cr)
{
	unsigned int r = 0;

#if defined(CONFIG_USER_NS)
	r = user_ns_zoneid(cr->user_ns);
#endif

	return (r);
}
EXPORT_SYMBOL(crgetzoneid);

boolean_t
inglobalzone(proc_t *proc)
{

#if defined(CONFIG_USER_NS)
	return (proc->cred->user_ns == &init_user_ns);
#else
	return (B_TRUE);
#endif
}
EXPORT_SYMBOL(inglobalzone);

int
spl_zone_init(void)
{
	mutex_init(&zone_datasets_lock, NULL, MUTEX_DEFAULT, NULL);
	INIT_LIST_HEAD(&zone_datasets);
	return (0);
}

void
spl_zone_fini(void)
{
	zone_datasets_t *zds;
	zone_dataset_t *zd;

	/*
	 * It would be better to assert an empty zone_datasets, but since
	 * there's no automatic mechanism for cleaning them up if the user
	 * namespace is destroyed, just do it here, since spl is about to go
	 * out of context.
	 */
	while (!list_empty(&zone_datasets)) {
		zds = list_entry(zone_datasets.next, zone_datasets_t, zds_list);
		while (!list_empty(&zds->zds_datasets)) {
			zd = list_entry(zds->zds_datasets.next,
			    zone_dataset_t, zd_list);
			list_del(&zd->zd_list);
			kmem_free(zd, sizeof (*zd) + zd->zd_dsnamelen + 1);
		}
		list_del(&zds->zds_list);
		kmem_free(zds, sizeof (*zds));
	}
}
