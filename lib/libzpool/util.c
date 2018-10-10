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
 * Copyright (c) 2016, 2018 by Delphix. All rights reserved.
 * Copyright 2017 Jason King
 * Copyright (c) 2017, Intel Corporation.
 */

#include <assert.h>
#include <sys/zfs_context.h>
#include <sys/avl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/spa.h>
#include <sys/fs/zfs.h>
#include <sys/refcount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/zfs_ioctl.h>
#include <dlfcn.h>
#include <libnvpair.h>

/*
 * Routines needed by more than one client of libzpool.
 */

/* The largest suffix that can fit, aka an exabyte (2^60 / 10^18) */
#define	INDEX_MAX	(6)

/* Verify INDEX_MAX fits */
CTASSERT_GLOBAL(INDEX_MAX * 10 < sizeof (uint64_t) * 8);

void
nicenum_scale(uint64_t n, size_t units, char *buf, size_t buflen,
    uint32_t flags)
{
	uint64_t divamt = 1024;
	uint64_t divisor = 1;
	int index = 0;
	int rc = 0;
	char u;

	if (units == 0)
		units = 1;

	if (n > 0) {
		n *= units;
		if (n < units)
			goto overflow;
	}

	if (flags & NN_DIVISOR_1000)
		divamt = 1000;

	/*
	 * This tries to find the suffix S(n) such that
	 * S(n) <= n < S(n+1), where S(n) = 2^(n*10) | 10^(3*n)
	 * (i.e. 1024/1000, 1,048,576/1,000,000, etc).  Stop once S(n)
	 * is the largest prefix supported (i.e. don't bother computing
	 * and checking S(n+1).  Since INDEX_MAX should be the largest
	 * suffix that fits (currently an exabyte), S(INDEX_MAX + 1) is
	 * never checked as it would overflow.
	 */
	while (index < INDEX_MAX) {
		uint64_t newdiv = divisor * divamt;

		/* CTASSERT() guarantee these never trip */
		VERIFY3U(newdiv, >=, divamt);
		VERIFY3U(newdiv, >=, divisor);

		if (n < newdiv)
			break;

		divisor = newdiv;
		index++;
	}

	u = " KMGTPE"[index];

	if (index == 0) {
		rc = snprintf(buf, buflen, "%llu", (u_longlong_t)n);
	} else if (n % divisor == 0) {
		/*
		 * If this is an even multiple of the base, always display
		 * without any decimal precision.
		 */
		rc = snprintf(buf, buflen, "%llu%c",
		    (u_longlong_t)(n / divisor), u);
	} else {
		/*
		 * We want to choose a precision that reflects the best choice
		 * for fitting in 5 characters.  This can get rather tricky
		 * when we have numbers that are very close to an order of
		 * magnitude.  For example, when displaying 10239 (which is
		 * really 9.999K), we want only a single place of precision
		 * for 10.0K.  We could develop some complex heuristics for
		 * this, but it's much easier just to try each combination
		 * in turn.
		 */
		int i;
		for (i = 2; i >= 0; i--) {
			if ((rc = snprintf(buf, buflen, "%.*f%c", i,
			    (double)n / divisor, u)) <= 5)
				break;
		}
	}

	if (rc + 1 > buflen || rc < 0)
		goto overflow;

	return;

overflow:
	/* prefer a more verbose message if possible */
	if (buflen > 10)
		(void) strlcpy(buf, "<overflow>", buflen);
	else
		(void) strlcpy(buf, "??", buflen);
}

void
nicenum(uint64_t num, char *buf, size_t buflen)
{
	nicenum_scale(num, 1, buf, buflen, 0);
}

static void
show_vdev_stats(const char *desc, const char *ctype, nvlist_t *nv, int indent)
{
	vdev_stat_t *vs;
	vdev_stat_t *v0 = { 0 };
	uint64_t sec;
	uint64_t is_log = 0;
	nvlist_t **child;
	uint_t c, children;
	char used[6], avail[6];
	char rops[6], wops[6], rbytes[6], wbytes[6], rerr[6], werr[6], cerr[6];

	v0 = umem_zalloc(sizeof (*v0), UMEM_NOFAIL);

	if (indent == 0 && desc != NULL) {
		(void) printf("                           "
		    " capacity   operations   bandwidth  ---- errors ----\n");
		(void) printf("description                "
		    "used avail  read write  read write  read write cksum\n");
	}

	if (desc != NULL) {
		char *suffix = "", *bias = NULL;
		char bias_suffix[32];

		(void) nvlist_lookup_uint64(nv, ZPOOL_CONFIG_IS_LOG, &is_log);
		(void) nvlist_lookup_string(nv, ZPOOL_CONFIG_ALLOCATION_BIAS,
		    &bias);
		if (nvlist_lookup_uint64_array(nv, ZPOOL_CONFIG_VDEV_STATS,
		    (uint64_t **)&vs, &c) != 0)
			vs = v0;

		if (bias != NULL) {
			(void) snprintf(bias_suffix, sizeof (bias_suffix),
			    " (%s)", bias);
			suffix = bias_suffix;
		} else if (is_log) {
			suffix = " (log)";
		}

		sec = MAX(1, vs->vs_timestamp / NANOSEC);

		nicenum(vs->vs_alloc, used, sizeof (used));
		nicenum(vs->vs_space - vs->vs_alloc, avail, sizeof (avail));
		nicenum(vs->vs_ops[ZIO_TYPE_READ] / sec, rops, sizeof (rops));
		nicenum(vs->vs_ops[ZIO_TYPE_WRITE] / sec, wops, sizeof (wops));
		nicenum(vs->vs_bytes[ZIO_TYPE_READ] / sec, rbytes,
		    sizeof (rbytes));
		nicenum(vs->vs_bytes[ZIO_TYPE_WRITE] / sec, wbytes,
		    sizeof (wbytes));
		nicenum(vs->vs_read_errors, rerr, sizeof (rerr));
		nicenum(vs->vs_write_errors, werr, sizeof (werr));
		nicenum(vs->vs_checksum_errors, cerr, sizeof (cerr));

		(void) printf("%*s%s%*s%*s%*s %5s %5s %5s %5s %5s %5s %5s\n",
		    indent, "",
		    desc,
		    (int)(indent+strlen(desc)-25-(vs->vs_space ? 0 : 12)),
		    suffix,
		    vs->vs_space ? 6 : 0, vs->vs_space ? used : "",
		    vs->vs_space ? 6 : 0, vs->vs_space ? avail : "",
		    rops, wops, rbytes, wbytes, rerr, werr, cerr);
	}
	free(v0);

	if (nvlist_lookup_nvlist_array(nv, ctype, &child, &children) != 0)
		return;

	for (c = 0; c < children; c++) {
		nvlist_t *cnv = child[c];
		char *cname = NULL, *tname;
		uint64_t np;
		int len;
		if (nvlist_lookup_string(cnv, ZPOOL_CONFIG_PATH, &cname) &&
		    nvlist_lookup_string(cnv, ZPOOL_CONFIG_TYPE, &cname))
			cname = "<unknown>";
		len = strlen(cname) + 2;
		tname = umem_zalloc(len, UMEM_NOFAIL);
		(void) strlcpy(tname, cname, len);
		if (nvlist_lookup_uint64(cnv, ZPOOL_CONFIG_NPARITY, &np) == 0)
			tname[strlen(tname)] = '0' + np;
		show_vdev_stats(tname, ctype, cnv, indent + 2);
		free(tname);
	}
}

void
show_pool_stats(spa_t *spa)
{
	nvlist_t *config, *nvroot;
	char *name;

	VERIFY(spa_get_stats(spa_name(spa), &config, NULL, 0) == 0);

	VERIFY(nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
	    &nvroot) == 0);
	VERIFY(nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME,
	    &name) == 0);

	show_vdev_stats(name, ZPOOL_CONFIG_CHILDREN, nvroot, 0);
	show_vdev_stats(NULL, ZPOOL_CONFIG_L2CACHE, nvroot, 0);
	show_vdev_stats(NULL, ZPOOL_CONFIG_SPARES, nvroot, 0);

	nvlist_free(config);
}

/*
 * Sets given global variable in libzpool to given unsigned 32-bit value.
 * arg: "<variable>=<value>"
 */
int
set_global_var(char *arg)
{
	void *zpoolhdl;
	char *varname = arg, *varval;
	u_longlong_t val;

#ifndef _LITTLE_ENDIAN
	/*
	 * On big endian systems changing a 64-bit variable would set the high
	 * 32 bits instead of the low 32 bits, which could cause unexpected
	 * results.
	 */
	fprintf(stderr, "Setting global variables is only supported on "
	    "little-endian systems\n");
	return (ENOTSUP);
#endif
	if (arg != NULL && (varval = strchr(arg, '=')) != NULL) {
		*varval = '\0';
		varval++;
		val = strtoull(varval, NULL, 0);
		if (val > UINT32_MAX) {
			fprintf(stderr, "Value for global variable '%s' must "
			    "be a 32-bit unsigned integer\n", varname);
			return (EOVERFLOW);
		}
	} else {
		return (EINVAL);
	}

	zpoolhdl = dlopen("libzpool.so", RTLD_LAZY);
	if (zpoolhdl != NULL) {
		uint32_t *var;
		var = dlsym(zpoolhdl, varname);
		if (var == NULL) {
			fprintf(stderr, "Global variable '%s' does not exist "
			    "in libzpool.so\n", varname);
			return (EINVAL);
		}
		*var = (uint32_t)val;

		dlclose(zpoolhdl);
	} else {
		fprintf(stderr, "Failed to open libzpool.so to set global "
		    "variable\n");
		return (EIO);
	}

	return (0);
}

static void
locate_binary_path(const char *binary, char *path, size_t len)
{
	/*
	 * Try to use the in-tree path. If not successful, just
	 * allow execv to search for binary through PATH.
	 */
	if (realpath(getexecname(), path) == NULL)
		goto filename;

	/*
	 * our executable basename is typically "ztest" or "zdb"
	 */
	char *basename = strrchr(path, '/');
	if (basename == NULL)
		goto filename;
	basename++;

	/*
	 * in-tree match is typically for "/cmd/ztest/" or "/cmd/zdb/"
	 */
	char match[MAXNAMELEN];
	(void) snprintf(match, sizeof (match), "/cmd/%s/", basename);

	char *parent = strstr(path, match);
	if (parent != NULL) {
		struct stat s;
		size_t resid = len - (parent - path);
		(void) snprintf(parent, resid, "/cmd/%s/%s", binary, binary);
		if (stat(path, &s) == 0)
			return;
	}

filename:
	strlcpy(path, binary, len);
}

static int
run_zpool_import_config(const char *pool, const char *config, int nsearch,
    char *searchdirs[])
{
	char *bin;
	char **argv;
	const int len = MAXPATHLEN + MAXNAMELEN + 20;
	int result;
	int argc = 0, argsiz;

	bin = umem_alloc(len, UMEM_NOFAIL);
	locate_binary_path("zpool", bin, len);

	/*
	 * basic argv set = {"zpool", "import", "-C", tmpfile, pool, NULL}
	 */
	argsiz = 6 * sizeof (char *);
	if (nsearch > 0)
		argsiz += (nsearch * 2) * sizeof (char *);
	argv = umem_alloc(argsiz, UMEM_NOFAIL);

	argv[argc++] = bin;
	argv[argc++] = "import";
	argv[argc++] = "-C";
	argv[argc++] = (char *)config;
	for (int i = 0; i < nsearch; i++) {
		argv[argc++] = "-d";
		argv[argc++] = searchdirs[i];
	}
	argv[argc++] = (char *)pool;
	argv[argc++] = NULL;

	pid_t pid = vfork();
	switch (pid) {
	case -1:
		_exit(-1);

	case 0: /* Child process */
	{
		int fd = open("/dev/null", O_WRONLY);

		if (fd > 0) {
			(void) dup2(fd, 1);
			(void) dup2(fd, 2);
			(void) close(fd);
		}

		if (bin[0] == '/')
			(void) execvp(bin, argv);
		else
			(void) execv(bin, argv);

		_exit(-1);
	}
	default: /* Parent process */
	{
		int error, status;

		while ((error = waitpid(pid, &status, 0)) == -1 &&
		    errno == EINTR) { }

		if (error < 0 || !WIFEXITED(status)) {
			result = -1;
			break;
		}

		result = WEXITSTATUS(status);
		break;
	}
	}

	umem_free(bin, len);
	umem_free(argv, argsiz);

	return (result);
}

static boolean_t
check_pool_active(const char *pool)
{
	zfs_cmd_t *zcp;
	nvlist_t *innvl;
	char *packed = NULL;
	size_t size = 0;
	int fd, ret;

	/*
	 * Use ZFS_IOC_POOL_SYNC to confirm if a pool is active
	 */

	fd = open("/dev/zfs", O_RDWR);
	if (fd < 0)
		return (B_FALSE);

	zcp = umem_zalloc(sizeof (zfs_cmd_t), UMEM_NOFAIL);

	innvl = fnvlist_alloc();
	fnvlist_add_boolean_value(innvl, "force", B_FALSE);

	(void) strlcpy(zcp->zc_name, pool, sizeof (zcp->zc_name));
	packed = fnvlist_pack(innvl, &size);
	zcp->zc_nvlist_src = (uint64_t)(uintptr_t)packed;
	zcp->zc_nvlist_src_size = size;

	ret = ioctl(fd, ZFS_IOC_POOL_SYNC, zcp);

	fnvlist_pack_free(packed, size);
	free((void *)(uintptr_t)zcp->zc_nvlist_dst);
	nvlist_free(innvl);
	umem_free(zcp, sizeof (zfs_cmd_t));

	(void) close(fd);

	return (ret == 0);
}

static nvlist_t *
cache_find_pool(nvlist_t *raw, const char *pool)
{
	nvlist_t *config = NULL;
	nvpair_t *elem = NULL;
	uint64_t guid = strtoull(pool, NULL, 0);

	/*
	 * walk the configs in raw looking for a match by name or guid
	 */
	while ((elem = nvlist_next_nvpair(raw, elem)) != NULL) {
		nvlist_t *nvl;
		char *s;
		uint64_t g;

		VERIFY3U(nvpair_type(elem), ==, DATA_TYPE_NVLIST);

		nvl = fnvpair_value_nvlist(elem);

		if (guid != 0) {
			g = fnvlist_lookup_uint64(nvl, ZPOOL_CONFIG_POOL_GUID);
			if (guid == g) {
				config = fnvlist_dup(nvl);
				break;
			}
		}

		s = fnvlist_lookup_string(nvl, ZPOOL_CONFIG_POOL_NAME);
		if (strcmp(pool, s) == 0) {
			config = fnvlist_dup(nvl);
			break;
		}
	}

	return (config);
}

/*
 * Run the zpool(8) command to find the config for 'pool' where the
 * pool value can be a name or a guid.
 *
 * Used by ztest(1) and zdb(8)
 */
nvlist_t *
lzp_find_pool_config(const char *pool, int nsearch, char *searchdirs[],
    boolean_t active_ok)
{
	nvlist_t *config = NULL;
	struct stat64 statbuf;
	char *packed;
	int fd;

	/*
	 * Create a unique tempfile to hold the config
	 */
	char tmpfile[] = "/tmp/lzp_pool_config_XXXXXX";
	fd = mkstemp(tmpfile);
	if (fd < 0)
		return (NULL);
	(void) close(fd);

	if (run_zpool_import_config(pool, tmpfile, nsearch, searchdirs) != 0) {
		(void) unlink(tmpfile);
		return (NULL);
	}

	fd = open(tmpfile, O_RDONLY);
	if (fd < 0) {
		(void) unlink(tmpfile);
		return (NULL);
	}
	if (fstat64(fd, &statbuf) != 0) {
		(void) close(fd);
		(void) unlink(tmpfile);
		return (NULL);
	}

	packed = umem_alloc(statbuf.st_size, UMEM_NOFAIL);

	char *bufptr = packed;
	int residual = statbuf.st_size;

	while (residual > 0) {
		ssize_t bytes = read(fd, bufptr, residual);
		if (bytes < 0)
			goto exit;
		bufptr += bytes;
		residual -= bytes;
	}

	nvlist_t *raw = fnvlist_unpack(packed, statbuf.st_size);
	config = cache_find_pool(raw, pool);
	nvlist_free(raw);

	if (config && !active_ok && check_pool_active(pool)) {
		nvlist_free(config);
		config = NULL;
	}
exit:
	(void) close(fd);
	(void) unlink(tmpfile);
	umem_free(packed, statbuf.st_size);

	return (config);
}

/*
 * Given a cache file, return the config that matches
 * 'pool' (can be a name or a guid)
 */
nvlist_t *
lzp_find_import_cached(const char *pool, const char *cachefile,
    boolean_t active_ok)
{
	char *buf;
	int fd;
	struct stat64 statbuf;
	nvlist_t *raw, *config = NULL;

	if ((fd = open(cachefile, O_RDONLY)) < 0)
		return (NULL);

	if (fstat64(fd, &statbuf) != 0) {
		(void) close(fd);
		return (NULL);
	}

	buf = umem_zalloc(statbuf.st_size, UMEM_NOFAIL);
	if (buf == NULL) {
		(void) close(fd);
		return (NULL);
	}

	if (read(fd, buf, statbuf.st_size) != statbuf.st_size) {
		(void) close(fd);
		umem_free(buf, statbuf.st_size);
		return (NULL);
	}

	(void) close(fd);

	if (nvlist_unpack(buf, statbuf.st_size, &raw, 0) != 0) {
		umem_free(buf, statbuf.st_size);
		return (NULL);
	}

	umem_free(buf, statbuf.st_size);

	config = cache_find_pool(raw, pool);

	if (config && !active_ok && check_pool_active(pool)) {
		nvlist_free(config);
		config = NULL;
	}

	nvlist_free(raw);

	return (config);
}
