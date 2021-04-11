
/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 2021 Tino Reichardt <milky-zfs@mcmilk.de>
 */

#include <sys/zfs_context.h>
#include "blake3_impl.h"

static const blake3_impl_ops_t *blake3_impls[] = {
	&blake3_generic_impl,
#if defined(__x86_64) && defined(HAVE_SSE2)
	&blake3_sse2_impl,
#endif
#if defined(__x86_64) && defined(HAVE_SSE4_1)
	&blake3_sse41_impl,
#endif
#if defined(__x86_64) && defined(HAVE_SSE4_1) && defined(HAVE_AVX2)
	&blake3_avx2_impl,
#endif
#if defined(__x86_64) && defined(HAVE_AVX512F) && defined(HAVE_AVX512VL)
	&blake3_avx512_impl,
#endif
#if defined(__aarch64__) && defined(HAVE_ARM_NEON_H)
	&blake3_neon_impl,
#endif
};

/*
 * Returns generic BLAKE3 implementation
 */
const blake3_impl_ops_t *
blake3_impl_get_generic_ops(void)
{
	return (&blake3_generic_impl);
}

/*
 * Returns optimal allowed BLAKE3 implementation
 */
const blake3_impl_ops_t *
blake3_impl_get_ops(void)
{
	static const blake3_impl_ops_t *blake3_optimal_impls = 0;

	if (blake3_optimal_impls) {
		return (blake3_optimal_impls);
	}

	/*
	 * XXX
	 * 1) micro-benchmark
	 * 2) take fastest one
	 */

	/*
	 * The last implementation is assumed to be the fastest.
	 */
	for (int i = 0; i < ARRAY_SIZE(blake3_impls); i++) {
		if (blake3_impls[i]->is_supported())
			blake3_optimal_impls = blake3_impls[i];
	}

	return (blake3_optimal_impls);
}
