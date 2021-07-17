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
 *
 * Copyright (C) 2013 Jorgen Lundman <lundman@lundman.net>
 *
 */

#include <sys/processor.h>

extern int cpu_number(void);

#ifdef __x86_64__
#define	cpuid(func, a, b, c, d) \
	__asm__ __volatile__( \
	"        pushq %%rbx        \n" \
	"        xorq %%rcx,%%rcx   \n" \
	"        cpuid              \n" \
	"        movq %%rbx, %%rsi  \n" \
	"        popq %%rbx         \n" : \
	"=a" (a), "=S" (b), "=c" (c), "=d" (d) : "a" (func))
#else /* Add ARM */
#define	cpuid(func, a, b, c, d) \
	a = b = c = d = 0
#endif

static uint64_t cpuid_features = 0ULL;
static uint64_t cpuid_features_leaf7 = 0ULL;
static boolean_t cpuid_has_xgetbv = B_FALSE;

uint32_t
getcpuid()
{
#if defined(__aarch64__)
	// Find arm64 solution.
	return (0);
#else
	return ((uint32_t)cpu_number());
#endif
}

uint64_t
spl_cpuid_features(void)
{
	static int first_time = 1;
	uint64_t a, b, c, d;

	if (first_time == 1) {
		first_time = 0;
		cpuid(0, a, b, c, d);
		if (a >= 1) {
			cpuid(1, a, b, c, d);
			cpuid_features = d;
			cpuid_has_xgetbv = (c & 0x08000000); // number->#define
		}
		if (a >= 7) {
			cpuid(7, a, b, c, d);
			cpuid_features_leaf7 = b;
			cpuid_features_leaf7 |= (c << 32);
		}
	}
	return (cpuid_features);
}

uint64_t
spl_cpuid_leaf7_features(void)
{
	return (cpuid_features_leaf7);
}
