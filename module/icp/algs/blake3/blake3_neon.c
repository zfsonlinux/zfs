
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
 * Based on BLAKE3 v0.3.7, https://github.com/BLAKE3-team/BLAKE3
 * Copyright (c) 2019-2020 Samuel Neves and Jack O'Connor
 * Copyright (c) 2021 Tino Reichardt <milky-zfs@mcmilk.de>
 */

#if defined(__aarch64__) && defined(HAVE_ARM_NEON_H)

#include <arm_neon.h>

#include <sys/types.h>
#include <sys/strings.h>
#include <sys/simd.h>

#include "blake3_impl.h"

static inline uint32x4_t loadu_128(const uint8_t src[16])
{
	uint32x4_t x;
	memcpy(&x, src, 16);
	return (x);
}

static inline void storeu_128(uint32x4_t src, uint8_t dest[16])
{
	memcpy(dest, &src, 16);
}

static inline uint32x4_t add_128(uint32x4_t a, uint32x4_t b)
{
	return (vaddq_u32(a, b));
}

static inline uint32x4_t xor_128(uint32x4_t a, uint32x4_t b)
{
	return (veorq_u32(a, b));
}

static inline uint32x4_t set1_128(uint32_t x)
{
	return (vld1q_dup_u32(&x));
}

static inline uint32x4_t set4(uint32_t a, uint32_t b, uint32_t c, uint32_t d)
{
	uint32_t array[4] = { a, b, c, d };
	return (vld1q_u32(array));
}

static inline uint32x4_t rot16_128(uint32x4_t x)
{
	return (vorrq_u32(vshrq_n_u32(x, 16), vshlq_n_u32(x, 32 - 16)));
}

static inline uint32x4_t rot12_128(uint32x4_t x)
{
	return (vorrq_u32(vshrq_n_u32(x, 12), vshlq_n_u32(x, 32 - 12)));
}

static inline uint32x4_t rot8_128(uint32x4_t x)
{
	return (vorrq_u32(vshrq_n_u32(x, 8), vshlq_n_u32(x, 32 - 8)));
}

static inline uint32x4_t rot7_128(uint32x4_t x)
{
	return (vorrq_u32(vshrq_n_u32(x, 7), vshlq_n_u32(x, 32 - 7)));
}

/*
 * ----------------------------------------------------------------------------
 * hash4_neon
 * ----------------------------------------------------------------------------
 */

static void blake3_compress_in_place_generic(uint32_t cv[8],
    const uint8_t block[BLAKE3_BLOCK_LEN], uint8_t block_len,
    uint64_t counter, uint8_t flags)
{
	const blake3_impl_ops_t *ops = blake3_impl_get_generic_ops();
	ops->compress_in_place(cv, block, block_len, counter, flags);
}

static void blake3_compress_xof_generic(const uint32_t cv[8],
    const uint8_t block[BLAKE3_BLOCK_LEN], uint8_t block_len,
    uint64_t counter, uint8_t flags, uint8_t out[64])
{
	const blake3_impl_ops_t *ops = blake3_impl_get_generic_ops();
	ops->compress_in_xof(cv, block, block_len, counter, flags, out);
}

static inline void round_fn4(uint32x4_t v[16], uint32x4_t m[16], size_t r)
{
	v[0] = add_128(v[0], m[(size_t)MSG_SCHEDULE[r][0]]);
	v[1] = add_128(v[1], m[(size_t)MSG_SCHEDULE[r][2]]);
	v[2] = add_128(v[2], m[(size_t)MSG_SCHEDULE[r][4]]);
	v[3] = add_128(v[3], m[(size_t)MSG_SCHEDULE[r][6]]);
	v[0] = add_128(v[0], v[4]);
	v[1] = add_128(v[1], v[5]);
	v[2] = add_128(v[2], v[6]);
	v[3] = add_128(v[3], v[7]);
	v[12] = xor_128(v[12], v[0]);
	v[13] = xor_128(v[13], v[1]);
	v[14] = xor_128(v[14], v[2]);
	v[15] = xor_128(v[15], v[3]);
	v[12] = rot16_128(v[12]);
	v[13] = rot16_128(v[13]);
	v[14] = rot16_128(v[14]);
	v[15] = rot16_128(v[15]);
	v[8] = add_128(v[8], v[12]);
	v[9] = add_128(v[9], v[13]);
	v[10] = add_128(v[10], v[14]);
	v[11] = add_128(v[11], v[15]);
	v[4] = xor_128(v[4], v[8]);
	v[5] = xor_128(v[5], v[9]);
	v[6] = xor_128(v[6], v[10]);
	v[7] = xor_128(v[7], v[11]);
	v[4] = rot12_128(v[4]);
	v[5] = rot12_128(v[5]);
	v[6] = rot12_128(v[6]);
	v[7] = rot12_128(v[7]);
	v[0] = add_128(v[0], m[(size_t)MSG_SCHEDULE[r][1]]);
	v[1] = add_128(v[1], m[(size_t)MSG_SCHEDULE[r][3]]);
	v[2] = add_128(v[2], m[(size_t)MSG_SCHEDULE[r][5]]);
	v[3] = add_128(v[3], m[(size_t)MSG_SCHEDULE[r][7]]);
	v[0] = add_128(v[0], v[4]);
	v[1] = add_128(v[1], v[5]);
	v[2] = add_128(v[2], v[6]);
	v[3] = add_128(v[3], v[7]);
	v[12] = xor_128(v[12], v[0]);
	v[13] = xor_128(v[13], v[1]);
	v[14] = xor_128(v[14], v[2]);
	v[15] = xor_128(v[15], v[3]);
	v[12] = rot8_128(v[12]);
	v[13] = rot8_128(v[13]);
	v[14] = rot8_128(v[14]);
	v[15] = rot8_128(v[15]);
	v[8] = add_128(v[8], v[12]);
	v[9] = add_128(v[9], v[13]);
	v[10] = add_128(v[10], v[14]);
	v[11] = add_128(v[11], v[15]);
	v[4] = xor_128(v[4], v[8]);
	v[5] = xor_128(v[5], v[9]);
	v[6] = xor_128(v[6], v[10]);
	v[7] = xor_128(v[7], v[11]);
	v[4] = rot7_128(v[4]);
	v[5] = rot7_128(v[5]);
	v[6] = rot7_128(v[6]);
	v[7] = rot7_128(v[7]);

	v[0] = add_128(v[0], m[(size_t)MSG_SCHEDULE[r][8]]);
	v[1] = add_128(v[1], m[(size_t)MSG_SCHEDULE[r][10]]);
	v[2] = add_128(v[2], m[(size_t)MSG_SCHEDULE[r][12]]);
	v[3] = add_128(v[3], m[(size_t)MSG_SCHEDULE[r][14]]);
	v[0] = add_128(v[0], v[5]);
	v[1] = add_128(v[1], v[6]);
	v[2] = add_128(v[2], v[7]);
	v[3] = add_128(v[3], v[4]);
	v[15] = xor_128(v[15], v[0]);
	v[12] = xor_128(v[12], v[1]);
	v[13] = xor_128(v[13], v[2]);
	v[14] = xor_128(v[14], v[3]);
	v[15] = rot16_128(v[15]);
	v[12] = rot16_128(v[12]);
	v[13] = rot16_128(v[13]);
	v[14] = rot16_128(v[14]);
	v[10] = add_128(v[10], v[15]);
	v[11] = add_128(v[11], v[12]);
	v[8] = add_128(v[8], v[13]);
	v[9] = add_128(v[9], v[14]);
	v[5] = xor_128(v[5], v[10]);
	v[6] = xor_128(v[6], v[11]);
	v[7] = xor_128(v[7], v[8]);
	v[4] = xor_128(v[4], v[9]);
	v[5] = rot12_128(v[5]);
	v[6] = rot12_128(v[6]);
	v[7] = rot12_128(v[7]);
	v[4] = rot12_128(v[4]);
	v[0] = add_128(v[0], m[(size_t)MSG_SCHEDULE[r][9]]);
	v[1] = add_128(v[1], m[(size_t)MSG_SCHEDULE[r][11]]);
	v[2] = add_128(v[2], m[(size_t)MSG_SCHEDULE[r][13]]);
	v[3] = add_128(v[3], m[(size_t)MSG_SCHEDULE[r][15]]);
	v[0] = add_128(v[0], v[5]);
	v[1] = add_128(v[1], v[6]);
	v[2] = add_128(v[2], v[7]);
	v[3] = add_128(v[3], v[4]);
	v[15] = xor_128(v[15], v[0]);
	v[12] = xor_128(v[12], v[1]);
	v[13] = xor_128(v[13], v[2]);
	v[14] = xor_128(v[14], v[3]);
	v[15] = rot8_128(v[15]);
	v[12] = rot8_128(v[12]);
	v[13] = rot8_128(v[13]);
	v[14] = rot8_128(v[14]);
	v[10] = add_128(v[10], v[15]);
	v[11] = add_128(v[11], v[12]);
	v[8] = add_128(v[8], v[13]);
	v[9] = add_128(v[9], v[14]);
	v[5] = xor_128(v[5], v[10]);
	v[6] = xor_128(v[6], v[11]);
	v[7] = xor_128(v[7], v[8]);
	v[4] = xor_128(v[4], v[9]);
	v[5] = rot7_128(v[5]);
	v[6] = rot7_128(v[6]);
	v[7] = rot7_128(v[7]);
	v[4] = rot7_128(v[4]);
}

static inline void transpose_vecs_128(uint32x4_t vecs[4])
{
	uint32x4x2_t rows01 = vtrnq_u32(vecs[0], vecs[1]);
	uint32x4x2_t rows23 = vtrnq_u32(vecs[2], vecs[3]);

	vecs[0] = vcombine_u32(vget_low_u32(rows01.val[0]),
	    vget_low_u32(rows23.val[0]));
	vecs[1] = vcombine_u32(vget_low_u32(rows01.val[1]),
	    vget_low_u32(rows23.val[1]));
	vecs[2] = vcombine_u32(vget_high_u32(rows01.val[0]),
	    vget_high_u32(rows23.val[0]));
	vecs[3] = vcombine_u32(vget_high_u32(rows01.val[1]),
	    vget_high_u32(rows23.val[1]));
}

static inline void transpose_msg_vecs4(const uint8_t * const *inputs,
    size_t block_offset, uint32x4_t out[16])
{
	out[0] = loadu_128(&inputs[0][block_offset + 0 * sizeof (uint32x4_t)]);
	out[1] = loadu_128(&inputs[1][block_offset + 0 * sizeof (uint32x4_t)]);
	out[2] = loadu_128(&inputs[2][block_offset + 0 * sizeof (uint32x4_t)]);
	out[3] = loadu_128(&inputs[3][block_offset + 0 * sizeof (uint32x4_t)]);
	out[4] = loadu_128(&inputs[0][block_offset + 1 * sizeof (uint32x4_t)]);
	out[5] = loadu_128(&inputs[1][block_offset + 1 * sizeof (uint32x4_t)]);
	out[6] = loadu_128(&inputs[2][block_offset + 1 * sizeof (uint32x4_t)]);
	out[7] = loadu_128(&inputs[3][block_offset + 1 * sizeof (uint32x4_t)]);
	out[8] = loadu_128(&inputs[0][block_offset + 2 * sizeof (uint32x4_t)]);
	out[9] = loadu_128(&inputs[1][block_offset + 2 * sizeof (uint32x4_t)]);
	out[10] = loadu_128(&inputs[2][block_offset + 2 * sizeof (uint32x4_t)]);
	out[11] = loadu_128(&inputs[3][block_offset + 2 * sizeof (uint32x4_t)]);
	out[12] = loadu_128(&inputs[0][block_offset + 3 * sizeof (uint32x4_t)]);
	out[13] = loadu_128(&inputs[1][block_offset + 3 * sizeof (uint32x4_t)]);
	out[14] = loadu_128(&inputs[2][block_offset + 3 * sizeof (uint32x4_t)]);
	out[15] = loadu_128(&inputs[3][block_offset + 3 * sizeof (uint32x4_t)]);
	transpose_vecs_128(&out[0]);
	transpose_vecs_128(&out[4]);
	transpose_vecs_128(&out[8]);
	transpose_vecs_128(&out[12]);
}

static inline void load_counters4(uint64_t counter, boolean_t increment_counter,
    uint32x4_t *out_low, uint32x4_t *out_high)
{
	uint64_t mask = (increment_counter ? ~0 : 0);
	*out_low = set4(counter_low(counter + (mask & 0)),
	    counter_low(counter + (mask & 1)),
	    counter_low(counter + (mask & 2)),
	    counter_low(counter + (mask & 3)));
	*out_high = set4(counter_high(counter + (mask & 0)),
	    counter_high(counter + (mask & 1)),
	    counter_high(counter + (mask & 2)),
	    counter_high(counter + (mask & 3)));
}

/*
 * ----------------------------------------------------------------------------
 * hash_many_neon
 * ----------------------------------------------------------------------------
 */

static void blake3_hash4_neon(const uint8_t * const *inputs, size_t blocks,
    const uint32_t key[8], uint64_t counter, boolean_t increment_counter,
    uint8_t flags, uint8_t flags_start, uint8_t flags_end, uint8_t *out)
{
	uint32x4_t h_vecs[8] = {
		set1_128(key[0]), set1_128(key[1]), set1_128(key[2]),
		set1_128(key[3]),
		set1_128(key[4]), set1_128(key[5]), set1_128(key[6]),
		set1_128(key[7]),
	};
	uint32x4_t counter_low_vec, counter_high_vec;
	load_counters4(counter, increment_counter, &counter_low_vec,
	    &counter_high_vec);
	uint8_t block_flags = flags | flags_start;

	for (size_t block = 0; block < blocks; block++) {
		if (block + 1 == blocks) {
			block_flags |= flags_end;
		}
		uint32x4_t block_len_vec = set1_128(BLAKE3_BLOCK_LEN);
		uint32x4_t block_flags_vec = set1_128(block_flags);
		uint32x4_t msg_vecs[16];
		transpose_msg_vecs4(inputs, block * BLAKE3_BLOCK_LEN, msg_vecs);

		uint32x4_t v[16] = {
			h_vecs[0], h_vecs[1], h_vecs[2], h_vecs[3],
			h_vecs[4], h_vecs[5], h_vecs[6], h_vecs[7],
			set1_128(IV[0]), set1_128(IV[1]),
			set1_128(IV[2]),
			set1_128(IV[3]),
			counter_low_vec, counter_high_vec, block_len_vec,
			block_flags_vec,
		};
		round_fn4(v, msg_vecs, 0);
		round_fn4(v, msg_vecs, 1);
		round_fn4(v, msg_vecs, 2);
		round_fn4(v, msg_vecs, 3);
		round_fn4(v, msg_vecs, 4);
		round_fn4(v, msg_vecs, 5);
		round_fn4(v, msg_vecs, 6);
		h_vecs[0] = xor_128(v[0], v[8]);
		h_vecs[1] = xor_128(v[1], v[9]);
		h_vecs[2] = xor_128(v[2], v[10]);
		h_vecs[3] = xor_128(v[3], v[11]);
		h_vecs[4] = xor_128(v[4], v[12]);
		h_vecs[5] = xor_128(v[5], v[13]);
		h_vecs[6] = xor_128(v[6], v[14]);
		h_vecs[7] = xor_128(v[7], v[15]);

		block_flags = flags;
	}

	transpose_vecs_128(&h_vecs[0]);
	transpose_vecs_128(&h_vecs[4]);
	storeu_128(h_vecs[0], &out[0 * sizeof (uint32x4_t)]);
	storeu_128(h_vecs[4], &out[1 * sizeof (uint32x4_t)]);
	storeu_128(h_vecs[1], &out[2 * sizeof (uint32x4_t)]);
	storeu_128(h_vecs[5], &out[3 * sizeof (uint32x4_t)]);
	storeu_128(h_vecs[2], &out[4 * sizeof (uint32x4_t)]);
	storeu_128(h_vecs[6], &out[5 * sizeof (uint32x4_t)]);
	storeu_128(h_vecs[3], &out[6 * sizeof (uint32x4_t)]);
	storeu_128(h_vecs[7], &out[7 * sizeof (uint32x4_t)]);
}

static inline void hash_one_neon(const uint8_t *input, size_t blocks,
    const uint32_t key[8], uint64_t counter, uint8_t flags,
    uint8_t flags_start, uint8_t flags_end, uint8_t out[BLAKE3_OUT_LEN]) {

    uint32_t cv[8];
	memcpy(cv, key, BLAKE3_KEY_LEN);
	uint8_t block_flags = flags | flags_start;
	while (blocks > 0) {
		if (blocks == 1) {
			block_flags |= flags_end;
		}
		blake3_compress_in_place_generic(cv, input, BLAKE3_BLOCK_LEN,
		    counter, block_flags);
		input = &input[BLAKE3_BLOCK_LEN];
		blocks -= 1;
		block_flags = flags;
	}
	memcpy(out, cv, BLAKE3_OUT_LEN);
}

static void blake3_hash_many_neon(const uint8_t *const *inputs,
    size_t num_inputs, size_t blocks, const uint32_t key[8], uint64_t counter,
    boolean_t increment_counter, uint8_t flags, uint8_t flags_start, uint8_t
    flags_end, uint8_t *out) {

	while (num_inputs >= 4) {
		blake3_hash4_neon(inputs, blocks, key, counter,
		    increment_counter, flags, flags_start, flags_end, out);
		if (increment_counter) {
			counter += 4;
		}
		inputs += 4;
		num_inputs -= 4;
		out = &out[4 * BLAKE3_OUT_LEN];
	}
	while (num_inputs > 0) {
		hash_one_neon(inputs[0], blocks, key, counter, flags,
		    flags_start, flags_end, out);
		if (increment_counter) {
		    counter += 1;
		}
		inputs += 1;
		num_inputs -= 1;
		out = &out[BLAKE3_OUT_LEN];
	}
}

static boolean_t blake3_is_neon_supported(void)
{
	/* XXX - check register set */
	return (B_TRUE);
}

const blake3_impl_ops_t blake3_neon_impl = {
	.compress_in_place = blake3_compress_in_place_generic,
	.compress_xof = blake3_compress_xof_generic,
	.hash_many = blake3_hash_many_neon,
	.is_supported = blake3_is_neon_supported,
	.degree = 4,
	.name = "neon"
};

#endif		/* defined(__aarch64__) */
