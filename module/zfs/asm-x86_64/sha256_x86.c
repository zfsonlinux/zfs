#ifdef _KERNEL
#include <asm/i387.h>
#include <asm/xcr.h>
#include <asm/user.h>
#include <asm/xsave.h>
#endif
#include <sys/sha256.h>

void sha256_transform_ssse3(const void *, uint32_t *, uint64_t);
#ifdef CONFIG_AS_AVX
void sha256_transform_avx(const void *, uint32_t *, uint64_t);
#endif
#ifdef CONFIG_AS_AVX2
void sha256_transform_rorx(const void *, uint32_t *, uint64_t);
#endif

static void (*sha256_transform_asm)(const void *, uint32_t *, uint64_t);

static void arch_sha256_transform(const void *buf, uint32_t *H, uint64_t blks)
{
#ifdef _KERNEL
	kernel_fpu_begin();
#endif
	sha256_transform_asm(buf, H, blks);
#ifdef _KERNEL
	kernel_fpu_end();
#endif
}

#if defined(CONFIG_AS_AVX) && defined(_KERNEL)
static int avx_usable(void)
{
	u64 xcr0;

	if (!cpu_has_avx || !cpu_has_osxsave)
		return (0);

	xcr0 = xgetbv(XCR_XFEATURE_ENABLED_MASK);
	if ((xcr0 & (XSTATE_SSE | XSTATE_YMM)) != (XSTATE_SSE | XSTATE_YMM)) {
		return (0);
	}
	return (1);
}
#endif

void
arch_sha256_init(void)
{
	sha256_transform_asm = NULL;
#ifdef _KERNEL
	if (cpu_has_ssse3)
		sha256_transform_asm = sha256_transform_ssse3;
#if defined(CONFIG_AS_AVX) && defined(_KERNEL)
	if (avx_usable()) {
		sha256_transform_asm = sha256_transform_avx;
#ifdef CONFIG_AS_AVX2
		if (cpu_has_avx2 && boot_cpu_has(X86_FEATURE_BMI2))
			sha256_transform_asm = sha256_transform_rorx;
#endif
	}
#endif
#else
	/* userspace doesn't have feature detection */
	sha256_transform_asm = sha256_transform_avx;
#endif
	if (sha256_transform_asm)
		sha256_transform = arch_sha256_transform;
}
