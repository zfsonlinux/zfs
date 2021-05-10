#ifdef __sparc__
#include <stdint.h>
#include "include/sparc_compat.h"
uint64_t __bswapdi2(uint64_t in) {
    return ( \
	((in << 56) & 0xff00000000000000ULL) |
	((in << 40) & 0x00ff000000000000ULL) |
	((in << 24) & 0x0000ff0000000000ULL) |
	((in << 8)  & 0x000000ff00000000ULL) |
	((in >> 8)  & 0x00000000ff000000ULL) |
	((in >> 24) & 0x0000000000ff0000ULL) |
	((in >> 40) & 0x000000000000ff00ULL) |
	((in >> 56) & 0x00000000000000ffULL));
}
uint32_t __bswapsi2(uint32_t in) {
	return ( \
	((in << 24) & 0xff000000) |
	((in <<  8) & 0x00ff0000) |
	((in >>  8) & 0x0000ff00) |
	((in >> 24) & 0x000000ff));
}
#endif
