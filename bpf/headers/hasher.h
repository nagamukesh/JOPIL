#ifndef __HASHER_H__
#define __HASHER_H__

#include "common.h"

static __inline __u32 calculate_hash(__u32 saddr, __u32 daddr, __u8 proto) {
	return (saddr ^ daddr ^ proto);
}

#endif