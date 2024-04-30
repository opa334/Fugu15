#include "kalloc_pt.h"
#include "primitives.h"
#include "translation.h"
#include "util.h"

#import <Foundation/Foundation.h>

// Kalloc implemented via allocating unassigned page tables
// Needed because the IOSurface primitive broke in iOS 16 (no clue why)
// Kinda lazy but works

NSMutableArray *gPool;

int kalloc_global_pt(uint64_t *kaddrOut, uint64_t size)
{
	@autoreleasepool {
		if (!kaddrOut) return -1;
		if (size == 0) return -1;
		if (size > vm_real_kernel_page_size) return -1; // nope
		
		if (gPool.count) {
			NSNumber *poolAllocation = gPool[0];
			[gPool removeObjectAtIndex:0];
			*kaddrOut = [poolAllocation unsignedLongLongValue];
			return 0;
		}
		else {
			uint64_t allocPA = alloc_page_table_unassigned();
			uint64_t allocVA = phystokv(allocPA);
			if (allocVA) {
				*kaddrOut = allocVA;
				return 0;
			}
			return -1;
		}
	}
}

int kfree_global_pt(uint64_t kaddr, uint64_t size)
{
	@autoreleasepool {
		if (!kaddr) return -1;

		// Doesn't seem feasible to free them, what we can do is cache "freed" pages and reuse them later
		// Keep in mind this only works on allocation made by this mechanism
		// Also it only works because there is only one kfree in the entire jailbreak and that works with this
		[gPool addObject:@(kaddr)];
		return 0;
	}
}

void libjailbreak_kalloc_pt_init(void)
{
	gPool = [NSMutableArray new];
	gPrimitives.kalloc_global = kalloc_global_pt;
	gPrimitives.kfree_global = kfree_global_pt;
}