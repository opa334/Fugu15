#include "primitives.h"
#include "translation.h"
#include "kernel.h"
#include "util.h"
#include "pte.h"
#include "info.h"
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <mach/mach.h>
#include <sys/sysctl.h>

#define MAGIC_PT_ADDRESS (L1_BLOCK_SIZE * (L1_BLOCK_COUNT - 1))
#define gMagicPT ((uint64_t *)MAGIC_PT_ADDRESS) // fake variable

uint8_t *gSwAsid = 0;
static pthread_mutex_t gLock;

void flush_tlb(void)
{
	uint8_t fakeSwAsid = UINT8_MAX;
	uint8_t origSwAsid = *gSwAsid;
	if (origSwAsid != fakeSwAsid) {
		*gSwAsid = fakeSwAsid;
		__asm("dmb sy");
		usleep(0); // Force context switch
		*gSwAsid = origSwAsid;
		__asm("dmb sy");
	}
}

void acquire_window(uint64_t pa, void (^block)(void *ua))
{
	pthread_mutex_lock(&gLock);

	int toUse = 0;

	// Find existing
	for (int i = 2; i < L2_BLOCK_COUNT; i++) {
		if ((gMagicPT[i] & ARM_TTE_PA_MASK) == pa) {
			toUse = i;
			break;
		}
	}

	// If not found, find empty
	if (toUse == 0) {
		for (int i = 2; i < L2_BLOCK_COUNT; i++) {
			if (!gMagicPT[i]) {
				toUse = i;
				break;
			}
		}
	}

	// If not found, clear page table
	if (toUse == 0) {
		// Reset all entries to 0
		for (int i = 2; i < L2_BLOCK_COUNT; i++) {
			gMagicPT[i] = 0;
		}
		flush_tlb();
		toUse = 2;
	}

	gMagicPT[toUse] = pa | PERM_TO_PTE(PERM_KRW_URW) | PTE_NON_GLOBAL | PTE_OUTER_SHAREABLE | PTE_LEVEL3_ENTRY;
	usleep(0);
	__asm("dmb sy");
	usleep(0);

	block((void *)(MAGIC_PT_ADDRESS + (toUse * vm_real_kernel_page_size)));

	pthread_mutex_unlock(&gLock);
}

int physrw_pte_physreadbuf(uint64_t pa, void* output, size_t size)
{
	__block int r = 0;
	enumerate_pages(pa, size, vm_real_kernel_page_size, ^bool(uint64_t curPA, size_t curSize) {
		acquire_window(curPA & ~vm_real_kernel_page_mask, ^(void *ua) {
			void *curUA = ((uint8_t*)ua) + (curPA & vm_real_kernel_page_mask);
			memcpy(&output[curPA - pa], curUA, curSize);
			__asm("dmb sy");
		});
		return true;
	});
	return r;
}

int physrw_pte_physwritebuf(uint64_t pa, const void* input, size_t size)
{
	__block int r = 0;
	enumerate_pages(pa, size, vm_real_kernel_page_size, ^bool(uint64_t curPA, size_t curSize) {
		acquire_window(curPA & ~vm_real_kernel_page_mask, ^(void *ua) {
			void *curUA = ((uint8_t*)ua) + (curPA & vm_real_kernel_page_mask);
			memcpy(curUA, &input[curPA - pa], curSize);
			__asm("dmb sy");
		});
		return true;
	});
	return r;
}

int physrw_pte_handoff(pid_t pid, uint64_t *swAsidPtr)
{
	if (!pid) return -1;

	uint64_t proc = proc_find(pid);
	if (!proc) return -2;

	int ret = 0;
	do {
		uint64_t task = proc_task(proc);
		if (!task) { ret = -3; break; };

		uint64_t vmMap = kread_ptr(task + koffsetof(task, map));
		if (!vmMap) { ret = -4; break; };

		uint64_t pmap = kread_ptr(vmMap + koffsetof(vm_map, pmap));
		if (!pmap) { ret = -5; break; };

		uint64_t ttep = kread64(pmap + koffsetof(pmap, ttep));

		// Allocate magic page table to our process at last possible location
		int exp_r = pmap_expand_range(pmap, MAGIC_PT_ADDRESS, L2_BLOCK_SIZE);
		if (exp_r != 0) { ret = -6; break; }

		// Map in the magic page table at MAGIC_PT_ADDRESS
		uint64_t leafLevel = PMAP_TT_L2_LEVEL;
		uint64_t magicPT = vtophys_lvl(ttep, MAGIC_PT_ADDRESS, &leafLevel, NULL);
		if (!magicPT) { ret = -7; break; }
		physwrite64(magicPT, magicPT | PERM_TO_PTE(PERM_KRW_URW) | PTE_NON_GLOBAL | PTE_OUTER_SHAREABLE | PTE_LEVEL3_ENTRY);

		// Map in the pmap at MAGIC_PT_ADDRESS+vm_real_kernel_page_size
		uint64_t sw_asid = pmap + koffsetof(pmap, sw_asid);
		uint64_t sw_asid_page = sw_asid & ~vm_real_kernel_page_mask;
		uint64_t sw_asid_page_pa = kvtophys(sw_asid_page);
		uint64_t sw_asid_pageoff = sw_asid & vm_real_kernel_page_mask;
		*swAsidPtr = (uint64_t)(MAGIC_PT_ADDRESS + vm_real_kernel_page_size + sw_asid_pageoff);
		physwrite64(magicPT+8, sw_asid_page_pa | PERM_TO_PTE(PERM_KRW_URW) | PTE_NON_GLOBAL | PTE_OUTER_SHAREABLE | PTE_LEVEL3_ENTRY);

		if (getpid() == pid) {
			flush_tlb();
		}
	} while (0);

	proc_rele(proc);
	return ret;
}

int libjailbreak_physrw_pte_init(bool receivedHandoff, uint64_t asidPtr)
{
	if (pthread_mutex_init(&gLock, NULL) != 0) return -8;

	if (!receivedHandoff) {
		physrw_pte_handoff(getpid(), (uint64_t *)&gSwAsid);
	}
	else {
		gSwAsid = (void *)asidPtr;
	}
	gPrimitives.physreadbuf = physrw_pte_physreadbuf;
	gPrimitives.physwritebuf = physrw_pte_physwritebuf;
	gPrimitives.kreadbuf = NULL;
	gPrimitives.kwritebuf = NULL;

	return 0;
}

bool device_supports_physrw_pte(void)
{
	cpu_subtype_t cpuFamily = 0;
	size_t cpuFamilySize = sizeof(cpuFamily);
	sysctlbyname("hw.cpufamily", &cpuFamily, &cpuFamilySize, NULL, 0);
	if (cpuFamily == CPUFAMILY_ARM_TYPHOON) {
		// On A8, phyrw_pte causes SUPER WEIRD UNEXPLAINABLE SYSTEM RESTARTS
		// No seriously, there is no panic-full log, only a panic-base that says "Unexpected watchdog reset"
		// This exact report also what you would get when you do a hard reset, super weird...
		// Luckily physrw doesn't have that issue so we can just use that immediately on A8
		// This makes jailbreaking a few seconds slower, but it's not the biggest deal in the world
		return false;
	}
	return true;
}