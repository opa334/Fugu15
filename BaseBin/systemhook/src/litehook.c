#include "litehook.h"
#include <stdarg.h>
#include <stdbool.h>
#include <sys/types.h>
#include <string.h>
#include <sys/fcntl.h>
#include <mach/mach.h>
#include <mach/arm/kern_return.h>
#include <mach/port.h>
#include <mach/vm_prot.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <libkern/OSCacheControl.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld_images.h>
#include <sys/syslimits.h>
#include <dispatch/dispatch.h>
#include <dyld_cache_format.h>

#ifdef __arm64e__
static uint64_t __attribute((naked)) __xpaci(uint64_t a)
{
	asm(".long        0xDAC143E0"); // XPACI X0
	asm("ret");
}
#endif

uint64_t xpaci(uint64_t a)
{
	// If a looks like a non-pac'd pointer just return it
	if ((a & 0xFFFFFF0000000000) == 0xFFFFFF0000000000) {
		return a;
	}
#ifdef __arm64e__
	return __xpaci(a);
#else
    return a;
#endif
}

uint32_t movk(uint8_t x, uint16_t val, uint16_t lsl)
{
	uint32_t base = 0b11110010100000000000000000000000;

	uint32_t hw = 0;
	if (lsl == 16) {
		hw = 0b01 << 21;
	}
	else if (lsl == 32) {
		hw = 0b10 << 21;
	}
	else if (lsl == 48) {
		hw = 0b11 << 21;
	}

	uint32_t imm16 = (uint32_t)val << 5;
	uint32_t rd = x & 0x1F;

	return base | hw | imm16 | rd;
}

uint32_t br(uint8_t x)
{
	uint32_t base = 0b11010110000111110000000000000000;
	uint32_t rn = ((uint32_t)x & 0x1F) << 5;
	return base | rn;
}

__attribute__((noinline, naked)) volatile kern_return_t litehook_vm_protect(mach_port_name_t target, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection)
{
	__asm("mov x16, #0xFFFFFFFFFFFFFFF2");
	__asm("svc 0x80");
	__asm("ret");
}

kern_return_t litehook_unprotect(vm_address_t addr, vm_size_t size)
{
	return litehook_vm_protect(mach_task_self(), addr, size, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
}

kern_return_t litehook_protect(vm_address_t addr, vm_size_t size)
{
	return litehook_vm_protect(mach_task_self(), addr, size, false, VM_PROT_READ | VM_PROT_EXECUTE);
}

kern_return_t litehook_hook_function(void *source, void *target)
{
	kern_return_t kr = KERN_SUCCESS;

	uint32_t *toHook = (uint32_t*)xpaci((uint64_t)source);
	uint64_t target64 = (uint64_t)xpaci((uint64_t)target);

	kr = litehook_unprotect((vm_address_t)toHook, 5*4);
	if (kr != KERN_SUCCESS) return kr;

	toHook[0] = movk(16, target64 >> 0, 0);
	toHook[1] = movk(16, target64 >> 16, 16);
	toHook[2] = movk(16, target64 >> 32, 32);
	toHook[3] = movk(16, target64 >> 48, 48);
	toHook[4] = br(16);
	uint32_t hookSize = 5 * sizeof(uint32_t);

	kr = litehook_protect((vm_address_t)toHook, hookSize);
	if (kr != KERN_SUCCESS) return kr;

	sys_icache_invalidate(toHook, hookSize);

	return KERN_SUCCESS;
}

size_t fstrlen(FILE *f)
{
	size_t sz = 0;
	uint32_t prev = ftell(f);
	while (true) {
		char c = 0;
		if (fread(&c, sizeof(c), 1, f) != 1) break;
		if (c == 0) break;
		sz++;
	}
	fseek(f, prev, SEEK_SET);
	return sz;
}

const char *litehook_locate_dsc(void)
{
	static char dscPath[PATH_MAX] = {};
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		if (!access("/System/Library/Caches/com.apple.dyld", F_OK)) /* iOS <=15 */ {
			strcpy(dscPath, "/System/Library/Caches/com.apple.dyld/dyld_shared_cache");
		}
		else if (!access("/private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld", F_OK)) /* iOS >=16 */ {
			strcpy(dscPath, "/private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache");
		}
#ifdef __arm64e__
		strcat(dscPath, "_arm64e");
#else
		strcat(dscPath, "_arm64");
#endif
	});
	return (const char *)dscPath;
}

uintptr_t litehook_get_dsc_slide(void)
{
	static uintptr_t slide = 0;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		task_dyld_info_data_t dyldInfo;
		uint32_t count = TASK_DYLD_INFO_COUNT;
		task_info(mach_task_self_, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);
		struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)dyldInfo.all_image_info_addr;
		slide = infos->sharedCacheSlide;
	});
	return slide;
}

void *litehook_find_dsc_symbol(const char *imagePath, const char *symbolName)
{
	const char *mainDSCPath = litehook_locate_dsc();
	char symbolDSCPath[PATH_MAX];
	strcpy(symbolDSCPath, mainDSCPath);
	strcat(symbolDSCPath, ".symbols");

	void *symbol = NULL;

	FILE *mainDSC = fopen(mainDSCPath, "rb");
	if (!mainDSC) goto end;
	FILE *symbolDSC = fopen(symbolDSCPath, "rb") ?: mainDSC;

	int imageIndex = -1;

	struct dyld_cache_header mainHeader;
	if (fread(&mainHeader, sizeof(mainHeader), 1, mainDSC) != 1) goto end;

	for (int i = 0; i < mainHeader.imagesCount; i++) {
		struct dyld_cache_image_info imageInfo;
		fseek(mainDSC, mainHeader.imagesOffset + sizeof(imageInfo) * i, SEEK_SET);
		if (fread(&imageInfo, sizeof(imageInfo), 1, mainDSC) != 1) goto end;

		char path[PATH_MAX];
		fseek(mainDSC, imageInfo.pathFileOffset, SEEK_SET);
		if (fread(path, PATH_MAX, 1, mainDSC) != 1) goto end;

		if (!strcmp(path, imagePath)) {
			imageIndex = i;
			break;
		}
	}

	struct dyld_cache_header symbolHeader;
	if (fread(&symbolHeader, sizeof(symbolHeader), 1, symbolDSC) != 1) goto end;

	struct dyld_cache_local_symbols_info symbolInfo;
	fseek(symbolDSC, symbolHeader.localSymbolsOffset, SEEK_SET);
	if (fread(&symbolInfo, sizeof(symbolInfo), 1, symbolDSC) != 1) goto end;

	if (imageIndex >= symbolInfo.entriesCount) goto end;

	struct dyld_cache_local_symbols_entry_64 entry;
	fseek(symbolDSC, symbolHeader.localSymbolsOffset + symbolInfo.entriesOffset + (sizeof(entry) * imageIndex), SEEK_SET);
	if (fread(&entry, sizeof(entry), 1, symbolDSC) != 1) goto end;

	if ((entry.nlistStartIndex + entry.nlistCount) > symbolInfo.nlistCount) goto end;

	for (uint32_t i = entry.nlistStartIndex; i < entry.nlistStartIndex + entry.nlistCount; i++) {
		struct nlist_64 n;
		fseek(symbolDSC, symbolHeader.localSymbolsOffset + symbolInfo.nlistOffset + (sizeof(n) * i), SEEK_SET);
		if (fread(&n, sizeof(n), 1, symbolDSC) != 1) goto end;

		fseek(symbolDSC, symbolHeader.localSymbolsOffset + symbolInfo.stringsOffset + n.n_un.n_strx, SEEK_SET);
		size_t len = fstrlen(symbolDSC);
		char curSymbolName[len+1];
		if (fread(curSymbolName, len+1, 1, symbolDSC) != 1) goto end;
		if (!strcmp(curSymbolName, symbolName)) {
			symbol = (void *)(litehook_get_dsc_slide() + n.n_value);
		}
	}

end:
	if (mainDSC) {
		if (symbolDSC != mainDSC) {
			fclose(symbolDSC);
		}
		fclose(mainDSC);
	}

	return symbol;
}
