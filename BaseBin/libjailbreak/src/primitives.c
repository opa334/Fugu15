#include "primitives.h"
#include "kernel.h"
#include "info.h"
#include "translation.h"
#include "pte.h"
#include "util.h"
#include <errno.h>
#include <string.h>
#include <sys/sysctl.h>

struct kernel_primitives gPrimitives = { 0 };

// Wrappers physical <-> virtual

void enumerate_pages(uint64_t start, size_t size, uint64_t pageSize, bool (^block)(uint64_t curStart, size_t curSize))
{
	uint64_t curStart = start;
	size_t sizeLeft = size;
	bool c = true;
	while (sizeLeft > 0 && c) {
		uint64_t pageOffset = curStart & (pageSize - 1);
		uint64_t readSize = min(sizeLeft, pageSize - pageOffset);
		c = block(curStart, readSize);
		curStart += readSize;
		sizeLeft -= readSize;
	}
}

int _kreadbuf_phys(uint64_t kaddr, void* output, size_t size)
{
	memset(output, 0, size);

	__block int pr = 0;
	enumerate_pages(kaddr, size, vm_real_kernel_page_size, ^bool(uint64_t curKaddr, size_t curSize){
		uint64_t curPhys = kvtophys(curKaddr);
		if (curPhys == 0 && errno != 0) {
			pr = errno;
			return false;
		}
		pr = physreadbuf(curPhys, &output[curKaddr - kaddr], curSize);
		if (pr != 0) {
			return false;
		}
		return true;
	});
	return pr;
}

int _kwritebuf_phys(uint64_t kaddr, const void* input, size_t size)
{
	__block int pr = 0;
	enumerate_pages(kaddr, size, vm_real_kernel_page_size, ^bool(uint64_t curKaddr, size_t curSize){
		uint64_t curPhys = kvtophys(curKaddr);
		if (curPhys == 0 && errno != 0) {
			pr = errno;
			return false;
		}
		pr = physwritebuf(curPhys, &input[curKaddr - kaddr], curSize);
		if (pr != 0) {
			return false;
		}
		return true;
	});
	return pr;
}

int _physreadbuf_virt(uint64_t physaddr, void* output, size_t size)
{
	memset(output, 0, size);

	__block int pr = 0;
	enumerate_pages(physaddr, size, vm_real_kernel_page_size, ^bool(uint64_t curPhys, size_t curSize){
		uint64_t curKaddr = phystokv(curPhys);
		if (curKaddr == 0 && errno != 0) {
			pr = errno;
			return false;
		}
		pr = kreadbuf(curKaddr, &output[curPhys - physaddr], curSize);
		if (pr != 0) {
			return false;
		}
		return true;
	});
	return pr;
}

int _physwritebuf_virt(uint64_t physaddr, const void* input, size_t size)
{
	__block int pr = 0;
	enumerate_pages(physaddr, size, vm_real_kernel_page_size, ^bool(uint64_t curPhys, size_t curSize){
		uint64_t curKaddr = phystokv(curPhys);
		if (curKaddr == 0 && errno != 0) {
			pr = errno;
			return false;
		}
		pr = kwritebuf(curKaddr, &input[curPhys - physaddr], curSize);
		if (pr != 0) {
			return false;
		}
		return true;
	});
	return pr;
}

// Wrappers to gPrimitives

int kreadbuf(uint64_t kaddr, void* output, size_t size)
{
	if (gPrimitives.kreadbuf) {
		return gPrimitives.kreadbuf(kaddr, output, size);
	}
	else if (gPrimitives.physreadbuf && gPrimitives.vtophys) {
		return _kreadbuf_phys(kaddr, output, size);
	}
	return -1;
}

int kwritebuf(uint64_t kaddr, const void* input, size_t size)
{
	if (gPrimitives.kwritebuf) {
		return gPrimitives.kwritebuf(kaddr, input, size);
	}
	else if (gPrimitives.physwritebuf && gPrimitives.vtophys) {
		return _kwritebuf_phys(kaddr, input, size);
	}
	return -1;
}

int physreadbuf(uint64_t physaddr, void* output, size_t size)
{
	if (gPrimitives.physreadbuf) {
		return gPrimitives.physreadbuf(physaddr, output, size);
	}
	else if (gPrimitives.kreadbuf && gPrimitives.phystokv) {
		return _physreadbuf_virt(physaddr, output, size);
	}
	return -1;
}

int physwritebuf(uint64_t physaddr, const void* input, size_t size)
{
	if (gPrimitives.physwritebuf) {
		return gPrimitives.physwritebuf(physaddr, input, size);
	}
	else if (gPrimitives.kwritebuf && gPrimitives.phystokv) {
		return _physwritebuf_virt(physaddr, input, size);
	}
	return -1;
}

// Convenience Wrappers

uint64_t physread64(uint64_t pa)
{
	uint64_t v;
	physreadbuf(pa, &v, sizeof(v));
	return v;
}

uint64_t physread_ptr(uint64_t pa)
{
	return UNSIGN_PTR(physread64(pa));
}

uint32_t physread32(uint64_t pa)
{
	uint32_t v;
	physreadbuf(pa, &v, sizeof(v));
	return v;
}

uint16_t physread16(uint64_t pa)
{
	uint16_t v;
	physreadbuf(pa, &v, sizeof(v));
	return v;
}

uint8_t physread8(uint64_t pa)
{
	uint8_t v;
	physreadbuf(pa, &v, sizeof(v));
	return v;
}


int physwrite64(uint64_t pa, uint64_t v)
{
	return physwritebuf(pa, &v, sizeof(v));
}

int physwrite32(uint64_t pa, uint32_t v)
{
	return physwritebuf(pa, &v, sizeof(v));
}

int physwrite16(uint64_t pa, uint16_t v)
{
	return physwritebuf(pa, &v, sizeof(v));
}

int physwrite8(uint64_t pa, uint8_t v)
{
	return physwritebuf(pa, &v, sizeof(v));
}


uint64_t kread64(uint64_t va)
{
	uint64_t v;
	kreadbuf(va, &v, sizeof(v));
	return v;
}

uint64_t kread_ptr(uint64_t va)
{
	return UNSIGN_PTR(kread64(va));
}

uint64_t kread_smrptr(uint64_t va)
{
	uint64_t value = kread_ptr(va);

	uint64_t bits = (kconstant(smrBase) << (62-kconstant(T1SZ_BOOT)));

	uint64_t case1 = 0xFFFFFFFFFFFFC000 & ~bits;
	uint64_t case2 = 0xFFFFFFFFFFFFFFE0 & ~bits;

	if ((value & bits) == 0) {
		if (value) {
			value = (value & case1) | bits;
		}
	}
	else {
		value = (value & case2) | bits;
	}

	return value;
}

uint32_t kread32(uint64_t va)
{
	uint32_t v;
	kreadbuf(va, &v, sizeof(v));
	return v;
}

uint16_t kread16(uint64_t va)
{
	uint16_t v;
	kreadbuf(va, &v, sizeof(v));
	return v;
}

uint8_t kread8(uint64_t va)
{
	uint8_t v;
	kreadbuf(va, &v, sizeof(v));
	return v;
}


int kwrite64(uint64_t va, uint64_t v)
{
	return kwritebuf(va, &v, sizeof(v));
}

int kwrite_ptr(uint64_t kaddr, uint64_t pointer, uint16_t salt)
{
#ifdef __arm64e__
	if (!gPrimitives.kexec || !kgadget(pacda)) return -1;
	kwrite64(kaddr, kptr_sign(kaddr, pointer, salt));
#else
	kwrite64(kaddr, pointer);
#endif
	return 0;
}

int kwrite32(uint64_t va, uint32_t v)
{
	return kwritebuf(va, &v, sizeof(v));
}

int kwrite16(uint64_t va, uint16_t v)
{
	return kwritebuf(va, &v, sizeof(v));
}

int kwrite8(uint64_t va, uint8_t v)
{
	return kwritebuf(va, &v, sizeof(v));
}

int kcall(uint64_t *result, uint64_t func, int argc, const uint64_t *argv)
{
	if (gPrimitives.kcall) {
		uint64_t resultTmp = gPrimitives.kcall(func, argc, argv);
		if(result) *result = resultTmp;
		return 0;
	}
	return -1;
}

int kexec(kRegisterState *state)
{
	if (gPrimitives.kexec) {
		gPrimitives.kexec(state);
	}
	return -1;
}

int kmap(uint64_t pa, uint64_t size, void **uaddr)
{
	if (gPrimitives.kmap) {
		return gPrimitives.kmap(pa, size, uaddr);
	}
	return -1;
}

int kalloc_with_options(uint64_t *addr, uint64_t size, kalloc_options options)
{
	if (options == KALLOC_OPTION_GLOBAL && gPrimitives.kalloc_global) {
		return gPrimitives.kalloc_global(addr, size);
	}
	else if (options == KALLOC_OPTION_LOCAL && gPrimitives.kalloc_local) {
		return gPrimitives.kalloc_local(addr, size);
	}
	return -1;
}

int kalloc(uint64_t *addr, uint64_t size)
{
	return kalloc_with_options(addr, size, KALLOC_OPTION_GLOBAL);
}

int kfree(uint64_t addr, uint64_t size)
{
	if (gPrimitives.kfree_global) {
		return gPrimitives.kfree_global(addr, size);
	}
	return -1;
}

bool is_kcall_available(void)
{
#ifdef __arm64e__
	return jbinfo(usesPACBypass);
#else
	if (__builtin_available(iOS 16.0, *)) {
		return false;
	}
	return true;
#endif
}
