#include "kernel.h"
#include <stdbool.h>
#include "primitives.h"
#include "info.h"
#include "util.h"
#include "codesign.h"
#include <dispatch/dispatch.h>

uint64_t proc_find(pid_t pidToFind)
{
	__block uint64_t foundProc = 0;
	// This sucks a bit due to us not being able to take locks
	// If we don't find anything, just repeat 5 times
	// Attempts to avoids conditions where we got thrown off by modifications
	for (int i = 0; i < 5 && !foundProc; i++) {
		proc_iterate(^(uint64_t proc, bool *stop) {
			pid_t pid = kread32(proc + koffsetof(proc, pid));
			if (pid == pidToFind) {
				foundProc = proc;
				*stop = true;
			}
		});
	}
	return foundProc;
}

int proc_rele(uint64_t proc)
{
	// If proc_find doesn't increment the ref count, there is also no need to decrement it again
	return -1;
}

uint64_t proc_task(uint64_t proc)
{
	if (koffsetof(proc, task)) {
		// iOS <= 15: proc has task attribute
		return kread_ptr(proc + koffsetof(proc, task));
	}
	else {
		// iOS >= 16: task is always at "proc + sizeof(proc)"
		return proc + ksizeof(proc);
	}
}

uint64_t proc_ucred(uint64_t proc)
{
	if (gSystemInfo.kernelStruct.proc_ro.exists) {
		uint64_t proc_ro = kread_ptr(proc + koffsetof(proc, proc_ro));
		return kread_ptr(proc_ro + koffsetof(proc_ro, ucred));
	}
	else {
		return kread_ptr(proc + koffsetof(proc, ucred));
	}
}

uint32_t proc_getcsflags(uint64_t proc)
{
	if (gSystemInfo.kernelStruct.proc_ro.exists) {
		uint64_t proc_ro = kread_ptr(proc + koffsetof(proc, proc_ro));
		return kread32(proc_ro + koffsetof(proc_ro, csflags));
	}
	else {
		return kread32(proc + koffsetof(proc, csflags));
	}
}

void proc_csflags_update(uint64_t proc, uint32_t flags)
{
	if (gSystemInfo.kernelStruct.proc_ro.exists) {
		uint64_t proc_ro = kread_ptr(proc + koffsetof(proc, proc_ro));
		kwrite32(proc_ro + koffsetof(proc_ro, csflags), flags);
	}
	else {
		kwrite32(proc + koffsetof(proc, csflags), flags);
	}
}

void proc_csflags_set(uint64_t proc, uint32_t flags)
{
	proc_csflags_update(proc, proc_getcsflags(proc) | (uint32_t)flags);
}

void proc_csflags_clear(uint64_t proc, uint32_t flags)
{
	proc_csflags_update(proc, proc_getcsflags(proc) & ~(uint32_t)flags);
}

uint64_t ipc_entry_lookup(uint64_t space, mach_port_name_t name)
{
	uint64_t table = 0;
	// New format in iOS 16.1
	if (gSystemInfo.kernelStruct.ipc_space.table_uses_smr) {
		table = kread_smrptr(space + koffsetof(ipc_space, table));
	}
	else {
		table = kread_ptr(space + koffsetof(ipc_space, table));
	}

	return (table + (ksizeof(ipc_entry) * (name >> 8)));
}

uint64_t pa_index(uint64_t pa)
{
	return atop(pa - kread64(ksymbol(vm_first_phys)));
}

uint64_t pai_to_pvh(uint64_t pai)
{
	return kread64(ksymbol(pv_head_table)) + (pai * 8);
}

uint64_t pvh_ptd(uint64_t pvh)
{
	return ((kread64(pvh) & PVH_LIST_MASK) | PVH_HIGH_FLAGS);
}

void task_set_memory_ownership_transfer(uint64_t task, bool value)
{
	kwrite8(task + koffsetof(task, task_can_transfer_memory_ownership), !!value);
}

uint64_t mac_label_get(uint64_t label, int slot)
{
	// On 15.0 - 15.1.1, 0 is the equivalent of -1 on 15.2+
	// So, treat 0 as -1 there
	uint64_t value = kread_ptr(label + ((slot + 1) * sizeof(uint64_t)));
	if (!gSystemInfo.kernelStruct.proc_ro.exists && value == 0) value = -1;
	return value;
}

void mac_label_set(uint64_t label, int slot, uint64_t value)
{
	// THe inverse of the condition above, treat -1 as 0 on 15.0 - 15.1.1
	if (!gSystemInfo.kernelStruct.proc_ro.exists && value == -1) value = 0;
#ifdef __arm64e__
	if (jbinfo(usesPACBypass) && !gSystemInfo.kernelStruct.proc_ro.exists) {
		kcall(NULL, ksymbol(mac_label_set), 3, (uint64_t[]){ label, slot, value });
		return;
	}
#endif
	kwrite64(label + ((slot + 1) * sizeof(uint64_t)), value);
}

#ifdef __arm64e__
int pmap_cs_allow_invalid(uint64_t pmap)
{
	kwrite8(pmap + koffsetof(pmap, wx_allowed), true);
	return 0;
}
#endif

int cs_allow_invalid(uint64_t proc, bool emulateFully)
{
	if (proc) {
		uint64_t task = proc_task(proc);
		if (task) {
			uint64_t vm_map = kread_ptr(task + koffsetof(task, map));
			if (vm_map) {
				uint64_t pmap = kread_ptr(vm_map + koffsetof(vm_map, pmap));
				if (pmap) {
					// For non-pmap_cs (arm64) devices, this should always be emulated.
#ifdef __arm64e__
					if (emulateFully) {
#endif
						// Fugu15 Rootful
						//proc_csflags_clear(proc, CS_EXEC_SET_ENFORCEMENT | CS_EXEC_SET_KILL | CS_EXEC_SET_HARD | CS_REQUIRE_LV | CS_ENFORCEMENT | CS_RESTRICT | CS_KILL | CS_HARD | CS_FORCED_LV);
						//proc_csflags_set(proc, CS_DEBUGGED | CS_INVALID_ALLOWED | CS_GET_TASK_ALLOW);

						// XNU
						proc_csflags_clear(proc, CS_KILL | CS_HARD);
						proc_csflags_set(proc, CS_DEBUGGED);

						task_set_memory_ownership_transfer(task, true);
						vm_map_flags flags = { 0 };
						kreadbuf(vm_map + koffsetof(vm_map, flags), &flags, sizeof(flags));
						flags.switch_protect = false;
						flags.cs_debugged = true;
						kwritebuf(vm_map + koffsetof(vm_map, flags), &flags, sizeof(flags));
#ifdef __arm64e__
					}
					// For pmap_cs (arm64e) devices, this is enough to get unsigned code to run
					pmap_cs_allow_invalid(pmap);
#endif
				}
			}
		}
	}
	return 0;
}

kern_return_t pmap_enter_options_addr(uint64_t pmap, uint64_t pa, uint64_t va)
{
	uint64_t kr = -1;
	if (!is_kcall_available()) return kr;
	while (1) {
		kcall(&kr, ksymbol(pmap_enter_options_addr), 8, (uint64_t[]){ pmap, va, pa, VM_PROT_READ | VM_PROT_WRITE, 0, 0, 1, 1 });
		if (kr != KERN_RESOURCE_SHORTAGE) {
			return kr;
		}
	}
}

uint64_t pmap_remove_options(uint64_t pmap, uint64_t start, uint64_t end)
{
	uint64_t r = -1;
	if (!is_kcall_available()) return r;
	kcall(&r, ksymbol(pmap_remove_options), 4, (uint64_t[]){ pmap, start, end, 0x100 });
	return r;
}

void pmap_remove(uint64_t pmap, uint64_t start, uint64_t end)
{
#ifdef __arm64e__
	pmap_remove_options(pmap, start, end);
#else
    uint64_t remove_count = 0;
    if (!pmap) {
        return;
    }
    uint64_t va = start;
    while (va < end) {
        uint64_t l;
        l = ((va + L2_BLOCK_SIZE) & ~L2_BLOCK_MASK);
        if (l > end) {
            l = end;
        }
        remove_count = pmap_remove_options(pmap, va, l);
        va = remove_count;
    }
#endif
}