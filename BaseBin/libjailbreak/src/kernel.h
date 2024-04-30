#ifndef KERNEL_H
#define KERNEL_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <mach/mach.h>
#include "pvh.h"
#include "info.h"

#define CPSR_KERN_INTR_EN  (0x401000 | ((uint32_t)kconstant(kernel_el) << 2))
#define CPSR_KERN_INTR_DIS (0x4013c0 | ((uint32_t)kconstant(kernel_el) << 2))
#define CPSR_USER_INTR_DIS 0x13C0

#define PERM_KRW_URW 0x7 // R/W for kernel and user

#define P_SUGID 0x00000100
#define atop(x) ((vm_address_t)(x) >> vm_real_kernel_page_shift)
typedef struct __attribute__((__packed__)) _vm_map_flags {
    unsigned int
        /* boolean_t */ wait_for_space:1,         /* Should callers wait for space? */
        /* boolean_t */ wiring_required:1,        /* All memory wired? */
        /* boolean_t */ no_zero_fill:1,           /* No zero fill absent pages */
        /* boolean_t */ mapped_in_other_pmaps:1,  /* has this submap been mapped in maps that use a different pmap */
        /* boolean_t */ switch_protect:1,         /* Protect map from write faults while switched */
        /* boolean_t */ disable_vmentry_reuse:1,  /* All vm entries should keep using newer and higher addresses in the map */
        /* boolean_t */ map_disallow_data_exec:1, /* Disallow execution from data pages on exec-permissive architectures */
        /* boolean_t */ holelistenabled:1,
        /* boolean_t */ is_nested_map:1,
        /* boolean_t */ map_disallow_new_exec:1, /* Disallow new executable code */
        /* boolean_t */ jit_entry_exists:1,
        /* boolean_t */ has_corpse_footprint:1,
        /* boolean_t */ terminated:1,
        /* boolean_t */ is_alien:1,              /* for platform simulation, i.e. PLATFORM_IOS on OSX */
        /* boolean_t */ cs_enforcement:1,        /* code-signing enforcement */
        /* boolean_t */ cs_debugged:1,           /* code-signed but debugged */
        /* boolean_t */ reserved_regions:1,      /* has reserved regions. The map size that userspace sees should ignore these. */
        /* boolean_t */ single_jit:1,            /* only allow one JIT mapping */
        /* boolean_t */ never_faults : 1,        /* only seen in KDK */
        /* reserved */ pad:13;
} vm_map_flags;

uint64_t proc_find(pid_t pidToFind);
uint64_t proc_task(uint64_t proc);
uint64_t proc_ucred(uint64_t proc);
int proc_rele(uint64_t proc);
uint32_t proc_getcsflags(uint64_t proc);
void proc_csflags_update(uint64_t proc, uint32_t flags);
void proc_csflags_set(uint64_t proc, uint32_t flags);
void proc_csflags_clear(uint64_t proc, uint32_t flags);
uint64_t ipc_entry_lookup(uint64_t space, mach_port_name_t name);
uint64_t pa_index(uint64_t pa);
uint64_t pai_to_pvh(uint64_t pai);
uint64_t pvh_ptd(uint64_t pvh);
void task_set_memory_ownership_transfer(uint64_t task, bool value);
uint64_t mac_label_get(uint64_t label, int slot);
void mac_label_set(uint64_t label, int slot, uint64_t value);
int pmap_cs_allow_invalid(uint64_t pmap);
int cs_allow_invalid(uint64_t proc, bool emulateFully);
kern_return_t pmap_enter_options_addr(uint64_t pmap, uint64_t pa, uint64_t va);
uint64_t pmap_remove_options(uint64_t pmap, uint64_t start, uint64_t end);
void pmap_remove(uint64_t pmap, uint64_t start, uint64_t end);

#endif