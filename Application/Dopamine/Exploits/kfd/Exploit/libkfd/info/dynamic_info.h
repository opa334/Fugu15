/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef dynamic_info_h
#define dynamic_info_h

struct dynamic_info {
    bool kread_kqueue_workloop_ctl_supported;
    bool krkw_iosurface_supported;
    bool perf_supported;
    u64 kernelcache__static_base;
    // struct proc
    u64 proc__p_list__le_prev;
    u64 proc__p_list__le_next;
    u64 proc__task;
    u64 proc__p_pid;
    u64 proc__p_fd__fd_ofiles;
    u64 proc__object_size;
    // struct task
    u64 task__map;
    // struct vm_map
    u64 vm_map__hdr_links_prev;
    u64 vm_map__hdr_links_next;
    u64 vm_map__min_offset;
    u64 vm_map__max_offset;
    u64 vm_map__hdr_nentries;
    u64 vm_map__hdr_nentries_u64;
    u64 vm_map__hdr_rb_head_store_rbh_root;
    u64 vm_map__pmap;
    u64 vm_map__hint;
    u64 vm_map__hole_hint;
    u64 vm_map__holes_list;
    u64 vm_map__object_size;
    // struct thread
    u64 thread__thread_id;
    // struct IOSurface
    u64 IOSurface__isa;
    u64 IOSurface__pixelFormat;
    u64 IOSurface__allocSize;
    u64 IOSurface__useCountPtr;
    u64 IOSurface__indexedTimestampPtr;
    u64 IOSurface__readDisplacement;
    // kernelcache static addresses (IOSurface)
    u64 kernelcache__allproc;
    // kernelcache static addresses (perf)
    u64 kernelcache__cdevsw;                          // "spec_open type" or "Can't mark ptc as kqueue ok"
    u64 kernelcache__gPhysBase;                       // "%s: illegal PA: 0x%llx; phys base 0x%llx, size 0x%llx"
    u64 kernelcache__gPhysSize;                       // (gPhysBase + 0x8)
    u64 kernelcache__gVirtBase;                       // "%s: illegal PA: 0x%llx; phys base 0x%llx, size 0x%llx"
    u64 kernelcache__perfmon_dev_open;                // "perfmon: attempt to open unsupported source: 0x%x"
    u64 kernelcache__perfmon_devices;                 // "perfmon: %s: devfs_make_node_clone failed"
    u64 kernelcache__ptov_table;                      // "%s: illegal PA: 0x%llx; phys base 0x%llx, size 0x%llx"
    u64 kernelcache__vn_kqfilter;                     // "Invalid knote filter on a vnode!"
    // address translation
    u64 device__T1SZ_BOOT;
    u64 device__ARM_TT_L1_INDEX_MASK;
};

struct dynamic_info dynamic_system_info = { 0 };

#define ARM64_LINK_ADDR dynamic_info(kernelcache__static_base)

#endif /* dynamic_info_h */
