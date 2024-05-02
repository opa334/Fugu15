#ifndef H_IOGPU_H
#define H_IOGPU_H

#include "iokit.h"

struct IOGPUNotificationQueueData
{
        uint64_t address;
        uint32_t id;
};

struct shmem {
        uint8_t *shm_addr;
        uint32_t shm_len;
        uint32_t shm_id;
};

typedef struct {
        vm_address_t gpuAddress;
        vm_address_t shm_addr;
        vm_address_t ro_addr;
        uint32_t unk_0x18;
        int resource_id;
        size_t resident_size;
        uint64_t unk_0x28;
        uint64_t unk_0x30;
        uint64_t unk_0x38;
        uint64_t protection;
        uint64_t unk_0x48;
}IOGPUNewResourceReturnData;

typedef uint32_t u32;
typedef uint64_t u64;
typedef struct {
        uint32_t field_0;
        uint32_t count; // how many submitArgs do we have in this structure ?
} IOGPUCommandQueueSubmitArgs_Header_t;

typedef struct {
        uint32_t shmid_1;
        uint32_t shmid_3;
        uint32_t shmid_2;
        uint64_t notify_1;
        uint64_t notify_2;
        uint32_t debug_shm_id;
        uint32_t padding;
} IOGPUCommandQueueSubmitArgs_Command_t;


typedef struct {
        IOGPUCommandQueueSubmitArgs_Header_t hdr;
        IOGPUCommandQueueSubmitArgs_Command_t body[1];
} IOGPUCommandQueueSubmitArgs_t;



/* Shmem1 struct for s_submit_command_buffers() */

struct IOGPUKernelCommand_Cmd_0x10005 {
        u64 mtlateevent_id;
        u64 kdebug_id;
};

struct IOGPUKernelCommand_Cmd_0x10003 {
        u64 var1; // must be less than 0x100
		u64 unused;
};

struct IOGPUKernelCommand_Cmd_0x2 {
        u64 sleep; // put the thread to sleep
};

struct IOGPUKernelCommand_Cmd_0x3 {
        u32 IOSurfacesharedEventId;
		u32 padd;
		u64 raw_64;
};

struct IOGPUKernelCommand_Cmd_0x4 {
        u32 IOSurfacesharedEventId;
		u32 padd;
		u64 raw_64;
};

struct IOGPUKernelCommand_Cmd_0x5 {
        u64 MTLEventId;
		u64 tosubmit;
};

struct IOGPUKernelCommand_Cmd_0x6 {
        u64 MTLEventId;
		u64 value;
};

// must be bigger than > 4
struct IOGPUKernelCommand_Cmd_0x8 {
        u32 resId_count;
		u32 resourceIds[];
};


struct IOGPUKernelCommand_Cmd_0x9 {
        u64 protection;
};

union IOGPUKernelCommand_Cmd
{
        /* ... */
        /* processKernelCommands ... */
		struct IOGPUKernelCommand_Cmd_0x10003 Cmd_0x10003;
		struct IOGPUKernelCommand_Cmd_0x10005 Cmd_0x10005;
		struct IOGPUKernelCommand_Cmd_0x2 Cmd_0x2;
		struct IOGPUKernelCommand_Cmd_0x3 Cmd_0x3;
		struct IOGPUKernelCommand_Cmd_0x4 Cmd_0x4;
		struct IOGPUKernelCommand_Cmd_0x5 Cmd_0x5;
		struct IOGPUKernelCommand_Cmd_0x6 Cmd_0x6;
		struct IOGPUKernelCommand_Cmd_0x8 Cmd_0x8;
		struct IOGPUKernelCommand_Cmd_0x9 Cmd_0x9;

};

struct IOGPUKernelCommand
{
        int type;
        int size;
        union IOGPUKernelCommand_Cmd cmd;
};



/* Shmem3 struct for s_submit_command_buffers() */
struct Shmem3_header
{
        uint32_t field0;
        uint32_t field4;
        uint32_t count;
        uint32_t fieldC;
};

struct Shmem3_offsets
{
        uint32_t kernelCommandStart;
        uint32_t kernelCommandEnd;
};

struct Shmem3
{
        struct Shmem3_header hdr;
        struct Shmem3_offsets off;
};



IOGPUNewResourceReturnData * do_s_new_resource(io_connect_t client, const char *str,size_t size, int *retval);
struct IOGPUNotificationQueueData * do_s_create_notificationqueue(io_connect_t client);
void do_s_destroy_notificationqueue(io_connect_t client,uint32_t id);
struct shmem * do_s_create_shmem(io_connect_t client,uint32_t shm_size,uint32_t shm_type);
kern_return_t do_s_new_command_queue(io_connect_t client,void *in,uint32_t *queue_id);
void do_s_submit_command_buffers(io_connect_t client,uint32_t cmdqID,uint8_t *buf,uint32_t size);
kern_return_t do_s_set_command_queue_notification_queue(io_connect_t client,uint32_t command_id,uint32_t notify_id);

#endif  /* H_IOGPU_H */

