#include "IOGPU.h"

struct IOGPUNotificationQueueData * do_s_create_notificationqueue(io_connect_t client)
{

        uint32_t structInputCnt = 0;
        uint32_t structOutputCnt = 16;

        IOKit_args_t *args = allocate_args(structInputCnt,structOutputCnt, False);

        args->client = client;

#if TARGET_OS_OSX
        u32 selector = 17;
#else
        u32 selector = 15;
#endif
        kern_return_t kr = IOConnectCallMethod(args->client,
                                               selector,
                                               args->scalarI,args->scalarISize,
                                               args->sInput, args->sInputSize,
                                               args->scalarO, (uint32_t *)&args->scalarOSize,
                                               args->sOutput, (size_t *)&args->sOutputSize);

        CHECK_IOKIT_ERR(kr, "s_create_notificationqueue");

        struct IOGPUNotificationQueueData * output = (struct IOGPUNotificationQueueData *)args->sOutput;
        args->sOutput = NULL;

        destroy_args(args);
        return output;
}


void do_s_destroy_notificationqueue(io_connect_t client,uint32_t id)
{

        uint32_t structInputCnt = 0;
        uint32_t structOutputCnt = 0;

        IOKit_args_t *args = allocate_args(structInputCnt,structOutputCnt, False);

        args->client = client;

        args->scalarISize = 1;
        args->scalarI[0] = id;

#if TARGET_OS_OSX
        u32 selector = 18;
#else
        u32 selector = 16;
#endif

        kern_return_t kr = IOConnectCallMethod(args->client,
                                               selector,
                                               args->scalarI,args->scalarISize,
                                               args->sInput, args->sInputSize,
                                               args->scalarO, (uint32_t *)&args->scalarOSize,
                                               args->sOutput, (size_t *)&args->sOutputSize);
        CHECK_IOKIT_ERR(kr, "s_destroy_notificationqueue");

        destroy_args(args);
}


struct shmem * do_s_create_shmem(io_connect_t client,uint32_t shm_size,uint32_t shm_type)
{

        uint32_t structInputCnt = 0;
        uint32_t structOutputCnt = 16;

        IOKit_args_t *args = allocate_args(structInputCnt,structOutputCnt, False);

        args->client = client;

        args->scalarISize = 2;
        args->scalarI[0] = shm_size; // size
        args->scalarI[1] = shm_type; // shmem type

        // types : 2 -> AGXDebugBufferShmem, else : IOGPUDeviceShmem

#if TARGET_OS_OSX
        u32 selector = 15;
#else
        u32 selector = 13;
#endif

        kern_return_t kr = IOConnectCallMethod(args->client,
                                               selector,
                                               args->scalarI,args->scalarISize,
                                               args->sInput, args->sInputSize,
                                               args->scalarO, (uint32_t *)&args->scalarOSize,
                                               args->sOutput, (size_t *)&args->sOutputSize);
        CHECK_IOKIT_ERR(kr, "s_create_shmem");
        if(kr != KERN_SUCCESS) {
                destroy_args(args);
                return NULL;
        }

        struct shmem * output = (struct shmem *)args->sOutput;
        args->sOutput = NULL;
        destroy_args(args);
        return output;
}

kern_return_t do_s_new_command_queue(io_connect_t client,void *in,uint32_t *queue_id)
{

        uint32_t structInputCnt = 1032;
        uint32_t structOutputCnt = 16;

        IOKit_args_t *args = allocate_args(structInputCnt,structOutputCnt, False);

        uint8_t * input = (uint8_t *)args->sInput;
        memcpy(input,in,structInputCnt);

        args->client = client;


#if TARGET_OS_OSX
        u32 selector = 8;
#else
        u32 selector = 7;
#endif

        kern_return_t kr = IOConnectCallMethod(args->client,
                                               selector,
                                               args->scalarI,args->scalarISize,
                                               args->sInput, args->sInputSize,
                                               args->scalarO, (uint32_t *)&args->scalarOSize,
                                               args->sOutput, (size_t *)&args->sOutputSize);
        CHECK_IOKIT_ERR(kr, "s_new_command_queue");
        *queue_id = *(uint32_t *)args->sOutput;

        destroy_args(args);
        return kr;
}

void do_s_submit_command_buffers(io_connect_t client,uint32_t cmdqID,uint8_t *buf,uint32_t size)
{

        uint32_t structInputCnt = size;
        uint32_t structOutputCnt = 0;
        IOKit_args_t *args = allocate_args(structInputCnt,structOutputCnt, False);

        uint8_t * input = (uint8_t *)args->sInput;
        memcpy(input,buf,size);
        args->client = client;

        args->scalarISize = 1;
        args->scalarI[0] = cmdqID;

#if TARGET_OS_OSX
        u32 selector = 30;
#else
        u32 selector = 26;
#endif

        kern_return_t kr = IOConnectCallMethod(args->client,
                                               selector,
                                               args->scalarI,args->scalarISize,
                                               args->sInput, args->sInputSize,
                                               args->scalarO, (uint32_t *)&args->scalarOSize,
                                               args->sOutput, (size_t *)&args->sOutputSize);
        CHECK_IOKIT_ERR(kr, "s_submit_command_buffers");
        destroy_args(args);
}

kern_return_t do_s_set_command_queue_notification_queue(io_connect_t client,uint32_t command_id,uint32_t notify_id)
{

        uint32_t structInputCnt = 0;
        uint32_t structOutputCnt = 0;

        IOKit_args_t *args = allocate_args(structInputCnt,structOutputCnt, False);

        args->client = client;

        args->scalarISize = 2;
        args->scalarI[0] = command_id;
        args->scalarI[1] = notify_id;
#if TARGET_OS_OSX
        u32 selector = 29;
#else
        u32 selector = 25;
#endif

        kern_return_t kr =  IOConnectCallMethod(args->client,
                                                selector,
                                                args->scalarI,args->scalarISize,
                                                args->sInput, args->sInputSize,
                                                args->scalarO, (uint32_t *)&args->scalarOSize,
                                                args->sOutput, (size_t *)&args->sOutputSize);
        CHECK_IOKIT_ERR(kr, "s_set_command_queue_notification_queue");
        destroy_args(args);
        return kr;
}
