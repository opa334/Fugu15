#include "IOSurface.h"

io_connect_t get_surface_client(void)
{
        return iokit_get_connection("IOSurfaceRoot",0);
}


io_connect_t create_surface_fast_path(io_connect_t surface,uint32_t *surface_id,IOSurfaceFastCreateArgs *args)
{
        io_connect_t conn = surface;
        kern_return_t kr = KERN_SUCCESS;

        char output[IOSurfaceLockResultSize] = {0};
        size_t output_cnt = IOSurfaceLockResultSize;

        if (surface == 0) {
                conn = get_surface_client();
        }

        kr = IOConnectCallMethod(conn, 6, 0,0,
                                 args, 0x20,
                                 NULL, NULL, output, &output_cnt);
        CHECK_IOKIT_ERR(kr, "create_surface_fast_path");
        assert(kr == KERN_SUCCESS);

        if (surface_id != NULL)
                *surface_id = *(uint32_t *)(output + 0x18);

        return conn;
}

io_connect_t release_surface(io_connect_t surface,uint32_t surface_id)
{
        io_connect_t conn = surface;
        kern_return_t kr = KERN_SUCCESS;

        uint64_t scalar = (uint64_t)surface_id;
        kr = IOConnectCallMethod(conn, 1, &scalar,1,
                                 NULL,0,
                                 NULL, NULL, NULL, NULL);
        CHECK_IOKIT_ERR(kr, "release_surface");
        assert(kr == KERN_SUCCESS);

        return conn;
}


mach_port_t iosurface_create_shared_event(io_connect_t c)
{
        kern_return_t kr = KERN_SUCCESS;

        uint32_t outputSize = 1;
        uint64_t port = 0;
        kr = IOConnectCallMethod(c, 36, 0,0,
                                 NULL, 0,
                                 &port, &outputSize, NULL, NULL);
        CHECK_IOKIT_ERR(kr, "do_create_shared_event");
        return (mach_port_t)port;
}

kern_return_t iosurface_signal_shared_event(io_connect_t c,mach_port_t sharedRefId, uint64_t signal)
{
        kern_return_t kr = KERN_SUCCESS;
        uint64_t scalar[2] = {(uint64_t)sharedRefId,signal};

        kr = IOConnectCallMethod(c, 37, scalar,2,
                                 NULL, 0,
                                 NULL, NULL, NULL, NULL);
        CHECK_IOKIT_ERR(kr, "iosurface_signal_shared_event");
        return kr;
}


kern_return_t iosurface_query_shared_event(io_connect_t c,mach_port_t sharedRefId)
{
        kern_return_t kr = KERN_SUCCESS;
        uint64_t scalar[1] = {(uint64_t)sharedRefId};
        uint64_t scalarO[2] = {0};
        uint32_t scalarOSize = 2;

        kr = IOConnectCallMethod(c, 38, scalar,1,
                                 NULL, 0,
                                 scalarO,&scalarOSize , NULL, NULL);
        CHECK_IOKIT_ERR(kr, "iosurface_query_shared_event");
        //printf("Completed Value 0x%llx \n",scalarO[0]);

        return kr;
}

kern_return_t iosurface_notify_shared_event(io_connect_t c,mach_port_t sharedRefId,
                                            uint64_t arg1,
                                            uint64_t arg2,
                                            uint64_t arg3,
                                            uint64_t arg4)
{
        kern_return_t kr = KERN_SUCCESS;
        uint64_t scalar[5] = {(uint64_t)sharedRefId,arg1,arg2,arg3,arg4};

        kr = IOConnectCallMethod(c, 39, scalar,5,
                                 NULL, 0,
                                 NULL,NULL , NULL, NULL);
        CHECK_IOKIT_ERR(kr, "iosurface_noitfy_shared_event");

        return kr;
}


void add_shared_event_notification_port(io_connect_t c,mach_port_t port,uint64_t *references)
{
        kern_return_t kr = KERN_SUCCESS;

        kr = IOConnectCallAsyncMethod(c, 40, port, references, 8,
                                      NULL, 0,
                                      NULL, 0,
                                      NULL, NULL,
                                      NULL, NULL);
        CHECK_IOKIT_ERR(kr, "add_shared_event_notification_port");
}


void notify_shared_event(io_connect_t c,u64 sharedRefId, u64 refcon, u64 a,u64 b,u64 cc)
{
        kern_return_t kr = KERN_SUCCESS;

        uint64_t scalars[5] = {sharedRefId,refcon,a,b,cc};
        kr = IOConnectCallMethod(c, 39, scalars,5,
                                 NULL, 0,
                                 NULL, NULL, NULL, NULL);
        CHECK_IOKIT_ERR(kr, "do_create_shared_event");

}



uint32_t *prop_data = 0;
vm_size_t prop_data_size = 0xff000000;
void * init_iosurface_prop_data(void)
{
        if(prop_data)
                return prop_data;

        mach_vm_address_t addr = 0;
#if TARGET_OS_IOS
        prop_data_size = 0xf000000;
#endif
        kern_return_t kr = _kernelrpc_mach_vm_allocate_trap(mach_task_self(),&addr,prop_data_size,1);

        CHECK_IOKIT_ERR(kr, "allocate_properties_buf");
        prop_data = (uint32_t*)addr;
        return prop_data;

}


void iosurface_remove_property(io_connect_t surface,uint32_t surface_id,uint32_t key)
{

        kern_return_t kr = KERN_SUCCESS;
        uint64_t _output = 0;
        size_t output_cnt = 4;

        uint64_t payload[2];
        payload[0] = surface_id;
        payload[1] = key;

        kr = IOConnectCallMethod(surface, 11,
                                 NULL,
                                 0,
                                 payload,
                                 0x10,
                                 NULL, NULL,
                                 &_output, &output_cnt);

        assert(kr == KERN_SUCCESS);
}

void iosurface_get_value(io_connect_t client,uint32_t surface_id,uint32_t key,void *output,size_t *outputSize)
{

        kern_return_t kr = KERN_SUCCESS;
        uint64_t payload[2];
        payload[0] = surface_id;
        payload[1] = key;

        kr = IOConnectCallMethod(client,
                                 10,
                                 NULL,
                                 0,
                                 payload,
                                 0x10,
                                 NULL, NULL,
                                 output, outputSize);

        assert(kr == KERN_SUCCESS);
}

void iosurface_set_value(io_connect_t surface,uint32_t surface_id)
{
        kern_return_t kr = KERN_SUCCESS;
        uint64_t _output = 0;
        size_t output_cnt = 4;

        *(uint64_t *) prop_data =  surface_id;

        kr = IOConnectCallMethod(surface, 9,
                                 NULL,
                                 0,
                                 prop_data,
                                 prop_data_size,
                                 NULL, NULL,
                                 &_output, &output_cnt);

        CHECK_IOKIT_ERR(kr, "iosurface_set_value");
        assert(kr == KERN_SUCCESS);
}

uint32_t build_iosurface_payload(uint32_t count,uint8_t *data,uint32_t datasize,uint32_t key)
{
        assert(prop_data != NULL);

        uint32_t * binary = prop_data + 2;
        memset((char *)prop_data,0,prop_data_size );

        int cur = 0;

        binary[cur++]  = kOSSerializeBinarySignature;
        binary[cur++]  = (kOSSerializeEndCollection| kOSSerializeArray | 2);

        binary[cur++] = (kOSSerializeArray | count);
        // count : how many object we want ?
        for(int i=0; i< count; i++) {
                int end = (i == (count -1))? kOSSerializeEndCollection : 0;
                binary[cur++]  = (end |kOSSerializeData | datasize );
                memcpy((char *)&binary[cur],data,datasize);
                cur +=  (datasize +3)/4;
        }

        binary[cur++]  = (kOSSerializeEndCollection | kOSSerializeSymbol | 5); // key
        binary[cur++]  = key;
        binary[cur++]  = 0;
        return cur;
}

uint32_t build_surface_payload_with_string(uint32_t count,char *string,uint32_t stringsize,uint32_t key)
{

        uint32_t * binary = prop_data + 2;//a place for surface id
        memset((char *)prop_data,0,prop_data_size);

        int cur = 0;

        binary[cur++]  = kOSSerializeBinarySignature;
        binary[cur++]  = (kOSSerializeEndCollection| kOSSerializeArray | 2);

        binary[cur++] = (kOSSerializeArray | count);
        // count : how many object we want ?
        for(int i=0; i< count; i++) {
                int end = (i == (count -1))? kOSSerializeEndCollection : 0;
                binary[cur++]  = (end |kOSSerializeString | stringsize -1 );
                memcpy((char *)&binary[cur],string,stringsize);
                cur +=  (stringsize +3)/4;
        }

        binary[cur++]  = (kOSSerializeEndCollection | kOSSerializeSymbol | 5); // key
        binary[cur++]  = key;
        binary[cur++]  = 0;
        return cur;
}

void set_indexed_timestamp(io_connect_t c,uint32_t surface_id,uint64_t index,uint64_t value)
{
        uint64_t args[3] = {0};
        args[0] = surface_id;
        args[1] = index;
        args[2] = value;
        kern_return_t kr = IOConnectCallMethod(c, 33, args,3,
                                               NULL, 0,
                                               NULL, NULL, NULL, NULL);
        CHECK_IOKIT_ERR(kr, "set_indexed_timestamp");
}

kern_return_t iosurface_get_use_count(io_connect_t c,uint32_t surface_id,uint32_t *output)
{
        uint64_t args[1] = {0};
        args[0] = surface_id;
        uint32_t outsize = 1;
        uint64_t out = 0;

        kern_return_t kr = IOConnectCallMethod(c, 16, args,1,
                                               NULL, 0,
                                               &out, &outsize, NULL, NULL);
        CHECK_IOKIT_ERR(kr, "iosurface_get_use_count");
        *output = (uint32_t)out;
        return kr;
}
