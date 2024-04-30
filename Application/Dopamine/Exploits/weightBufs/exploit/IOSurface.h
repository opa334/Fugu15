#ifndef H_IOSURFACE_H
#define H_IOSURFACE_H

#include "iokit.h"
#include <IOSurface/IOSurfaceRef.h>

#define IOSurfaceLockResultSize 0xF60

#define kOSSerializeBinarySignature        0x000000D3
#define kOSSerializeIndexedBinarySignature 0x000000D4

typedef struct IOSurfaceFastCreateArgs
{
        uint64_t IOSurfaceAddress;
        uint32_t IOSurfaceWidth;
        uint32_t IOSurfaceHeight;
        uint32_t IOSurfacePixelFormat;
        uint32_t IOSurfaceBytesPerElement;
        uint32_t IOSurfaceBytesPerRow;
        uint32_t IOSurfaceAllocSize;
} IOSurfaceFastCreateArgs;


io_connect_t get_surface_client(void);
io_connect_t release_surface(io_connect_t surface,uint32_t surface_id);
io_connect_t create_surface_fast_path(io_connect_t surface,uint32_t *surface_id,IOSurfaceFastCreateArgs *args);
void set_indexed_timestamp(io_connect_t c,uint32_t surface_id,uint64_t index,uint64_t value);
kern_return_t iosurface_get_use_count(io_connect_t c,uint32_t surface_id,uint32_t *output);
void iosurface_remove_property(io_connect_t ,uint32_t ,uint32_t );

typedef uint64_t u64;

mach_port_t iosurface_create_shared_event(io_connect_t c);
kern_return_t iosurface_signal_shared_event(io_connect_t c,mach_port_t sharedRefId, uint64_t signal);
kern_return_t iosurface_query_shared_event(io_connect_t c,mach_port_t sharedRefId);
kern_return_t iosurface_notify_shared_event(io_connect_t c,mach_port_t sharedRefId,
                                            uint64_t arg1,
                                            uint64_t arg2,
                                            uint64_t arg3,
                                            uint64_t arg4);


void add_shared_event_notification_port(io_connect_t c,mach_port_t port,uint64_t *references);
void notify_shared_event(io_connect_t ,u64 , u64 , u64 ,u64 ,u64 );
void iosurface_set_value(io_connect_t ,uint32_t );
void * init_iosurface_prop_data(void);
uint32_t build_iosurface_payload(uint32_t count,uint8_t *data,uint32_t datasize,uint32_t key);
uint32_t build_surface_payload_with_string(uint32_t count,char *string,uint32_t stringsize,uint32_t key);


#endif  /* H_IOSURFACE_H */
