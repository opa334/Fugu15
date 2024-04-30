#ifndef _H_ANEDIRECTIN_H
#define _H_ANEDIRECTIN_H

#include "iokit.h"

struct H11ANEDeviceInfoStruct {
        uint64_t fields[0x58/8];
};

typedef struct
{
        uint64_t programHandle;
        uint64_t field_8;
        unsigned int procedureId;
        uint32_t field_14;
        uint64_t field_18;
        uint64_t field_20;
        unsigned int total_InputBuffers;
        char inputBufferSymbolIndex[256];
        uint32_t inputBufferSurfaceId[255];
        unsigned int total_OutputBuffers;
        char OutputBuffers[256];
        uint32_t outputBufferSurfaceId[255];
        unsigned int total_IntermediateBuffers;
        uint IntermediateBufferSurfaceId[3];
        uint64_t callBack;
        uint64_t refCon;
        char field_A48;
        char field_A49;
        char field_A4A;
        char field_A4B;
        uint32_t weightsBufferSurfaceId;
        uint64_t EventsAddr;
        uint64_t field_A58;
} H11ANEProgramRequestArgsStruct;

kern_return_t do__ANEDriect_DeviceOpen(io_connect_t client,void *in);
kern_return_t do__ANEDirect_ProgramSendRequest(io_connect_t client,mach_port_t port, void *address);

#endif  /* _H_ANEDIRECTIN_H */
