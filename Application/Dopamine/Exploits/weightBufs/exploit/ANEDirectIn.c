#include "ANEDirectIn.h"

kern_return_t do__ANEDirect_ProgramSendRequest(io_connect_t client,mach_port_t port, void *address)
{

        uint32_t structInputCnt = 16;
        uint32_t structOutputCnt = 0;

        IOKit_args_t *args = allocate_args(structInputCnt,structOutputCnt, False);

        uint64_t * input = (uint64_t *)args->sInput;
        input[0] = (uint64_t)address;
        input[1] = 0xA60;

        args->client = client;
        args->asyncAwake = port;
        kern_return_t kr = IOConnectCallAsyncMethod(args->client,
                                                    2,
                                                    args->asyncAwake,
                                                    args->references,
                                                    8,
                                                    args->scalarI,args->scalarISize,
                                                    args->sInput, args->sInputSize,
                                                    args->scalarO, (uint32_t *)&args->scalarOSize,
                                                    args->sOutput, (size_t *)&args->sOutputSize);
        /* printf("_ANE_ProgramSendRequest status -> kr = (0x%x) %s\n",kr, mach_error_string(kr)); */
        destroy_args(args);
        return kr;
}

kern_return_t do__ANEDriect_DeviceOpen(io_connect_t client,void *in)
{

        uint32_t structInputCnt = 88;
        uint32_t structOutputCnt = 88;

        IOKit_args_t *args = allocate_args(structInputCnt,structOutputCnt, False);

        uint8_t * input = (uint8_t *)args->sInput;
        args->sInput = (uint8_t *)in;

        args->client = client;

        kern_return_t kr = IOConnectCallMethod(args->client,
                                               0,
                                               args->scalarI,args->scalarISize,
                                               args->sInput, args->sInputSize,
                                               args->scalarO, (uint32_t *)&args->scalarOSize,
                                               args->sOutput, (size_t *)&args->sOutputSize);
        if(kr)
                printf("_ANEDirect_DeviceOpen status -> kr = (0x%x) %s\n",kr, mach_error_string(kr));
        args->sInput = input;
        memcpy(in,args->sOutput,structInputCnt);
        destroy_args(args);
        return kr;
}
