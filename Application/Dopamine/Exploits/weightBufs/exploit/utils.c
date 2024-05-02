#include "iokit.h"

char * load_file(const char* filename, vm_size_t * size) {
        int fd = open(filename,O_RDONLY);
        if(fd < 0) {
                perror("load_file(): %s \n");
        }
        assert(fd > 0);

        struct stat st = {};
        int err = fstat(fd,&st);
        assert(err == 0);

        void *ptr = mmap(0,round_page(st.st_size),PROT_READ | PROT_WRITE,MAP_FILE | MAP_PRIVATE, fd,0);
        assert(ptr != (void*)-1);
        *size = round_page(st.st_size);
        close(fd);

        return (char*)ptr;
}

io_connect_t iokit_get_connection(const char *name,unsigned int type)
{
        io_service_t service  = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                            IOServiceMatching(name));
        if (service == IO_OBJECT_NULL) {
                printf("unable to find service \n");
                exit(-1);
        }

        io_connect_t conn = MACH_PORT_NULL;
        kern_return_t kr = IOServiceOpen(service, mach_task_self(), type, &conn);
        if(kr != KERN_SUCCESS) {
                printf("[x] Could not open %s: %s\n",name,mach_error_string(kr));
                exit(-1);

        }
        return conn;
}


IOKit_args_t * allocate_args(uint32_t InSize,uint32_t OutSize,bool has_mp)
{
        IOKit_args_t *args = (IOKit_args_t *)calloc(sizeof(IOKit_args_t),1);
        args->sInput = (uint8_t *)calloc(InSize,1);
        args->sOutput = (uint8_t *)calloc(OutSize,1);

        args->sInputSize = InSize;
        args->sOutputSize = OutSize;

        if(has_mp) {
                mach_port_t mp = 0;
                if(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &mp))
                        assert(false);
                args->asyncAwake  = mp;
        }
        return args;
}

void destroy_args(IOKit_args_t *args)
{
        if(args->sInput) free(args->sInput);
        if(args->sOutput) free(args->sOutput);

        if(args->asyncAwake)
                ;//mach_port_destroy(mach_task_self(),args->asyncAwake);

        args->sInput = args->sOutput = NULL;
        free(args);


}


CFNumberRef CFInt32(int32_t value)
{
        return CFNumberCreate(NULL, kCFNumberSInt32Type, &value);
}

CFNumberRef CFInt64(int64_t value)
{
        return CFNumberCreate(NULL, kCFNumberSInt64Type, &value);
}


void hexdump(const void* data, size_t size)
{
        char ascii[17];
        size_t i, j;
        ascii[16] = '\0';
        for (i = 0; i < size; ++i) {
                printf("%02X ", ((unsigned char*)data)[i]);
                if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
                        ascii[i % 16] = ((unsigned char*)data)[i];
                } else
                        ascii[i % 16] = '.';

                if ((i+1) % 8 == 0 || i+1 == size) {
                        printf(" ");
                        if ((i+1) % 16 == 0)
                                printf("|  %s \n", ascii);
                        else if (i+1 == size) {
                                ascii[(i+1) % 16] = '\0';
                                if ((i+1) % 16 <= 8) {
                                        printf(" ");
                                }
                                for (j = (i+1) % 16; j < 16; ++j)
                                        printf("   ");

                                printf("|  %s \n", ascii);
                        }
                }
        }
}
