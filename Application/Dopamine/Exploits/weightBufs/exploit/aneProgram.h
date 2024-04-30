#ifndef H_ANEPROGRAM_H
#define H_ANEPROGRAM_H

#include <stdio.h>
#include <mach/mach.h>
#include <CoreFoundation/CoreFoundation.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <mach-o/loader.h>

typedef unsigned int ZinComputeProgramStatus;
struct ZinComputeProgramInitInfo;
struct ZinComputeProgramStruct;
struct ZinComputeProgramSection;
typedef struct ZinComputeProgramStruct ZinComputeProgram;

typedef uint64_t u64;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint8_t u8;

#define FOR_EACH_COMMAND                                                \
        lc = (load_command*)(mh + 1);                                   \
        for (int i = 0; i < mh->ncmds; ++i, lc = (load_command*)((char*)lc + lc->cmdsize))


CFMutableDictionaryRef ANECCreateModelDictionary(void *, size_t);
ZinComputeProgramStatus  ZinComputeProgramUpdateMutables(uint32_t,void *,void *, size_t,void *,size_t);

ZinComputeProgramStatus ZinComputeProgramMakeInitInfo(
        const ZinComputeProgram *,
        struct ZinComputeProgramInitInfo **);

ZinComputeProgramStatus ZinComputeProgramMake(
        struct mach_header_64 *,
        size_t,
        struct ZinComputeProgramStruct **);

ZinComputeProgramStatus  ZinComputeProgramHasMutableOperation(
        struct ZinComputeProgramStruct *,
        boolean_t *);

ZinComputeProgramStatus __cdecl ZinComputeProgramGetInitSection(
        const ZinComputeProgram *program,
        struct ZinComputeProgramSection **SectionOut);

ZinComputeProgramStatus __cdecl ZinComputeProgramCompareCompilerVersion(const char *, const char *, int32_t *);

ZinComputeProgramStatus ZinComputeProgramGetNamesFromMultiPlaneLinear(struct load_command *,u32 *, u64*, u32 *,u64 *);

long ZinComputeProgramGetNamesFromMultiPlaneTiledCompressed(struct load_command *,u32 *,
                                                                       u64 *,
                                                                       u64 *,
                                                                       u64 *,
                                                                       u64 *);

struct ZinComputeProgramSectionInfo
{
        struct
        {
                int  bufferType;
                struct ZinComputeProgramSection *ComputeSgment;
        }infos;
};

ZinComputeProgramStatus ZinComputeGetProgramSections(ZinComputeProgram *,
                                            uint32_t *,
                                            struct ZinComputeProgramSectionInfo **);

struct ZinComputeProgramInitInfo
{
        uint64_t count_index;
        void* unk_ptr;
        uint64_t unk_ptr_size;
};


struct compute_thread_binding;
struct ZinComputeProgramBinding
{
        struct load_command *load_command;
        void *unk_thread_obj;
        struct compute_thread_binding *thread_binding;
};

struct ZinComputeProgramSymbol {int a;};

struct __attribute__((aligned(8))) ZinComputeProgramSection
{
        struct section_64 *MachSections;
        struct ZinComputeProgramSegment *ProgramSegments;
        struct relocation_entries *relocation_entries;
        char *sect_start_addrs;
        u64 field_20;
};

struct ZinComputeProgramProcedure
{
        char *procedureName;
        u64 proc_fvmlib_count;
        struct ZinComputeProgramFvmlib **fvmlib;
        u64 ProcedcureOperationsCount;
        struct ZinComputeProcedureOperation **ProcedcureOperations;
        u64 field_28;
        u64 ProgramBindingsCount;
        struct ZinComputeProgramBinding **ProgramBindings;
};


struct ZinComputeProcedureOperation {int a;};
struct ZinComputeProgramFvmlib {int a;};
struct ZinComputeProgramSegment {int a;};


struct ZinComputeProgramStruct
{
        struct mach_header_64 *CP_mach_header;
        u64 CP_version;
        struct ident_command *CP_lc_ident;
        struct note_command *CP_lc_note;
        struct source_version_command *CP_lc_source_version;
        u64 CP_ProgramSegments_Count;
        struct ZinComputeProgramSegment *CP_ProgramSegments;
        u64 CP_fixed_vm_dylib_count;
        struct ZinComputeProgramFvmlib *CP_ProgramFvmlib;
        u64 CP_ThreadProcedureOperationsCount;
        struct ZinComputeProcedureOperation *CP_ThreadProcedureOperations;
        u64 CP_ThreadProceduresCount;
        struct ZinComputeProgramProcedure *CP_ThreadProcedures;
        struct symtab_command *CP_ProgramSymbolTable;
        struct ZinComputeProgramSymbol *CP_ProgramSymbols;
        u64 CP_unk_78;
        u64 CP_ThreadBindingCount;
        struct ZinComputeProgramBinding *CP_ThreadBindings;
};

enum THREAD_FLAVORS
{
        THREAD_PROCEDURE_OPERATION = 0x1,
        THREAD_FLAVORS_2 = 0x2,
        THREAD_BINDING = 0x3,
        THREAD_PROCEDURE = 0x4,
};


union compute_thread_command_flavors
{
        u8 * procedure_operation; // ane_op_state ?
        u8 * ane_bind_state; // ane_bind_state
        u8 * seg_thread_state; // ane_seg_thread_state_64
};


struct compute_thread_command
{
        u32 cmd;
        u32 cmdsize;
        enum THREAD_FLAVORS flavor;
        int count;
        union compute_thread_command_flavors thread_states;
};

struct compute_thread_binding
{
        u32 binding_typeinfo;
        u32 kind;
        char data[0xD20];
};

struct relocation_info
{
        int32_t r_address;
        uint32_t r_symbolnum;
};

struct relocation_entries
{
        struct relocation_info *relocs;
        struct ZinComputeProgramSymbol *Symbols;
        struct ZinComputeProgramSection *compute_sect;
};



struct ANECMutableProcedureInfoHeader {
        u64 field_0;
        u64 field_8;
        u64 field_10;
        u32 weight_buffer_size;
        u32 unk_20;
};

struct ANECMutableProcedureInfo
{
        struct ANECMutableProcedureInfoHeader hdr;
        uint64_t wb_offsets[0];
};

struct opsInfo
{
        uint32_t op_index;
        uint32_t op_count;
        uint64_t op_offsets[0];
};

struct weightInfo {
        uint64_t wi_index;
        uint64_t wi_offset;
        uint64_t wi_size;
};


typedef struct  {
        mach_port_t eventPort;
        uint32_t eventType;
        uint64_t waitValue;
        uint64_t unknown;
        uint64_t _mIOSurfaceSharedEvent;
        uint64_t field_20;
} Events;

typedef struct {
        uint32_t numWaitEvents;
        uint32_t numSignalEvents;
        Events WaitEvents[0x40];
        Events SignalEvents[0x40];
} H11ANESharedEventsStruct;



#if 0
struct ZinComputeProgramStruct
{
        struct mach_header_64 *mach_header;
        u64 version;
        struct ident_command *ident_cmd;
        stryct note_command *lc_note;
        struct source_version_command *lc_source_version;
        u64 segment_count;
        void *segments;                                         /* ZinComputeProgramSegment *segments; */
        u64 fixed_vm_dylibs_count;
        void *fixed_vm_dylibs;                                  /* ZinComputeProgramFvmlib */
        u64 size;
        void *lc_procedure_operation;                           /* ZinComputeProcedureOperation */
        u64 procedure_count;
        void  *procedures;                                      /* ZinComputeProgramProcedure */
        struct symtab_command *ProgramSymbolTable;
        void *ProgramSymbols;                                   /* ZinComputeProgramSymbol */
        u64 unk_78;
        u64 ProgramBindingCount;
        void *ProgramBinding;                                   /* ZinComputeProgramBinding */
};
#endif


struct OcgRasterizationInfoStruct
{
        u16 vals[4];
};

typedef struct
{
        u64 read_count;                             /* How many bytes I'd like to read ? */
        u64 read_offset;                            /* At which offset I should start reading data ?  */
        u64 global_chunk_size;
        u32 chunk_index;                            /* DeCxt::FileIndexToWeight() OOB Read due to lack of array index validation */
        u64 underflow;                              /* DeCxt::RasterizeScaleBiasData() OOB writes due to integer overflow vulnerability */
        struct OcgRasterizationInfoStruct ocg;
}serializer_info_t;


#endif  /* H_ANEPROGRAM_H */
