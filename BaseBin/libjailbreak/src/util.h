#ifndef LJB_UTIL_H
#define LJB_UTIL_H

#include "info.h"
#include "jbclient_xpc.h"
#include "jbroot.h"

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

void proc_iterate(void (^itBlock)(uint64_t, bool*));

uint64_t proc_self(void);
uint64_t task_self(void);
uint64_t vm_map_self(void);
uint64_t pmap_self(void);
uint64_t ttep_self(void);
uint64_t tte_self(void);

uint64_t task_get_ipc_port_table_entry(uint64_t task, mach_port_t port);
uint64_t task_get_ipc_port_object(uint64_t task, mach_port_t port);
uint64_t task_get_ipc_port_kobject(uint64_t task, mach_port_t port);

uint64_t alloc_page_table_unassigned(void);
uint64_t pmap_alloc_page_table(uint64_t pmap, uint64_t va);
int pmap_expand_range(uint64_t pmap, uint64_t vaStart, uint64_t size);
int pmap_map_in(uint64_t pmap, uint64_t uaStart, uint64_t paStart, uint64_t size);

#ifdef __arm64e__
uint64_t pmap_find_main_binary_code_dir(uint64_t pmap);
uint64_t proc_find_main_binary_code_dir(uint64_t proc);
uint32_t pmap_cs_trust_string_to_int(const char *trustString);
#endif

int sign_kernel_thread(uint64_t proc, mach_port_t threadPort);
uint64_t kpacda(uint64_t pointer, uint64_t modifier);
uint64_t kptr_sign(uint64_t kaddr, uint64_t pointer, uint16_t salt);

void proc_allow_all_syscalls(uint64_t proc);

void killall(const char *executablePathToKill, bool softly);
int libarchive_unarchive(const char *fileToExtract, const char *extractionPath);

void thread_caffeinate_start(void);
void thread_caffeinate_stop(void);

void convert_data_to_hex_string(const void *data, size_t size, char *outBuf);
int convert_hex_string_to_data(const char *string, void *outBuf);

int cmd_wait_for_exit(pid_t pid);
int exec_cmd(const char *binary, ...);
int exec_cmd_nowait(pid_t *pidOut, const char *binary, ...);
int exec_cmd_suspended(pid_t *pidOut, const char *binary, ...);
int exec_cmd_root(const char *binary, ...);

#define exec_cmd_trusted(x, args ...) ({ \
    jbclient_trust_binary(x, NULL); \
    int retval; \
    retval = exec_cmd(x, args); \
    retval; \
})

char *boot_manifest_hash(void);

#define prebootUUIDPath(path) ({ \
	static char outPath[PATH_MAX]; \
	strlcpy(outPath, "/private/preboot/", PATH_MAX); \
	strlcat(outPath, boot_manifest_hash(), PATH_MAX); \
	strlcat(outPath, path, PATH_MAX); \
	(outPath); \
})

#define VM_FLAGS_GET_PROT(x)    ((x >>  7) & 0xFULL)
#define VM_FLAGS_GET_MAXPROT(x) ((x >> 11) & 0xFULL);
#define VM_FLAGS_SET_PROT(x, p)    x = ((x & ~(0xFULL <<  7)) | (((uint64_t)p) <<  7))
#define VM_FLAGS_SET_MAXPROT(x, p) x = ((x & ~(0xFULL << 11)) | (((uint64_t)p) << 11))

#ifdef __OBJC__
NSString *NSPrebootUUIDPath(NSString *relativePath);
#endif

void JBFixMobilePermissions(void);

#endif