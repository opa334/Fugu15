#ifndef __SANDBOX_H__
#define __SANDBOX_H__

#include <mach/mach.h>
#include <stdlib.h>

enum sandbox_filter_type {
	SANDBOX_FILTER_NONE,
	SANDBOX_FILTER_PATH,
	SANDBOX_FILTER_GLOBAL_NAME,
	SANDBOX_FILTER_LOCAL_NAME,
	SANDBOX_FILTER_APPLEEVENT_DESTINATION,
	SANDBOX_FILTER_RIGHT_NAME,
	SANDBOX_FILTER_PREFERENCE_DOMAIN,
	SANDBOX_FILTER_KEXT_BUNDLE_ID,
	SANDBOX_FILTER_INFO_TYPE,
	SANDBOX_FILTER_NOTIFICATION,
	// ?
	// ?
	SANDBOX_FILTER_XPC_SERVICE_NAME = 12,
	SANDBOX_FILTER_IOKIT_CONNECTION,
	// ?
	// ?
	// ?
	// ?
};

enum sandbox_extension_flags {
	FS_EXT_DEFAULTS =              0,
	FS_EXT_FOR_PATH =       (1 << 0),
	FS_EXT_FOR_FILE =       (1 << 1),
	FS_EXT_READ =           (1 << 2),
	FS_EXT_WRITE =          (1 << 3),
	FS_EXT_PREFER_FILEID =  (1 << 4),
};

enum sandbox_extension_types {
    EXTENSION_TYPE_FILE,
    EXTENSION_TYPE_MACH,
    EXTENSION_TYPE_IOKIT_REGISTRY_ENTRY,
    EXTENSION_TYPE_GENERIC,
    EXTENSION_TYPE_POSIX,
    EXTENSION_TYPE_PREFERENCE,
    EXTENSION_TYPE_SYSCTL,
    EXTENSION_TYPE_MAX /* last */
};

#define EXTENSION_FLAG_INVALID        (1 <<  0)
#define EXTENSION_FLAG_CANONICAL    (1 <<  1)
#define EXTENSION_FLAG_PREFIXMATCH    (1 <<  2)  /* Not for paths. */
#define EXTENSION_FLAG_PATHLITERAL    (1 <<  3)  /* Only for paths. */
#define EXTENSION_FLAG_NO_REPORT    (1 <<  4)
#define EXTENSION_FLAG_BIND_PID        (1 << 16)
#define EXTENSION_FLAG_BIND_PIDVERSION    (1 << 17)

#define MAX_TOKEN_SIZE 2048

struct syscall_extension_issue_args {
    uint64_t extension_class;
    uint64_t extension_type;
    uint64_t extension_data;
    uint64_t extension_flags;
    uint64_t extension_token;        /* out */
    int64_t extension_pid;
    int64_t extension_pid_version;
};

extern const char *APP_SANDBOX_IOKIT_CLIENT;
extern const char *APP_SANDBOX_MACH;
extern const char *APP_SANDBOX_READ;
extern const char *APP_SANDBOX_READ_WRITE;

extern const char *IOS_SANDBOX_APPLICATION_GROUP;
extern const char *IOS_SANDBOX_CONTAINER;

extern const enum sandbox_filter_type SANDBOX_CHECK_ALLOW_APPROVAL;
extern const enum sandbox_filter_type SANDBOX_CHECK_CANONICAL;
extern const enum sandbox_filter_type SANDBOX_CHECK_NOFOLLOW;
extern const enum sandbox_filter_type SANDBOX_CHECK_NO_APPROVAL;
extern const enum sandbox_filter_type SANDBOX_CHECK_NO_REPORT;

extern const uint32_t SANDBOX_EXTENSION_CANONICAL;
extern const uint32_t SANDBOX_EXTENSION_DEFAULT;
extern const uint32_t SANDBOX_EXTENSION_MAGIC;
extern const uint32_t SANDBOX_EXTENSION_NOFOLLOW;
extern const uint32_t SANDBOX_EXTENSION_NO_REPORT;
extern const uint32_t SANDBOX_EXTENSION_NO_STORAGE_CLASS;
extern const uint32_t SANDBOX_EXTENSION_PREFIXMATCH;
extern const uint32_t SANDBOX_EXTENSION_UNRESOLVED;

int sandbox_init(const char *profile, uint64_t flags, char **errorbuf);
int sandbox_init_with_parameters(const char *profile, uint64_t flags, const char *const parameters[], char **errorbuf);
int sandbox_init_with_extensions(const char *profile, uint64_t flags, const char *const extensions[], char **errorbuf);

int sandbox_check(pid_t pid, const char *operation, enum sandbox_filter_type, ...);
int sandbox_check_by_audit_token(audit_token_t, const char *operation, enum sandbox_filter_type, ...);
int sandbox_check_by_uniqueid(uid_t, pid_t, const char *operation, enum sandbox_filter_type, ...);

int64_t sandbox_extension_consume(const char *extension_token);
char *sandbox_extension_issue_file(const char *extension_class, const char *path, uint32_t flags);
char *sandbox_extension_issue_file_to_process(const char *extension_class, const char *path, uint32_t flags, audit_token_t);
char *sandbox_extension_issue_file_to_process_by_pid(const char *extension_class, const char *path, uint32_t flags, pid_t);
char *sandbox_extension_issue_file_to_self(const char *extension_class, const char *path, uint32_t flags);
char *sandbox_extension_issue_generic(const char *extension_class, uint32_t flags);
char *sandbox_extension_issue_generic_to_process(const char *extension_class, uint32_t flags, audit_token_t);
char *sandbox_extension_issue_generic_to_process_by_pid(const char *extension_class, uint32_t flags, pid_t);
char *sandbox_extension_issue_iokit_registry_entry_class(const char *extension_class, const char *registry_entry_class, uint32_t flags);
char *sandbox_extension_issue_iokit_registry_entry_class_to_process(const char *extension_class, const char *registry_entry_class, uint32_t flags, audit_token_t);
char *sandbox_extension_issue_iokit_registry_entry_class_to_process_by_pid(const char *extension_class, const char *registry_entry_class, uint32_t flags, pid_t);
char *sandbox_extension_issue_iokit_user_client_class(const char *extension_class, const char *registry_entry_class, uint32_t flags);
char *sandbox_extension_issue_mach(const char *extension_class, const char *name, uint32_t flags);
char *sandbox_extension_issue_mach_to_process(const char *extension_class, const char *name, uint32_t flags, audit_token_t);
char *sandbox_extension_issue_mach_to_process_by_pid(const char *extension_class, const char *name, uint32_t flags, pid_t);
char *sandbox_extension_issue_posix_ipc(const char *extension_class, const char *name, uint32_t flags);

void sandbox_extension_reap(void);
int sandbox_extension_release(int64_t extension_handle);
int sandbox_extension_release_file(int64_t extension_handle, const char *path);
int sandbox_extension_update_file(int64_t extension_handle, const char *path);

int __sandbox_ms(const char *policyname, int call, void *arg);

#endif