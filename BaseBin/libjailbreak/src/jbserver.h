#ifndef JBSERVER_H
#define JBSERVER_H

#include <stdbool.h>
#include <stdint.h>
#include <xpc/xpc.h>
#include <xpc_private.h>

typedef enum {
    JBS_TYPE_BOOL,
	JBS_TYPE_UINT64,
	JBS_TYPE_STRING,
	JBS_TYPE_DATA,
    JBS_TYPE_ARRAY,
	JBS_TYPE_DICTIONARY,
	JBS_TYPE_CALLER_TOKEN,
} jbserver_type;

typedef struct s_jbserver_arg
{
    const char *name;
    jbserver_type type;
	bool out;
} jbserver_arg;

struct jbserver_action {
    void *handler;
    jbserver_arg *args;
};

struct jbserver_domain {
    bool (*permissionHandler)(audit_token_t);
    struct jbserver_action actions[];  // Flexible array member moved to the end
};

struct jbserver_impl {
    uint64_t maxDomain;
    struct jbserver_domain **domains;
};

extern struct jbserver_impl gGlobalServer;



// Domain: System-Wide
// Reachable from all processes
#define JBS_DOMAIN_SYSTEMWIDE 1
enum {
    JBS_SYSTEMWIDE_GET_JBROOT = 1,
    JBS_SYSTEMWIDE_GET_BOOT_UUID,
    JBS_SYSTEMWIDE_TRUST_BINARY,
    JBS_SYSTEMWIDE_TRUST_LIBRARY,
    JBS_SYSTEMWIDE_PROCESS_CHECKIN,
    JBS_SYSTEMWIDE_FORK_FIX,
    JBS_SYSTEMWIDE_CS_REVALIDATE,
    // JBS_SYSTEMWIDE_LOCK_PAGE,
};

// Domain: Platform
// Reachable from all processes that have CS_PLATFORMIZED or are entitled with platform-application or are the Dopamine app itself
#define JBS_DOMAIN_PLATFORM 2
enum {
    JBS_PLATFORM_SET_PROCESS_DEBUGGED = 1,
    JBS_PLATFORM_STAGE_JAILBREAK_UPDATE,
    JBS_PLATFORM_SET_JAILBREAK_VISIBLE,
};


// Domain: Watchdog
// Only reachable from watchdogd
#define JBS_DOMAIN_WATCHDOG 3
enum {
    JBS_WATCHDOG_INTERCEPT_USERSPACE_PANIC = 1,
    JBS_WATCHDOG_GET_LAST_USERSPACE_PANIC
};

// Domain: Root
// Only reachable from root processes
#define JBS_DOMAIN_ROOT 4
enum {
    JBS_ROOT_GET_PHYSRW = 1,
    JBS_ROOT_SIGN_THREAD,
    JBS_ROOT_GET_SYSINFO,
    JBS_ROOT_ADD_CDHASH,
    JBS_ROOT_STEAL_UCRED,
    JBS_ROOT_SET_MAC_LABEL,
};

#define JBS_BOOMERANG_DONE 42

int jbserver_received_xpc_message(struct jbserver_impl *server, xpc_object_t xmsg);

#endif
