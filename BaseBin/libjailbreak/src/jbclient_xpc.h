#ifndef JBCLIENT_XPC_H
#define JBCLIENT_XPC_H

#include <xpc/xpc.h>
#include <xpc_private.h>
#include <stdint.h>

void jbclient_xpc_set_custom_port(mach_port_t serverPort);

xpc_object_t jbserver_xpc_send_dict(xpc_object_t xdict);
xpc_object_t jbserver_xpc_send(uint64_t domain, uint64_t action, xpc_object_t xargs);

char *jbclient_get_jbroot(void);
char *jbclient_get_boot_uuid(void);
int jbclient_trust_binary(const char *binaryPath, xpc_object_t preferredArchsArray);
int jbclient_trust_library(const char *libraryPath, void *addressInCaller);
int jbclient_process_checkin(char **rootPathOut, char **bootUUIDOut, char **sandboxExtensionsOut, bool *fullyDebuggedOut);
int jbclient_fork_fix(uint64_t childPid);
int jbclient_cs_revalidate(void);
int jbclient_jbsettings_get(const char *key, xpc_object_t *valueOut);
bool jbclient_jbsettings_get_bool(const char *key);
uint64_t jbclient_jbsettings_get_uint64(const char *key);
double jbclient_jbsettings_get_double(const char *key);
int jbclient_platform_set_process_debugged(uint64_t pid, bool fullyDebugged);
int jbclient_platform_stage_jailbreak_update(const char *updateTar);
int jbclient_platform_jbsettings_set(const char *key, xpc_object_t value);
int jbclient_platform_jbsettings_set_bool(const char *key, bool boolValue);
int jbclient_platform_jbsettings_set_uint64(const char *key, uint64_t uint64Value);
int jbclient_platform_jbsettings_set_double(const char *key, double doubleValue);
int jbclient_watchdog_intercept_userspace_panic(const char *panicMessage);
int jbclient_watchdog_get_last_userspace_panic(char **panicMessage);
int jbclient_root_get_physrw(bool singlePTE, uint64_t *singlePTEAsidPtr);
int jbclient_root_sign_thread(mach_port_t threadPort);
int jbclient_root_get_sysinfo(xpc_object_t *sysInfoOut);
int jbclient_root_steal_ucred(uint64_t ucredToSteal, uint64_t *orgUcred);
int jbclient_root_set_mac_label(uint64_t slot, uint64_t label, uint64_t *orgLabel);
int jbclient_root_trustcache_info(xpc_object_t *infoOut);
int jbclient_root_trustcache_add_cdhash(uint8_t *cdhashData, size_t cdhashLen);
int jbclient_root_trustcache_clear(void);
int jbclient_boomerang_done(void);

#endif
