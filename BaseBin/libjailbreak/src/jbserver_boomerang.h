#ifndef JBSERVER_BOOMERANG_H
#define JBSERVER_BOOMERANG_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include <xpc/xpc.h>
#include <bsm/audit.h>

#include "jbserver.h"

int boomerang_get_physrw(audit_token_t *clientToken, bool singlePTE, uint64_t *singlePTEAsidPtr);
int boomerang_sign_thread(audit_token_t *clientToken, mach_port_t threadPort);
int boomerang_get_sysinfo(xpc_object_t *sysInfoOut);

extern struct jbserver_impl gBoomerangServer;
int jbserver_received_boomerang_xpc_message(struct jbserver_impl *server, xpc_object_t xmsg);

#endif