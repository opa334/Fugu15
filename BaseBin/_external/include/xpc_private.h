#ifndef __XPC_PRIVATE_H__
#define __XPC_PRIVATE_H__

void xpc_dictionary_get_audit_token(xpc_object_t xdict, audit_token_t *token);
char *xpc_strerror (int);

extern XPC_RETURNS_RETAINED xpc_object_t xpc_pipe_create_from_port(mach_port_t port, uint32_t flags);
extern int xpc_pipe_simpleroutine(xpc_object_t pipe, xpc_object_t message);
extern int xpc_pipe_routine(xpc_object_t pipe, xpc_object_t message, XPC_GIVES_REFERENCE xpc_object_t *reply);
extern int xpc_pipe_routine_with_flags(xpc_object_t xpc_pipe, xpc_object_t inDict, XPC_GIVES_REFERENCE xpc_object_t *reply, uint32_t flags);
extern int xpc_pipe_routine_reply(xpc_object_t reply);
extern int xpc_pipe_receive(mach_port_t port, XPC_GIVES_REFERENCE xpc_object_t *message);

extern XPC_RETURNS_RETAINED xpc_object_t xpc_copy_entitlement_for_token(const char *, audit_token_t *);

#endif