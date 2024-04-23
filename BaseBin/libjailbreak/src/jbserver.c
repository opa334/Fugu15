#include "jbserver.h"

int jbserver_received_xpc_message(struct jbserver_impl *server, xpc_object_t xmsg)
{
	if (xpc_get_type(xmsg) != XPC_TYPE_DICTIONARY) return -1;

	if (!xpc_dictionary_get_value(xmsg, "jb-domain")) return -1;
	if (!xpc_dictionary_get_value(xmsg, "action")) return -1;

	uint64_t domainIdx = xpc_dictionary_get_uint64(xmsg, "jb-domain");
	if (domainIdx == 0) return -1;
	struct jbserver_domain *domain = server->domains[0];
	for (int i = 1; i < domainIdx && domain; i++) {
		domain = server->domains[i];
	}
	if (!domain) return -1;

	audit_token_t clientToken = { 0 };
	xpc_dictionary_get_audit_token(xmsg, &clientToken);

	if (domain->permissionHandler) {
		if (!domain->permissionHandler(clientToken)) return -2;
	}

	uint64_t actionIdx = xpc_dictionary_get_uint64(xmsg, "action");
	if (actionIdx == 0) return -1;
	struct jbserver_action *action = &domain->actions[0];
	for (int i = 1; i < actionIdx && action->handler; i++) {
		action = &domain->actions[i];
	}
	if (!action->handler) return -1;

	int (*handler)(void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8) = action->handler;
	void *args[8] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
	void *argsOut[8] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };

	for (uint64_t i = 0; action->args[i].name && i < 8; i++) {
		jbserver_arg *argDesc = &action->args[i];
		if (!argDesc->out) {
			switch (argDesc->type) {
				case JBS_TYPE_BOOL:
				args[i] = (void *)xpc_dictionary_get_bool(xmsg, argDesc->name);
				break;
				case JBS_TYPE_UINT64:
				args[i] = (void *)xpc_dictionary_get_uint64(xmsg, argDesc->name);
				break;
				case JBS_TYPE_STRING:
				args[i] = (void *)xpc_dictionary_get_string(xmsg, argDesc->name);
				break;
				case JBS_TYPE_DATA: { // Data occupies 2 arguments (buf, len)
					if (i < 7) {
						args[i] = (void *)xpc_dictionary_get_data(xmsg, argDesc->name, (size_t *)&args[i+1]); i++;
					}
					break;
				}
				case JBS_TYPE_ARRAY:
				args[i] = (void *)xpc_dictionary_get_array(xmsg, argDesc->name);
				break;
				case JBS_TYPE_DICTIONARY:
				args[i] = (void *)xpc_dictionary_get_dictionary(xmsg, argDesc->name);
				break;
				case JBS_TYPE_CALLER_TOKEN:
				args[i] = (void *)&clientToken;
				break;
			}
		}
		else {
			args[i] = &argsOut[i];
		}
	}

	int result = handler(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);

	xpc_object_t xreply = xpc_dictionary_create_reply(xmsg);
	for (uint64_t i = 0; action->args[i].name && i < 8; i++) {
		jbserver_arg *argDesc = &action->args[i];
		if (argDesc->out) {
			switch (argDesc->type) {
				case JBS_TYPE_BOOL:
				xpc_dictionary_set_bool(xreply, argDesc->name, (bool)argsOut[i]);
				break;
				case JBS_TYPE_UINT64:
				xpc_dictionary_set_uint64(xreply, argDesc->name, (uint64_t)argsOut[i]);
				break;
				case JBS_TYPE_STRING: {
					if (argsOut[i]) {
						xpc_dictionary_set_string(xreply, argDesc->name, (char *)argsOut[i]);
						free(argsOut[i]);
					}
					break;
				}
				case JBS_TYPE_DATA: {
					if (i < 7) {
						if (argsOut[i] && action->args[i+1].name) {
							xpc_dictionary_set_data(xreply, argDesc->name, (const void *)argsOut[i], (size_t)argsOut[i+1]);
							free(argsOut[i]);
						}
					}
					break;
				}
				case JBS_TYPE_ARRAY:
				case JBS_TYPE_DICTIONARY: {
					if (argsOut[i]) {
						xpc_dictionary_set_value(xreply, argDesc->name, (xpc_object_t)argsOut[i]);
						xpc_release((xpc_object_t)argsOut[i]);
					}
					break;
				}
				default:
				break;
			}
		}
	}
	xpc_dictionary_set_int64(xreply, "result", result);
	xpc_pipe_routine_reply(xreply);
	xpc_release(xreply);
	return 0;
}