#ifndef SYSTEMHOOK_PRIVATE
#define SYSTEMHOOK_PRIVATE

#define SYS_ptrace 0x1A
#define SYS_execve 0x3B
#define SYS_posix_spawn 0xF4
#define SYS_csops 0xA9
#define SYS_csops_audittoken 0xAA
#define SYS_necp_match_policy 0x1CC
#define SYS_necp_open 0x1F5
#define SYS_necp_client_action 0x1F6
#define SYS_necp_session_open 0x20A
#define SYS_necp_session_action 0x20B

int necp_match_policy(uint8_t *parameters, size_t parameters_size, void *returned_result);
int necp_open(int flags);
int necp_client_action(int necp_fd, uint32_t action, uuid_t client_id, size_t client_id_len, uint8_t *buffer, size_t buffer_size);
int necp_session_open(int flags);
int necp_session_action(int necp_fd, uint32_t action, uint8_t *in_buffer, size_t in_buffer_length, uint8_t *out_buffer, size_t out_buffer_length);

int ptrace(int request, pid_t pid, caddr_t addr, int data);
#define PT_ATTACH       10      /* trace some running process */
#define PT_ATTACHEXC    14      /* attach to running process with signal exception */

#define POSIX_SPAWN_PROC_TYPE_DRIVER 0x700
int posix_spawnattr_getprocesstype_np(const posix_spawnattr_t * __restrict, int * __restrict) __API_AVAILABLE(macos(10.8), ios(6.0));

#define POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE 0x48
#define POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE 0x4C
#define POSIX_SPAWNATTR_OFF_LAUNCH_TYPE 0xA8

extern char **environ;

struct _posix_spawn_args_desc {
	size_t attr_size;
	posix_spawnattr_t attrp;
	
	size_t file_actions_size;
	void *file_actions;

	size_t port_actions_size;
	void *port_actions;

	size_t mac_extensions_size;
	void *mac_extensions;

	size_t coal_info_size;
	struct _posix_spawn_coalition_info *coal_info;

	size_t persona_info_size;
	void *persona_info;

	size_t posix_cred_info_size;
	void *posix_cred_info;

	size_t subsystem_root_path_size;
	char *subsystem_root_path;

	size_t conclave_id_size;
	char *conclave_id;
};

#endif