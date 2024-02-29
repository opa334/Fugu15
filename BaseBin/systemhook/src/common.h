#include <CoreFoundation/CoreFoundation.h>
#include <spawn.h>
#include <xpc/xpc.h>

#define HOOK_DYLIB_PATH "/usr/lib/systemhook.dylib"
extern char *JB_BootUUID;
extern char *JB_RootPath;

bool stringStartsWith(const char *str, const char* prefix);
bool stringEndsWith(const char* str, const char* suffix);

int resolvePath(const char *file, const char *searchPath, int (^attemptHandler)(char *path));
int spawn_hook_common(pid_t *restrict pid, const char *restrict path,
					   const posix_spawn_file_actions_t *restrict file_actions,
					   const posix_spawnattr_t *restrict attrp,
					   char *const argv[restrict],
					   char *const envp[restrict],
					   void *orig,
					   int (*trust_binary)(const char *),
					   int (*set_process_debugged)(uint64_t pid, bool fullyDebugged));