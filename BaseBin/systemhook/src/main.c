#include "common.h"

#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <paths.h>
#include <util.h>
#include "sandbox.h"
#include "objc.h"
#include <libjailbreak/jbclient_xpc.h>
#include <libjailbreak/codesign.h>
#include "litehook.h"

#define SYSCALL_CSOPS 0xA9
#define SYSCALL_CSOPS_AUDITTOKEN 0xAA

#define JBRootPath(path) ({ \
	char *outPath = alloca(PATH_MAX); \
	strlcpy(outPath, JB_RootPath, PATH_MAX); \
	strlcat(outPath, path, PATH_MAX); \
	(outPath); \
})

extern char **environ;
bool gTweaksEnabled = false;

int ptrace(int request, pid_t pid, caddr_t addr, int data);
#define PT_ATTACH       10      /* trace some running process */
#define PT_ATTACHEXC    14      /* attach to running process with signal exception */

void* dlopen_from(const char* path, int mode, void* addressInCaller);
void* dlopen_audited(const char* path, int mode);
bool dlopen_preflight(const char* path);

#define DYLD_INTERPOSE(_replacement,_replacee) \
   __attribute__((used)) static struct{ const void* replacement; const void* replacee; } _interpose_##_replacee \
			__attribute__ ((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacement, (const void*)(unsigned long)&_replacee };

static char gExecutablePath[PATH_MAX];
static int loadExecutablePath(void)
{
	char executablePath[PATH_MAX];
	uint32_t bufsize = PATH_MAX;
	if (_NSGetExecutablePath(executablePath, &bufsize) == 0) {
		if (realpath(executablePath, gExecutablePath) != NULL) return 0;
	}
	return -1;
}

static char *JB_SandboxExtensions = NULL;
void applySandboxExtensions(void)
{
	if (JB_SandboxExtensions) {
		char *JB_SandboxExtensions_dup = strdup(JB_SandboxExtensions);
		char *extension = strtok(JB_SandboxExtensions_dup, "|");
		while (extension != NULL) {
			sandbox_extension_consume(extension);
			extension = strtok(NULL, "|");
		}
		free(JB_SandboxExtensions_dup);
	}
}

int posix_spawn_hook(pid_t *restrict pid, const char *restrict path,
					   const posix_spawn_file_actions_t *restrict file_actions,
					   const posix_spawnattr_t *restrict attrp,
					   char *const argv[restrict],
					   char *const envp[restrict])
{
	return spawn_hook_common(pid, path, file_actions, attrp, argv, envp, (void *)posix_spawn, jbclient_trust_binary, jbclient_platform_set_process_debugged);
}

int posix_spawnp_hook(pid_t *restrict pid, const char *restrict file,
					   const posix_spawn_file_actions_t *restrict file_actions,
					   const posix_spawnattr_t *restrict attrp,
					   char *const argv[restrict],
					   char *const envp[restrict])
{
	return resolvePath(file, NULL, ^int(char *path) {
		return spawn_hook_common(pid, path, file_actions, attrp, argv, envp, (void *)posix_spawn, jbclient_trust_binary, jbclient_platform_set_process_debugged);
	});
}


int execve_hook(const char *path, char *const argv[], char *const envp[])
{
	posix_spawnattr_t attr = NULL;
	posix_spawnattr_init(&attr);
	posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC);
	int result = spawn_hook_common(NULL, path, NULL, &attr, argv, envp, (void *)posix_spawn, jbclient_trust_binary, jbclient_platform_set_process_debugged);
	if (attr) {
		posix_spawnattr_destroy(&attr);
	}
	
	if(result != 0) { // posix_spawn will return errno and restore errno if it fails
		errno = result; // so we need to set errno by ourself
		return -1;
	}

	return result;
}

int execle_hook(const char *path, const char *arg0, ... /*, (char *)0, char *const envp[] */)
{
	va_list args;
	va_start(args, arg0);

	// Get argument count
	va_list args_copy;
	va_copy(args_copy, args);
	int arg_count = 1;
	for (char *arg = va_arg(args_copy, char *); arg != NULL; arg = va_arg(args_copy, char *)) {
		arg_count++;
	}
	va_end(args_copy);

	char *argv[arg_count+1];
	argv[0] = (char*)arg0;
	for (int i = 0; i < arg_count-1; i++) {
		char *arg = va_arg(args, char*);
		argv[i+1] = arg;
	}
	argv[arg_count] = NULL;

	char *nullChar = va_arg(args, char*);

	char **envp = va_arg(args, char**);
	return execve_hook(path, argv, envp);
}

int execlp_hook(const char *file, const char *arg0, ... /*, (char *)0 */)
{
	va_list args;
	va_start(args, arg0);

	// Get argument count
	va_list args_copy;
	va_copy(args_copy, args);
	int arg_count = 1;
	for (char *arg = va_arg(args_copy, char*); arg != NULL; arg = va_arg(args_copy, char*)) {
		arg_count++;
	}
	va_end(args_copy);

	char **argv = malloc((arg_count+1) * sizeof(char *));
	argv[0] = (char*)arg0;
	for (int i = 0; i < arg_count-1; i++) {
		char *arg = va_arg(args, char*);
		argv[i+1] = arg;
	}
	argv[arg_count] = NULL;

	int r = resolvePath(file, NULL, ^int(char *path) {
		return execve_hook(path, argv, environ);
	});

	free(argv);

	return r;
}

int execl_hook(const char *path, const char *arg0, ... /*, (char *)0 */)
{
	va_list args;
	va_start(args, arg0);

	// Get argument count
	va_list args_copy;
	va_copy(args_copy, args);
	int arg_count = 1;
	for (char *arg = va_arg(args_copy, char*); arg != NULL; arg = va_arg(args_copy, char*)) {
		arg_count++;
	}
	va_end(args_copy);

	char *argv[arg_count+1];
	argv[0] = (char*)arg0;
	for (int i = 0; i < arg_count-1; i++) {
		char *arg = va_arg(args, char*);
		argv[i+1] = arg;
	}
	argv[arg_count] = NULL;

	return execve_hook(path, argv, environ);
}

int execv_hook(const char *path, char *const argv[])
{
	return execve_hook(path, argv, environ);
}

int execvP_hook(const char *file, const char *search_path, char *const argv[])
{
	__block bool execve_failed = false;
	int err = resolvePath(file, search_path, ^int(char *path) {
		(void)execve_hook(path, argv, environ);
		execve_failed = true;
		return 0;
	});
	if (!execve_failed) {
		errno = err;
	}
	return -1;
}

int execvp_hook(const char *name, char * const *argv)
{
	const char *path;
	/* Get the path we're searching. */
	if ((path = getenv("PATH")) == NULL)
		path = _PATH_DEFPATH;
	return execvP_hook(name, path, argv);
}


void* dlopen_hook(const char* path, int mode)
{
	void* addressInCaller = __builtin_return_address(0);
	if (path && !(mode & RTLD_NOLOAD)) {
		jbclient_trust_library(path, addressInCaller);
	}
    return dlopen_from(path, mode, addressInCaller);
}

void* dlopen_from_hook(const char* path, int mode, void* addressInCaller)
{
	if (path && !(mode & RTLD_NOLOAD)) {
		jbclient_trust_library(path, addressInCaller);
	}
	return dlopen_from(path, mode, addressInCaller);
}

void* dlopen_audited_hook(const char* path, int mode)
{
	void* addressInCaller = __builtin_return_address(0);
	if (path && !(mode & RTLD_NOLOAD)) {
		jbclient_trust_library(path, addressInCaller);
	}
	return dlopen_audited(path, mode);
}

bool dlopen_preflight_hook(const char* path)
{
	void* addressInCaller = __builtin_return_address(0);
	if (path) {
		jbclient_trust_library(path, addressInCaller);
	}
	return dlopen_preflight(path);
}

int sandbox_init_hook(const char *profile, uint64_t flags, char **errorbuf)
{
	int retval = sandbox_init(profile, flags, errorbuf);
	if (retval == 0) {
		applySandboxExtensions();
	}
	return retval;
}

int sandbox_init_with_parameters_hook(const char *profile, uint64_t flags, const char *const parameters[], char **errorbuf)
{
	int retval = sandbox_init_with_parameters(profile, flags, parameters, errorbuf);
	if (retval == 0) {
		applySandboxExtensions();
	}
	return retval;
}

int sandbox_init_with_extensions_hook(const char *profile, uint64_t flags, const char *const extensions[], char **errorbuf)
{
	int retval = sandbox_init_with_extensions(profile, flags, extensions, errorbuf);
	if (retval == 0) {
		applySandboxExtensions();
	}
	return retval;
}

int ptrace_hook(int request, pid_t pid, caddr_t addr, int data)
{
	int retval = ptrace(request, pid, addr, data);

	// ptrace works on any process when the parent is unsandboxed,
	// but when the victim process does not have the get-task-allow entitlement,
	// it will fail to set the debug flags, therefore we patch ptrace to manually apply them
	if (retval == 0 && (request == PT_ATTACHEXC || request == PT_ATTACH)) {
		jbclient_platform_set_process_debugged(pid, true);
		jbclient_platform_set_process_debugged(getpid(), true);
	}

	return retval;
}

void loadForkFix(void)
{
	if (gTweaksEnabled) {
		static dispatch_once_t onceToken;
		dispatch_once (&onceToken, ^{
			// If tweaks have been loaded into this process, we need to load forkfix to ensure forking will work
			// Optimization: If the process cannot fork at all due to sandbox, we don't need to do anything
			if (sandbox_check(getpid(), "process-fork", SANDBOX_CHECK_NO_REPORT, NULL) == 0) {
				dlopen(JBRootPath("/basebin/forkfix.dylib"), RTLD_NOW);
			}
		});
	}
}

pid_t fork_hook(void)
{
	loadForkFix();
	return fork();
}

pid_t vfork_hook(void)
{
	loadForkFix();
	return vfork();
}

pid_t forkpty_hook(int *amaster, char *name, struct termios *termp, struct winsize *winp)
{
	loadForkFix();
	return forkpty(amaster, name, termp, winp);
}

int daemon_hook(int __nochdir, int __noclose)
{
	loadForkFix();
	return daemon(__nochdir, __noclose);
}

// Always set CS_VALID in csflag to avoid causing a crash when hooking a c function on arm64
int csops_hook(pid_t pid, unsigned int ops, void *useraddr, size_t usersize)
{
	int rv = syscall(SYSCALL_CSOPS, pid, ops, useraddr, usersize);
	if (rv != 0) return rv;
	if (ops == CS_OPS_STATUS) {
		if (useraddr && usersize == sizeof(uint32_t)) {
			uint32_t* csflag = (uint32_t *)useraddr;
			*csflag |= CS_VALID;
			*csflag &= ~CS_DEBUGGED;
		}
	}
	return rv;
}

int csops_audittoken_hook(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, audit_token_t *token)
{
	int rv = syscall(SYSCALL_CSOPS_AUDITTOKEN, pid, ops, useraddr, usersize, token);
	if (rv != 0) return rv;
	if (ops == CS_OPS_STATUS) {
		if (useraddr && usersize == sizeof(uint32_t)) {
			uint32_t* csflag = (uint32_t *)useraddr;
			*csflag |= CS_VALID;
			*csflag &= ~CS_DEBUGGED;
		}
	}
	return rv;
}

bool shouldEnableTweaks(void)
{
	if (access(JBRootPath("/basebin/.safe_mode"), F_OK) == 0) {
		return false;
	}

	char *tweaksDisabledEnv = getenv("DISABLE_TWEAKS");
	if (tweaksDisabledEnv) {
		if (!strcmp(tweaksDisabledEnv, "1")) {
			return false;
		}
	}

	const char *tweaksDisabledPathSuffixes[] = {
		// System binaries
		"/usr/libexec/xpcproxy",

		// Dopamine app itself (jailbreak detection bypass tweaks can break it)
		"Dopamine.app/Dopamine",
	};
	for (size_t i = 0; i < sizeof(tweaksDisabledPathSuffixes) / sizeof(const char*); i++)
	{
		if (stringEndsWith(gExecutablePath, tweaksDisabledPathSuffixes[i])) return false;
	}

	return true;
}

__attribute__((constructor)) static void initializer(void)
{
	jbclient_process_checkin(&JB_RootPath, &JB_BootUUID, &JB_SandboxExtensions);

	// Apply sandbox extensions
	applySandboxExtensions();

	// Unset DYLD_INSERT_LIBRARIES, but only if systemhook itself is the only thing contained in it
	const char *dyldInsertLibraries = getenv("DYLD_INSERT_LIBRARIES");
	if (dyldInsertLibraries) {
		if (!strcmp(dyldInsertLibraries, HOOK_DYLIB_PATH)) {
			unsetenv("DYLD_INSERT_LIBRARIES");
		}
	}

	if (loadExecutablePath() == 0) {
		if (strcmp(gExecutablePath, "/usr/sbin/cfprefsd") == 0) {
			dlopen_hook(JBRootPath("/basebin/rootlesshooks.dylib"), RTLD_NOW);
		}
		else if (strcmp(gExecutablePath, "/usr/libexec/watchdogd") == 0) {
			dlopen_hook(JBRootPath("/basebin/watchdoghook.dylib"), RTLD_NOW);
		}

#ifndef __arm64e__
		litehook_hook_function(csops, csops_hook);
		litehook_hook_function(csops_audittoken, csops_audittoken_hook);
#endif

		if (shouldEnableTweaks()) {
			const char *tweakLoaderPath = "/var/jb/usr/lib/TweakLoader.dylib";
			if(access(tweakLoaderPath, F_OK) == 0) {
				gTweaksEnabled = true;
				void *tweakLoaderHandle = dlopen_hook(tweakLoaderPath, RTLD_NOW);
				if (tweakLoaderHandle != NULL) {
					dlclose(tweakLoaderHandle);
					dopamine_fix_NSTask();
				}
			}
		}

#ifndef __arm64e__
		// Feeable attempt at adding back CS_VALID
		// If any hooks are applied after this, it is lost again
		// Temporary workaround until a better solution for this problem is found
		// This + the csops hook should resolve all cases unless a tweak does something really stupid
		jbclient_cs_revalidate();
#endif
	}
}

DYLD_INTERPOSE(posix_spawn_hook, posix_spawn)
DYLD_INTERPOSE(posix_spawnp_hook, posix_spawnp)
DYLD_INTERPOSE(execve_hook, execve)
DYLD_INTERPOSE(execle_hook, execle)
DYLD_INTERPOSE(execlp_hook, execlp)
DYLD_INTERPOSE(execv_hook, execv)
DYLD_INTERPOSE(execl_hook, execl)
DYLD_INTERPOSE(execvp_hook, execvp)
DYLD_INTERPOSE(execvP_hook, execvP)
DYLD_INTERPOSE(dlopen_hook, dlopen)
DYLD_INTERPOSE(dlopen_from_hook, dlopen_from)
DYLD_INTERPOSE(dlopen_audited_hook, dlopen_audited)
DYLD_INTERPOSE(dlopen_preflight_hook, dlopen_preflight)
DYLD_INTERPOSE(sandbox_init_hook, sandbox_init)
DYLD_INTERPOSE(sandbox_init_with_parameters_hook, sandbox_init_with_parameters)
DYLD_INTERPOSE(sandbox_init_with_extensions_hook, sandbox_init_with_extensions)
DYLD_INTERPOSE(ptrace_hook, ptrace)
#ifdef __arm64e__
DYLD_INTERPOSE(fork_hook, fork)
DYLD_INTERPOSE(vfork_hook, vfork)
DYLD_INTERPOSE(forkpty_hook, forkpty)
DYLD_INTERPOSE(daemon_hook, daemon)
#endif
