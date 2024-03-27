#include <sys/sysctl.h>
#include <string.h>
#include <unistd.h>
#include <kern_memorystatus.h>
#include <substrate.h>

// Allocated page tables (done by physrw handoff) count towards the physical memory footprint of the process that created them
// Unfortunately that means jetsam kills us if we do it too often
// For launchd, we therefore prevent it from enabling jetsam using this hook

int (*memorystatus_control_orig)(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);
int memorystatus_control_hook(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize)
{
	if (command == MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT) {
		return 0;
	}
	return memorystatus_control_orig(command, pid, flags, buffer, buffersize);
}

void initJetsamHook(void)
{
	MSHookFunction((void *)memorystatus_control, (void *)memorystatus_control_hook, (void **)&memorystatus_control_orig);
}