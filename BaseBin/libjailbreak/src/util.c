#include "util.h"
#include "primitives.h"
#include "info.h"
#include "kernel.h"
#include "translation.h"
#include <spawn.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <signal.h>
#include <sys/sysctl.h>
#include <archive.h>
#include <archive_entry.h>
#include <math.h>
extern char **environ;

#define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1
extern int posix_spawnattr_set_persona_np(const posix_spawnattr_t* __restrict, uid_t, uint32_t);
extern int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t* __restrict, uid_t);
extern int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t* __restrict, uid_t);

void proc_iterate(void (^itBlock)(uint64_t, bool*))
{
	uint64_t proc = ksymbol(allproc);
	while((proc = kread_ptr(proc + koffsetof(proc, list_next))))
	{
		bool stop = false;
		itBlock(proc, &stop);
		if(stop) return;
	}
}

uint64_t proc_self(void)
{
	static uint64_t gSelfProc = 0;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		gSelfProc = proc_find(getpid());
		// decrement ref count again, we assume proc_self will exist for the whole lifetime of this process
		proc_rele(gSelfProc);
	});
	return gSelfProc;
}

uint64_t task_self(void)
{
	static uint64_t gSelfTask = 0;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		gSelfTask = proc_task(proc_self());
	});
	return gSelfTask;
}

uint64_t vm_map_self(void)
{
	static uint64_t gSelfMap = 0;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		gSelfMap = kread_ptr(task_self() + koffsetof(task, map));
	});
	return gSelfMap;
}

uint64_t pmap_self(void)
{
	static uint64_t gSelfPmap = 0;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		gSelfPmap = kread_ptr(vm_map_self() + koffsetof(vm_map, pmap));
	});
	return gSelfPmap;
}

uint64_t task_get_ipc_port_table_entry(uint64_t task, mach_port_t port)
{
	uint64_t itk_space = kread_ptr(task + koffsetof(task, itk_space));
	return ipc_entry_lookup(itk_space, port);
}

uint64_t task_get_ipc_port_object(uint64_t task, mach_port_t port)
{
	return kread_ptr(task_get_ipc_port_table_entry(task, port) + koffsetof(ipc_entry, object));
}

uint64_t task_get_ipc_port_kobject(uint64_t task, mach_port_t port)
{
	return kread_ptr(task_get_ipc_port_object(task, port) + koffsetof(ipc_port, kobject));
}

uint64_t alloc_page_table_unassigned(void)
{
	thread_caffeinate_start();

	uint64_t pmap = pmap_self();
	uint64_t ttep = kread64(pmap + koffsetof(pmap, ttep));

	void *free_lvl2 = NULL;
	uint64_t tte_lvl2 = 0;
	uint64_t allocatedPT = 0;
	uint64_t pinfo_pa = 0;
	while (true) {
		// When we allocate the entire address range of an L2 block, we can assume ownership of the backing table
		if (posix_memalign(&free_lvl2, L2_BLOCK_SIZE, L2_BLOCK_SIZE) != 0) {
			printf("WARNING: Failed to allocate L2 page table address range\n");
			return 0;
		}
		// Now, fault in one page to make the kernel allocate the page table for it
		*(volatile uint64_t *)free_lvl2;

		// Find the newly allocated page table
		uint64_t lvl = PMAP_TT_L2_LEVEL;
		allocatedPT = vtophys_lvl(ttep, (uint64_t)free_lvl2, &lvl, &tte_lvl2);

		uint64_t pvh = pai_to_pvh(pa_index(allocatedPT));
		uint64_t ptdp = pvh_ptd(pvh);
		uint64_t pinfo = kread64(ptdp + koffsetof(pt_desc, ptd_info)); // TODO: Fake 16k devices (4 values)
		pinfo_pa = kvtophys(pinfo);

		uint16_t refCount = physread16(pinfo_pa);
		if (refCount != 1) {
			// Something is off, retry
			free(free_lvl2);
			continue;
		}

		break;
	}

	// Handle case where all entries in the level 2 table are 0 after we leak ours
	// In that case, leak an allocation in the span of it to keep it alive
	/*uint64_t lvl2Table = tte_lvl2 & ~PAGE_MASK;
	uint64_t lvl2TableEntries[PAGE_SIZE / sizeof(uint64_t)];
	physreadbuf(lvl2Table, lvl2TableEntries, PAGE_SIZE);
	int freeIdx = -1;
	for (int i = 0; i < (PAGE_SIZE / sizeof(uint64_t)); i++) {
		uint64_t curPtr = lvl2Table + (sizeof(uint64_t) * i);
		if (curPtr != tte_lvl2) {
			if (lvl2TableEntries[i]) {
				freeIdx = -1;
				break;
			}
			else {
				freeIdx = i;
			}
		}
	}
	if (freeIdx != -1) {
		vm_address_t freeUserspace = ((uint64_t)free_lvl2 & ~L1_BLOCK_MASK) + (freeIdx * L2_BLOCK_SIZE);
		if (vm_allocate(mach_task_self(), &freeUserspace, 0x4000, VM_FLAGS_FIXED) == 0) {
			*(volatile uint8_t *)freeUserspace;
		}
	}*/

	// Bump reference count of our allocated page table
	physwrite16(pinfo_pa, 0x1337);

	// Deallocate address range (our allocated page table will stay because we bumped it's reference count)
	free(free_lvl2);

	// Remove our allocated page table from it's original location (leak it)
	physwrite64(tte_lvl2, 0);

	// Ensure there is at least one entry in page table
	// Attempts to prevent "pte is empty" panic
	// Sometimes weird prefetches happen so this has to be a valid physical page to ensure those don't panic
	// Disabled for now cause it causes super weird issues
	//physwrite64(allocatedPT, kconstant(physBase) | PERM_TO_PTE(PERM_KRW_URW) | PTE_NON_GLOBAL | PTE_OUTER_SHAREABLE | PTE_LEVEL3_ENTRY);

	// Reference count of new page table must be 0!
	// original ref count is 1 because the table holds one PTE
	// Our new PTEs are not part of the pmap layer though so refcount needs to be 0
	physwrite16(pinfo_pa, 0);

	// After we leaked the page table, the ledger still thinks it belongs to our process
	// We need to remove it from there aswell so that the process doesn't get jetsam killed
	// (This ended up more complicated than I thought, so I just disabled jetsam in launchd)
	//uint64_t ledger = kread_ptr(pmap + koffsetof(pmap, ledger));
	//uint64_t ledger_pa = kvtophys(ledger);
	//int page_table_ledger = physread32(ledger_pa + koffsetof(_task_ledger_indices, page_table));
	//physwrite32(ledger_pa + koffsetof(_task_ledger_indices, page_table), page_table_ledger - 1);

	thread_caffeinate_stop();

	return allocatedPT;
}

uint64_t pmap_alloc_page_table(uint64_t pmap, uint64_t va)
{
	if (!pmap) {
		pmap = pmap_self();
	}

	uint64_t tt_p = alloc_page_table_unassigned();
	if (!tt_p) return 0;

	uint64_t pvh = pai_to_pvh(pa_index(tt_p));
	uint64_t ptdp = pvh_ptd(pvh);

	uint64_t ptdp_pa = kvtophys(ptdp);

	// At this point the allocated page table is associated
	// to the pmap of this process alongside the address it was allocated on
	// We now need to replace the association with the context in which it will be used
	physwrite64(ptdp_pa + koffsetof(pt_desc, pmap), pmap);

	// On A14+ PT_INDEX_MAX is 4, for whatever reason
	// However in practice, only the first slot is used...
	// TODO: On devices where kernel page size != userland page size, populate all 4 values
	physwrite64(ptdp_pa + koffsetof(pt_desc, va), va);

	return tt_p;
}

int pmap_map_in(uint64_t pmap, uint64_t uaStart, uint64_t paStart, uint64_t size)
{
	thread_caffeinate_start();

	uint64_t uaEnd = uaStart + size;
	uint64_t ttep = kread64(pmap + koffsetof(pmap, ttep));

	// Sanity check: Ensure the entire area to be mapped in is not mapped to anything yet
	for(uint64_t ua = uaStart; ua < uaEnd; ua += PAGE_SIZE) {
		if (vtophys(ttep, ua)) { thread_caffeinate_stop(); return -1; }
		// TODO: If all mappings match 1:1, maybe return 0 instead of -1?
	}

	// Allocate all page tables that need to be allocated
	for(uint64_t ua = uaStart; ua < uaEnd; ua += PAGE_SIZE) {
		uint64_t leafLevel;
		do {
			leafLevel = PMAP_TT_L3_LEVEL;
			uint64_t pt = 0;
			vtophys_lvl(ttep, ua, &leafLevel, &pt);
			if (leafLevel != PMAP_TT_L3_LEVEL) {
				uint64_t pt_va = 0;
				switch (leafLevel) {
					case PMAP_TT_L1_LEVEL: {
						pt_va = ua & ~L1_BLOCK_MASK;
						break;
					}
					case PMAP_TT_L2_LEVEL: {
						pt_va = ua & ~L2_BLOCK_MASK;
						break;
					}
				}
				uint64_t newTable = pmap_alloc_page_table(pmap, pt_va);
				if (newTable) {
					physwrite64(pt, newTable | ARM_TTE_VALID | ARM_TTE_TYPE_TABLE);
				}
				else { thread_caffeinate_stop(); return -2; }
			}
		} while (leafLevel < PMAP_TT_L3_LEVEL);
	}

	// Insert entries into L3 pages
	for(uint64_t ua = uaStart; ua < uaEnd; ua += PAGE_SIZE) {
		uint64_t pa = (ua - uaStart) + paStart;
		uint64_t leafLevel = PMAP_TT_L3_LEVEL;
		uint64_t pt = 0;

		vtophys_lvl(ttep, ua, &leafLevel, &pt);
		physwrite64(pt, pa | PERM_TO_PTE(PERM_KRW_URW) | PTE_NON_GLOBAL | PTE_OUTER_SHAREABLE | PTE_LEVEL3_ENTRY);
	}

	thread_caffeinate_stop();
	return 0;
}

int sign_kernel_thread(uint64_t proc, mach_port_t threadPort)
{
	uint64_t threadKobj = task_get_ipc_port_kobject(proc_task(proc), threadPort);
	uint64_t threadContext = kread_ptr(threadKobj + koffsetof(thread, machine_contextData));

	uint64_t pc   = kread64(threadContext + offsetof(kRegisterState, pc));
	uint64_t cpsr = kread64(threadContext + offsetof(kRegisterState, cpsr));
	uint64_t lr   = kread64(threadContext + offsetof(kRegisterState, lr));
	uint64_t x16  = kread64(threadContext + offsetof(kRegisterState, x[16]));
	uint64_t x17  = kread64(threadContext + offsetof(kRegisterState, x[17]));

	return kcall(NULL, ksymbol(ml_sign_thread_state), 6, (uint64_t[]){ threadContext, pc, cpsr, lr, x16, x17 });
}

uint64_t kpacda(uint64_t pointer, uint64_t modifier)
{
	if (gPrimitives.kexec && kgadget(pacda)) {
		// |------- GADGET -------|
		// | cmp x1, #0		      |
		// | pacda x1, x9         |
		// | str x9, [x8]         |
		// | csel x9, xzr, x1, eq |
		// | ret                  |
		// |----------------------|
		uint64_t output = 0;
		uint64_t output_kernelVA = phystokv(vtophys(kread_ptr(pmap_self() + koffsetof(pmap, ttep)), (uint64_t)&output));
		kRegisterState threadState = { 0 };
		threadState.pc = kgadget(pacda);
		threadState.x[1] = pointer;
		threadState.x[9] = modifier;
		threadState.x[8] = output_kernelVA;
		kexec(&threadState);
		return output;
	}
	return 0;
}

uint64_t kptr_sign(uint64_t kaddr, uint64_t pointer, uint16_t salt)
{
	uint64_t modifier = (kaddr & 0xffffffffffff) | ((uint64_t)salt << 48);
	return kpacda(UNSIGN_PTR(pointer), modifier);
}

int kwrite1_bits(uint64_t startPtr, uint32_t bitCount)
{
	uint32_t byteSize = ceil((float)bitCount / 8);
	uint8_t buf[byteSize];

	for (uint32_t i = 0; i < bitCount; i += 8) {
		uint32_t rem = (bitCount - i);
		if (rem < 8) {
			for (int y = 0; y < rem; y++) {
				buf[i/8] |= (1 << y);
			}
		}
		else {
			buf[i/8] = 0xff;
		}
	}

	return kwritebuf(startPtr, buf, byteSize);
}

void proc_allow_all_syscalls(uint64_t proc)
{
	if (!gSystemInfo.kernelStruct.proc_ro.exists) return;
	uint64_t proc_ro = kread_ptr(proc + koffsetof(proc, proc_ro));

	uint64_t bsdFilter = kread_ptr(proc_ro + koffsetof(proc_ro, syscall_filter_mask));
	uint64_t machFilter = kread_ptr(proc_ro + koffsetof(proc_ro, mach_trap_filter_mask));
	uint64_t machKobjFilter = kread_ptr(proc_ro + koffsetof(proc_ro, mach_kobj_filter_mask));

	if (bsdFilter) {
		kwrite1_bits(bsdFilter, kconstant(nsysent));
	}
	if (machFilter) {
		kwrite1_bits(machFilter, kconstant(mach_trap_count));
	}
	if (machKobjFilter) {
		kwrite1_bits(machKobjFilter, kread64(ksymbol(mach_kobj_count)));
	}
}

int cmd_wait_for_exit(pid_t pid)
{
	int status = 0;
	do {
		if (waitpid(pid, &status, 0) == -1) {
			return -1;
		}
	} while (!WIFEXITED(status) && !WIFSIGNALED(status));
	return status;
}

int __exec_cmd_internal_va(bool suspended, bool root, pid_t *pidOut, const char *binary, int argc, va_list va_args)
{
	const char *argv[argc+1];
	argv[0] = binary;
	for (int i = 1; i < argc; i++) {
		argv[i] = va_arg(va_args, const char *);
	}
	argv[argc] = NULL;

	posix_spawnattr_t attr = NULL;
	posix_spawnattr_init(&attr);
	if (suspended) {
		posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
	}
	if (root) {
		posix_spawnattr_set_persona_np(&attr, 99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
		posix_spawnattr_set_persona_uid_np(&attr, 0);
		posix_spawnattr_set_persona_gid_np(&attr, 0);
	}

	pid_t spawnedPid = 0;
	int spawnError = posix_spawn(&spawnedPid, binary, NULL, &attr, (char *const *)argv, environ);
	if (attr) posix_spawnattr_destroy(&attr);
	if (spawnError != 0) return spawnError;

	if (!suspended) {
		return cmd_wait_for_exit(spawnedPid);
	}
	else if (pidOut) {
		*pidOut = spawnedPid;
	}
	return 0;
}

int exec_cmd(const char *binary, ...)
{
	int argc = 1;
	va_list args;
	va_start(args, binary);
	while (va_arg(args, const char *)) argc++;
	va_end(args);

	va_start(args, binary);
	int r = __exec_cmd_internal_va(false, false, NULL, binary, argc, args);
	va_end(args);
	return r;
}

int exec_cmd_suspended(pid_t *pidOut, const char *binary, ...)
{
	int argc = 1;
	va_list args;
	va_start(args, binary);
	while (va_arg(args, const char *)) argc++;
	va_end(args);

	va_start(args, binary);
	int r = __exec_cmd_internal_va(true, false, pidOut, binary, argc, args);
	va_end(args);
	return r;
}

int exec_cmd_root(const char *binary, ...)
{
	int argc = 1;
	va_list args;
	va_start(args, binary);
	while (va_arg(args, const char *)) argc++;
	va_end(args);

	va_start(args, binary);
	int r = __exec_cmd_internal_va(false, true, NULL, binary, argc, args);
	va_end(args);
	return r;
}

void killall(const char *executablePathToKill, bool softly)
{
	static int maxArgumentSize = 0;
	if (maxArgumentSize == 0) {
		size_t size = sizeof(maxArgumentSize);
		if (sysctl((int[]){ CTL_KERN, KERN_ARGMAX }, 2, &maxArgumentSize, &size, NULL, 0) == -1) {
			perror("sysctl argument size");
			maxArgumentSize = 4096; // Default
		}
	}
	int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL};
	struct kinfo_proc *info;
	size_t length;
	int count;
	
	if (sysctl(mib, 3, NULL, &length, NULL, 0) < 0)
		return;
	if (!(info = malloc(length)))
		return;
	if (sysctl(mib, 3, info, &length, NULL, 0) < 0) {
		free(info);
		return;
	}
	count = length / sizeof(struct kinfo_proc);
	for (int i = 0; i < count; i++) {
		pid_t pid = info[i].kp_proc.p_pid;
		if (pid == 0) {
			continue;
		}
		size_t size = maxArgumentSize;
		char* buffer = (char *)malloc(length);
		if (sysctl((int[]){ CTL_KERN, KERN_PROCARGS2, pid }, 3, buffer, &size, NULL, 0) == 0) {
			char *executablePath = buffer + sizeof(int);
			if (strcmp(executablePath, executablePathToKill) == 0) {
				if(softly)
				{
					kill(pid, SIGTERM);
				}
				else
				{
					kill(pid, SIGKILL);
				}
			}
		}
		free(buffer);
	}
	free(info);
}

static int
copy_data(struct archive *ar, struct archive *aw)
{
	int r;
	const void *buff;
	size_t size;
	la_int64_t offset;

	for (;;) {
		r = archive_read_data_block(ar, &buff, &size, &offset);
		if (r == ARCHIVE_EOF)
			return (ARCHIVE_OK);
		if (r < ARCHIVE_OK)
			return (r);
		r = archive_write_data_block(aw, buff, size, offset);
		if (r < ARCHIVE_OK) {
			fprintf(stderr, "%s\n", archive_error_string(aw));
			return (r);
		}
	}
}

int libarchive_unarchive(const char *fileToExtract, const char *extractionPath)
{
	struct archive *a;
	struct archive *ext;
	struct archive_entry *entry;
	int flags;
	int r;

	/* Select which attributes we want to restore. */
	flags = ARCHIVE_EXTRACT_TIME;
	flags |= ARCHIVE_EXTRACT_PERM;
	flags |= ARCHIVE_EXTRACT_ACL;
	flags |= ARCHIVE_EXTRACT_FFLAGS;
	flags |= ARCHIVE_EXTRACT_OWNER;

	a = archive_read_new();
	archive_read_support_format_all(a);
	archive_read_support_filter_all(a);
	ext = archive_write_disk_new();
	archive_write_disk_set_options(ext, flags);
	archive_write_disk_set_standard_lookup(ext);
	if ((r = archive_read_open_filename(a, fileToExtract, 10240)))
			return 1;
	for (;;) {
			r = archive_read_next_header(a, &entry);
			if (r == ARCHIVE_EOF)
					break;
			if (r < ARCHIVE_OK)
					fprintf(stderr, "%s\n", archive_error_string(a));
			if (r < ARCHIVE_WARN)
					return 1;

			const char *currentFile = archive_entry_pathname(entry);
			char outputPath[PATH_MAX];
			strlcpy(outputPath, extractionPath, PATH_MAX);
			strlcat(outputPath, "/", PATH_MAX);
			strlcat(outputPath, currentFile, PATH_MAX);

			archive_entry_set_pathname(entry, outputPath);
			
			r = archive_write_header(ext, entry);
			if (r < ARCHIVE_OK)
					fprintf(stderr, "%s\n", archive_error_string(ext));
			else if (archive_entry_size(entry) > 0) {
					r = copy_data(a, ext);
					if (r < ARCHIVE_OK)
							fprintf(stderr, "%s\n", archive_error_string(ext));
					if (r < ARCHIVE_WARN)
							return 1;
			}
			r = archive_write_finish_entry(ext);
			if (r < ARCHIVE_OK)
					fprintf(stderr, "%s\n", archive_error_string(ext));
			if (r < ARCHIVE_WARN)
					return 1;
	}
	archive_read_close(a);
	archive_read_free(a);
	archive_write_close(ext);
	archive_write_free(ext);
	
	return 0;
}


// code from ktrw by Brandon Azad : https://github.com/googleprojectzero/ktrw
// A worker thread for activity_thread that just spins.
static void* worker_thread(void *arg)
{
	uint64_t end = *(uint64_t *)arg;
	for (;;) {
		close(-1);
		uint64_t now = mach_absolute_time();
		if (now >= end) {
			break;
		}
	}
	return NULL;
}

// A thread to alternately spin and sleep.
static void* activity_thread(void *arg)
{
	volatile uint64_t *runCount = arg;
	struct mach_timebase_info tb;
	mach_timebase_info(&tb);
	const unsigned milliseconds = 40;
	const unsigned worker_count = 10;
	while (*runCount != 0) {
		// Spin for one period on multiple threads.
		uint64_t start = mach_absolute_time();
		uint64_t end = start + milliseconds * 1000 * 1000 * tb.denom / tb.numer;
		pthread_t worker[worker_count];
		for (unsigned i = 0; i < worker_count; i++) {
			pthread_create(&worker[i], NULL, worker_thread, &end);
		}
		worker_thread(&end);
		for (unsigned i = 0; i < worker_count; i++) {
			pthread_join(worker[i], NULL);
		}
		// Sleep for one period.
		usleep(milliseconds * 1000);
	}
	return NULL;
}

static uint64_t gCaffeinateThreadRunCount = 0;
static pthread_t gCaffeinateThread = NULL;

void thread_caffeinate_start(void)
{
	if (gCaffeinateThreadRunCount == UINT64_MAX) return;
	gCaffeinateThreadRunCount++;
	if (gCaffeinateThreadRunCount == 1) {
		pthread_create(&gCaffeinateThread, NULL, activity_thread, &gCaffeinateThreadRunCount);
	}
}

void thread_caffeinate_stop(void)
{
	if (gCaffeinateThreadRunCount == 0) return;
	gCaffeinateThreadRunCount--;
	if (gCaffeinateThreadRunCount == 0) {
		pthread_join(gCaffeinateThread, NULL);
	}
}