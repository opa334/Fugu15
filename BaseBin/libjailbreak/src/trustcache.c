#include "trustcache.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "kernel.h"
#include "info.h"
#include "primitives.h"

void _trustcache_file_init(trustcache_file_v1 *file)
{
	memset(file, 0, sizeof(*file));
	file->version = 1;
	uuid_generate(file->uuid);
}

// iOS 16:
// ppl_trust_cache_rt has trustcache runtime
// **(ppl_trust_cache_rt+0x20) seems to have the loaded trustcache linked list
// trustcache struct changed, "next" is still at +0x0, but "this" is at +0x20

uint64_t _trustcache_list_get_start(void)
{
	if (ksymbol(pmap_image4_trust_caches)) { // iOS <=15
		return kread64(ksymbol(pmap_image4_trust_caches));
	}
	else if (ksymbol(ppl_trust_cache_rt)) {  // iOS >=16
		return kread64(kread64(ksymbol(ppl_trust_cache_rt) + 0x20));
	}

	return 0;
}

void _trustcache_list_set_start(uint64_t newStart)
{
	if (ksymbol(pmap_image4_trust_caches)) { // iOS <=15
		kwrite64(ksymbol(pmap_image4_trust_caches), newStart);
	}
	else if (ksymbol(ppl_trust_cache_rt)) {  // iOS >=16
		kwrite64(kread64(ksymbol(ppl_trust_cache_rt) + 0x20), newStart);
	}
}

void _trustcache_list_enumerate(void (^enumerateBlock)(uint64_t tcKaddr, bool *stop))
{
	uint64_t curTC = _trustcache_list_get_start();
	while(curTC != 0) {
		bool stop = false;
		enumerateBlock(curTC, &stop);
		if (stop) break;
		curTC = kread64(curTC + koffsetof(trustcache, nextptr));
	}
}

int trustcache_list_insert(uint64_t tcToInsert)
{
	if (!tcToInsert) return -1;
	uint64_t previousStartTC = _trustcache_list_get_start();
	kwrite64(tcToInsert + koffsetof(trustcache, nextptr), previousStartTC);
	if (koffsetof(trustcache, prevptr)) {
		kwrite64(previousStartTC + koffsetof(trustcache, prevptr), tcToInsert);
	}
	_trustcache_list_set_start(tcToInsert);
	return 0;
}

int trustcache_list_remove(uint64_t tcKaddr)
{
	if (!tcKaddr) return -1;

	uint64_t nextTc = kread64(tcKaddr + koffsetof(trustcache, nextptr));

	uint64_t curTc = _trustcache_list_get_start();
	if (curTc == 0) {
		return -1;
	}
	else if (curTc == tcKaddr) {
		_trustcache_list_set_start(nextTc);
		if (nextTc && koffsetof(trustcache, prevptr)) {
			kwrite64(nextTc + koffsetof(trustcache, prevptr), 0);
		}
	}
	else {
		uint64_t prevTc = 0;
		while (curTc != tcKaddr)
		{
			if (curTc == 0) {
				return -1;
			}
			prevTc = curTc;
			curTc = kread64(curTc);
		}
		kwrite64(prevTc + koffsetof(trustcache, nextptr), nextTc);
		if (nextTc && koffsetof(trustcache, prevptr)) {
			kwrite64(nextTc + koffsetof(trustcache, prevptr), prevTc);
		}
	}

	return 0;
}

int _trustcache_file_sort_entry_comparator_v1(const void * vp1, const void * vp2)
{
	trustcache_entry_v1* tc1 = (trustcache_entry_v1*)vp1;
	trustcache_entry_v1* tc2 = (trustcache_entry_v1*)vp2;
	return memcmp(tc1->hash, tc2->hash, sizeof(cdhash_t));
}

void _trustcache_file_sort(trustcache_file_v1 *file)
{
	qsort(file->entries, file->length, sizeof(trustcache_entry_v1), _trustcache_file_sort_entry_comparator_v1);
}

bool _is_jb_trustcache(uint64_t tcKaddr)
{
	uint64_t jbTcFile = tcKaddr + offsetof(jb_trustcache, file);
	uint64_t file = kread64(tcKaddr + koffsetof(trustcache, fileptr));
	if (file == jbTcFile) {
		// If there is exactly one 8-byte value between the kpage start and the trustcache file,
		// Check if that matches against the JB_MAGIC
		// This is a 100% accurate way of determining whether this entry is a jb_trustcache or not
		return (kread64(tcKaddr + offsetof(jb_trustcache, magic)) == JB_MAGIC);
	}
	return false;
}

void _jb_trustcache_enumerate(void (^enumerateBlock)(uint64_t jbTcKaddr, bool *stop))
{
	_trustcache_list_enumerate(^(uint64_t tcKaddr, bool *stop) {
		if (_is_jb_trustcache(tcKaddr)) {
			enumerateBlock(tcKaddr, stop);
		}
	});
}

void jb_trustcache_clear(void)
{
	_jb_trustcache_enumerate(^(uint64_t jbTcKaddr, bool *stop) {
		kwrite64(jbTcKaddr + offsetof(jb_trustcache, file.length), 0);
	});
}

uint64_t _jb_trustcache_grow(void)
{
	uint64_t jbTcKern = 0;
	if (kalloc(&jbTcKern, 0x4000) != 0) return 0;

	jb_trustcache *jbTc = alloca(sizeof(jb_trustcache));
	memset(jbTc, 0, sizeof(jb_trustcache));
	_trustcache_file_init(&jbTc->file);
	jbTc->magic = JB_MAGIC;
	*(uint64_t *)(jbTc->trustcache + koffsetof(trustcache, fileptr)) = (jbTcKern + offsetof(jb_trustcache, file));
	if (koffsetof(trustcache, size)) {
		*(uint64_t *)(jbTc->trustcache + koffsetof(trustcache, size)) = JB_TRUSTCACHE_SIZE;
	}
	kwritebuf(jbTcKern, jbTc, sizeof(*jbTc));
	trustcache_list_insert(jbTcKern);
	return jbTcKern;
}

int jb_trustcache_add_entries(struct trustcache_entry_v1 *entries, uint32_t entryCount)
{
	uint32_t remainingEntryCount = entryCount;
	while (remainingEntryCount > 0) {
		__block uint64_t freeJbTcKaddr = 0;
		__block uint32_t freeJbTcCurrentLength = 0;
		_jb_trustcache_enumerate(^(uint64_t jbTcKaddr, bool *stop) {
			uint32_t length = kread32(jbTcKaddr + offsetof(jb_trustcache, file.length));
			if (length < JB_TRUSTCACHE_ENTRY_COUNT) {
				freeJbTcKaddr = jbTcKaddr;
				freeJbTcCurrentLength = length;
				*stop = true;
			}
		});
		if (freeJbTcKaddr == 0) {
			freeJbTcKaddr = _jb_trustcache_grow();
		}

		uint32_t entryCountToInsert = JB_TRUSTCACHE_ENTRY_COUNT - freeJbTcCurrentLength;
		if (remainingEntryCount < entryCountToInsert) {
			entryCountToInsert = remainingEntryCount;
		}

		jb_trustcache *jbTc = alloca(JB_TRUSTCACHE_SIZE);
		kreadbuf(freeJbTcKaddr, jbTc, JB_TRUSTCACHE_SIZE);
		for (uint32_t i = 0; i < entryCountToInsert; i++) {
			jbTc->file.entries[freeJbTcCurrentLength+i] = entries[i];
		}
		jbTc->file.length += entryCountToInsert;
		_trustcache_file_sort(&jbTc->file);
		kwritebuf(freeJbTcKaddr, jbTc, JB_TRUSTCACHE_SIZE);
		remainingEntryCount -= entryCountToInsert;
	}
	return 0;
}

int jb_trustcache_add_cdhashes(cdhash_t *hashes, uint32_t hashCount)
{
	struct trustcache_entry_v1 entries[hashCount];
	for (int i = 0; i < hashCount; i++) {
		memcpy(entries[i].hash, hashes[i], sizeof(cdhash_t));
		entries[i].hash_type = 1;
		entries[i].flags = 0;
	}
	return jb_trustcache_add_entries(entries, hashCount);
}

int jb_trustcache_add_entry(struct trustcache_entry_v1 entry)
{
	return jb_trustcache_add_entries(&entry, 1);
}


/*int jb_trustcache_add_file(const char *filePath)
{
	
}

int jb_trustcache_add_directory(const char *directoryPath)
{

}*/

xpc_object_t jb_trustcache_info(void)
{
	xpc_object_t arr = xpc_array_create_empty();
	_jb_trustcache_enumerate(^(uint64_t jbTcKaddr, bool *stop) {
		uuid_t uuid;
		kreadbuf(jbTcKaddr + offsetof(jb_trustcache, file.uuid), (void *)uuid, sizeof(uuid));
		uint32_t length = kread32(jbTcKaddr + offsetof(jb_trustcache, file.length));

		xpc_object_t tcDict = xpc_dictionary_create_empty();
		xpc_dictionary_set_data(tcDict, "uuid", &uuid, sizeof(uuid));

		xpc_object_t hashesArr = xpc_array_create_empty();
		for (int i = 0; i < length; i++) {
			trustcache_entry_v1 entry;
			kreadbuf(jbTcKaddr + offsetof(jb_trustcache, file.entries[i]), &entry, sizeof(entry));
			xpc_array_set_data(hashesArr, XPC_ARRAY_APPEND, &entry.hash, sizeof(entry.hash));
		}
		xpc_dictionary_set_value(tcDict, "cdhashes", hashesArr);
		xpc_release(hashesArr);

		xpc_array_append_value(arr, tcDict);
		xpc_release(tcDict);
	});
	return arr;
}

void jb_trustcache_debug_print(FILE *f)
{
	__block int i = 0;
	_jb_trustcache_enumerate(^(uint64_t jbTcKaddr, bool *stop) {
		uuid_t uuid;
		kreadbuf(jbTcKaddr + offsetof(jb_trustcache, file.uuid), (void *)uuid, sizeof(uuid));
		uint32_t length = kread32(jbTcKaddr + offsetof(jb_trustcache, file.length));

		uint32_t *uuidData = (uint32_t *)uuid;
		fprintf(f, "Jailbreak TrustCache %d <%08x%08x%08x%08x> (length: %u) (kaddr: 0x%llx):\n", i++, htonl(uuidData[0]), htonl(uuidData[1]), htonl(uuidData[2]), htonl(uuidData[3]), length, jbTcKaddr);
		
		for (uint32_t j = 0; j < length; j++) {
			trustcache_entry_v1 entry;
			kreadbuf(jbTcKaddr + offsetof(jb_trustcache, file.entries[j]), &entry, sizeof(entry));
			fprintf(f, "| ");
			for (uint32_t k = 0; k < sizeof(cdhash_t); k++) {
				fprintf(f, "%02x", entry.hash[k]);
			}
			fprintf(f, "\n");
		}
	});
}

int trustcache_file_upload(trustcache_file_v1 *tc)
{
	uint64_t tcSize = ksizeof(trustcache) + sizeof(trustcache_file_v1) + (tc->length * sizeof(trustcache_entry_v1));
	if (tcSize > 0x4000) return -1;

	// Check if there is already a TrustCache with the same UUID
	__block uint64_t existingTcKaddr = 0;
	_trustcache_list_enumerate(^(uint64_t tcKaddr, bool *stop) {
		uint64_t tcFileKaddr = kread64(tcKaddr + koffsetof(trustcache, fileptr));
		uuid_t tcFileUUID;
		kreadbuf(tcFileKaddr + offsetof(trustcache_file_v1, uuid), tcFileUUID, sizeof(tcFileUUID));
		if (memcmp(tcFileUUID, tc->uuid, sizeof(tcFileUUID)) == 0) {
			existingTcKaddr = tcKaddr;
			*stop = true;
		}
	});

	// If so, we want to either replace it or remove it
	if (existingTcKaddr != 0) {
		if (_is_jb_trustcache(existingTcKaddr)) {
			// There is something terribly wrong, abort
			return -1;
		}

		uint64_t prevTcFile = kread64(existingTcKaddr + koffsetof(trustcache, fileptr));
		uint32_t prevTcLength = kread32(prevTcFile + offsetof(trustcache_file_v1, length));
		uint64_t prevTcSize = ksizeof(trustcache) + sizeof(trustcache_file_v1) + (prevTcLength * sizeof(trustcache_entry_v1));
		if (prevTcSize == tcSize) {
			// If size is the same this is simple, just replace the file data
			kwritebuf(prevTcFile, tc, tcSize);
			return 0;
		}
		else {
			// If not, it gets more complicated and hacky...
			// We can't take a lock (at least not yet??) to ensure nothing accesses the original TrustCache after we freed it
			// So we do the next best thing, we remove it from the linked list and wait a bit before freeing it, hoping that any
			// outstanding reads on the memory would be done by then
			if (trustcache_list_remove(existingTcKaddr) != 0) {
				return -1; // really unlikely error, if this triggers the world is probably upside down
			}
			usleep(10000); // hope for current accesses to finish if there are any (new accesses won't come as we removed the list entry)
			kfree(existingTcKaddr, prevTcSize); // free the original allocation
			// now just fall through and make this function add the new TrustCache
		}
	}

	uint64_t tcKaddr = 0;
	if (kalloc(&tcKaddr, tcSize) != 0) return -1;

	uint64_t tcFileKaddr = tcKaddr + ksizeof(trustcache);
	kwritebuf(tcFileKaddr, tc, tcSize - ksizeof(trustcache));

	kwrite64(tcKaddr + koffsetof(trustcache, fileptr), tcFileKaddr);
	if (koffsetof(trustcache, size)) {
		kwrite64(tcKaddr + koffsetof(trustcache, size), tcSize);
	}

	trustcache_list_insert(tcKaddr);
	return 0;
}

int trustcache_file_upload_with_uuid(trustcache_file_v1 *tc, uuid_t uuid)
{
	memcpy(tc->uuid, uuid, sizeof(uuid_t));
	return trustcache_file_upload(tc);
}

int trustcache_file_build_from_cdhashes(cdhash_t *CDHashes, uint32_t CDHashCount, trustcache_file_v1 **tcOut)
{
	if (!CDHashes || CDHashCount == 0 || !tcOut) return -1;

	size_t tcSize = sizeof(trustcache_file_v1) + (sizeof(trustcache_entry_v1) * CDHashCount);
	trustcache_file_v1 *file = malloc(tcSize);
	_trustcache_file_init(file);

	file->length = CDHashCount;
	for (uint32_t i = 0; i < CDHashCount; i++) {
		memcpy(file->entries[i].hash, CDHashes[i], sizeof(cdhash_t));
		file->entries[i].hash_type = 2;
		file->entries[i].flags = 0;
	}
	_trustcache_file_sort(file);

	*tcOut = file;
	return 0;
}

int trustcache_file_build_from_path(const char *filePath, trustcache_file_v1 **tcOut)
{
	int fd = open(filePath, O_RDONLY);
	struct stat s = { 0 };
	fstat(fd, &s);
	
	size_t tcSize = s.st_size;
	if (tcSize < (sizeof(trustcache_file_v1))) {
		// To small to be a TrustCache, file is probably malformed
		return -1;
	}

	trustcache_file_v1 *file = malloc(tcSize);
	read(fd, file, tcSize);
	close(fd);

	size_t actualTcSize = sizeof(trustcache_file_v1) + (sizeof(trustcache_entry_v1) * file->length);
	if (actualTcSize != tcSize) {
		// Size mismatch, file is malformed
		free(file);
		return -1;
	}

	*tcOut = file;
	return 0;
}

bool trustcache_contains_cdhash(uint64_t tcKaddr, cdhash_t CDHash)
{
	uint64_t tcFileKaddr = kread64(tcKaddr + koffsetof(trustcache, fileptr));
	uint32_t length = kread32(tcFileKaddr + offsetof(trustcache_file_v1, length));
	if (length == 0) return false;

	int32_t left = 0;
	int32_t right = length - 1;

	while (left <= right) {
		int32_t mid = (left + right) / 2;
		cdhash_t itCDHash;
		kreadbuf(tcFileKaddr + offsetof(trustcache_file_v1, entries[mid].hash), itCDHash, CS_CDHASH_LEN);
		int32_t cmp = memcmp(CDHash, itCDHash, CS_CDHASH_LEN);
		if (cmp == 0) {
			return true;
		}
		if (cmp < 0) {
			right = mid - 1;
		} else {
			left = mid + 1;
		}
	}
	return false;
}

bool is_cdhash_trustcached(cdhash_t CDHash)
{
	__block bool inTrustCache = false;
	_trustcache_list_enumerate(^(uint64_t tcKaddr, bool *stop) {
		bool inThisTrustCache = trustcache_contains_cdhash(tcKaddr, CDHash);
		if (inThisTrustCache) {
			inTrustCache = true;
			*stop = true;
		}
	});
	return inTrustCache;
}