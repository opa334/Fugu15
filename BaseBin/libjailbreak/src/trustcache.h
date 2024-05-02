#ifndef TRUSTCACHE_H
#define TRUSTCACHE_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "trustcache_structs.h"
#include <xpc/xpc.h>

#define BASEBIN_TRUSTCACHE_UUID (uuid_t){'B','A','S','E','B','I','N','\0','\0','\0','\0','\0','\0','\0','\0','\0'}
#define DYLD_TRUSTCACHE_UUID (uuid_t){'D','Y','L','D','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0'}

int trustcache_list_insert(uint64_t tcKaddr);

int jb_trustcache_add_entries(struct trustcache_entry_v1 *entries, uint32_t entryCount);
int jb_trustcache_add_entry(trustcache_entry_v1 entry);
int jb_trustcache_add_cdhashes(cdhash_t *hashes, uint32_t hashCount);
xpc_object_t jb_trustcache_info(void);
void jb_trustcache_clear(void);

//int jb_trustcache_add_file(const char *filePath);
//int jb_trustcache_add_directory(const char *directoryPath);
//void jb_trustcache_rebuild(void);

void jb_trustcache_debug_print(FILE *f);

int trustcache_file_upload(trustcache_file_v1 *tc);
int trustcache_file_upload_with_uuid(trustcache_file_v1 *tc, uuid_t uuid);
int trustcache_file_build_from_cdhashes(cdhash_t *CDHashes, uint32_t CDHashCount, trustcache_file_v1 **tcOut);
int trustcache_file_build_from_path(const char *filePath, trustcache_file_v1 **tcOut);

bool is_cdhash_in_trustcache(uint64_t tcKaddr, cdhash_t CDHash);
bool is_cdhash_trustcached(cdhash_t CDHash);

#endif
