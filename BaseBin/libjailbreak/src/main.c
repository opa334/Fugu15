#include "jbclient_xpc.h"
#include <stdlib.h>
#include "physrw.h"
#include "physrw_pte.h"
#include "kalloc_pt.h"
#include "primitives_IOSurface.h"
#include "info.h"
#include "translation.h"
#include "kcall_Fugu14.h"
#include "kcall_arm64.h"
#include <xpc/xpc.h>

int jbclient_initialize_primitives_internal(bool physrwPTE)
{
	if (getuid() != 0) return -1;

	xpc_object_t xSystemInfo = NULL;
	if (jbclient_root_get_sysinfo(&xSystemInfo) == 0) {
		SYSTEM_INFO_DESERIALIZE(xSystemInfo);
		xpc_release(xSystemInfo);
		uint64_t asidPtr = 0;
		if (jbclient_root_get_physrw(physrwPTE, &asidPtr) == 0) {
			if (physrwPTE) {
				libjailbreak_physrw_pte_init(true, asidPtr);
			}
			else {
				libjailbreak_physrw_init(true);
			}
			libjailbreak_translation_init();
			libjailbreak_IOSurface_primitives_init();
			if (__builtin_available(iOS 16.0, *)) {
				libjailbreak_kalloc_pt_init();
			}
			if (gPrimitives.kalloc_local) {
#ifdef __arm64e__
				if (jbinfo(usesPACBypass)) {
					jbclient_get_fugu14_kcall();
				}
#else
				arm64_kcall_init();
#endif
			}

			return 0;
		}
	}

	return -1;
}

int jbclient_initialize_primitives(void)
{
	return jbclient_initialize_primitives_internal(false);
}

// Used for supporting third party legacy software that still calls this function
int jbdInitPPLRW(void)
{
	return jbclient_initialize_primitives();
}
