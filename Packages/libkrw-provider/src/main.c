#include <libjailbreak/libjailbreak.h>
#include <libkrw/libkrw_plugin.h>
#include <dispatch/dispatch.h>
#include <errno.h>

static void load_primitives_once(void)
{
	static dispatch_once_t onceToken;
	dispatch_once (&onceToken, ^{
		jbclient_initialize_primitives();
	});
}

static int kwritebuf_wrapper(void *from, uint64_t to, size_t len)
{
	return kwritebuf(to, from, len);
}

static int kcall_wrapper(uint64_t func, size_t argc, const uint64_t *argv, uint64_t *ret)
{
	if (is_kcall_available()) {
		return kcall(ret, func, argc, argv);
	}
	return ENOTSUP;
}

static int physreadbuf_wrapper(uint64_t from, void *to, size_t len, uint8_t granule)
{
	return physreadbuf(from, to, len);
}

static int physwritebuf_wrapper(void *from, uint64_t to, size_t len, uint8_t granule)
{
	return physwritebuf(to, from, len);
}

static int kbase_wrapper(uint64_t *kbase)
{
	*kbase = kconstant(base);
	return 0;
}

__attribute__((used)) int krw_initializer(krw_handlers_t handlers)
{
	load_primitives_once();

	handlers->kbase = kbase_wrapper;
	handlers->kread = kreadbuf;
	handlers->kwrite = kwritebuf_wrapper;
	handlers->kmalloc = (krw_kmalloc_func_t)(kalloc);
	handlers->kdealloc = (krw_kdealloc_func_t)(kfree);
	return 0;
}

__attribute__((used)) int kcall_initializer(krw_handlers_t handlers)
{
	load_primitives_once();

	handlers->kcall = kcall_wrapper;
	handlers->physread = physreadbuf_wrapper;
	handlers->physwrite = physwritebuf_wrapper;
	return 0;
}