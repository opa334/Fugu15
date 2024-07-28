#ifndef JBROOT_H
#define JBROOT_H

extern char *_Nullable get_jbroot(void);

// Partially adapted from libroot for consistency
// This can be included even when libjailbreak is not linked, as long as the includer implements the get_jbroot symbol

__attribute__((__overloadable__))
static inline const char *_Nullable __jbroot_convert_path(const char *_Nullable path, char *_Nonnull buf) {
	if (!buf || !path) return NULL;
	const char *jbroot = get_jbroot();
	if (!jbroot) return NULL;
	strlcpy(buf, jbroot, PATH_MAX);
	strlcat(buf, path, PATH_MAX);
	return buf;
}

#ifdef __OBJC__
#import <Foundation/Foundation.h>

__attribute__((__overloadable__))
static inline NSString *_Nullable __jbroot_convert_path(NSString *_Nullable path, void *_Nullable const __unused buf) {
	char tmpBuf[PATH_MAX];
	const char *convertedPath = __jbroot_convert_path(path.fileSystemRepresentation, tmpBuf);
	return convertedPath ? [NSString stringWithUTF8String:convertedPath] : nil;
}

#endif

#define __BUFFER_FOR_CHAR_P(x) \
	__builtin_choose_expr(										\
		__builtin_types_compatible_p(__typeof__(*(x)), char),	\
		alloca(PATH_MAX),										\
		NULL													\
	)

#define JBROOT_PATH(path) __jbroot_convert_path((path), __BUFFER_FOR_CHAR_P(path))
#define ROOTFS_PATH(path) __jbroot_convert_path((path), __BUFFER_FOR_CHAR_P(path))

#endif