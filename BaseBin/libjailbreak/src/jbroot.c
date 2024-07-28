#include "info.h"

char *get_jbroot(void)
{
	return jbinfo(rootPath);
}