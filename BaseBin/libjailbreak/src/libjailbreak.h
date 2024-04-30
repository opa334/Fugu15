#include "primitives.h"
#include "info.h"
#include "kernel.h"
#include "util.h"
#include "translation.h"
#include "trustcache.h"
#include "jbclient_xpc.h"

int jbclient_initialize_primitives_internal(bool physrwPTE);
int jbclient_initialize_primitives(void);