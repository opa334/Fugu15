//
//  shim.c
//  idownloadd
//
//  Created by Lars Fröder on 25.01.24.
//

#include <stdio.h>
#include "idownloadd-Bridging-Header.h"

uint64_t c_getkslide(void)
{
    return kconstant(slide);
}

uint64_t c_getkbase(void)
{
    return kconstant(base);
}

bool c_kcall_supported(void)
{
    return is_kcall_available();
}

int c_kcall(uint64_t *result, uint64_t func, int argc, const uint64_t *argv)
{
    return kcall(result, func, argc, argv);
}

uint64_t c_kalloc(uint64_t *addr, uint64_t size)
{
    return kalloc(addr, size);
}
