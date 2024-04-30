#ifndef PTE_H
#define PTE_H

#define PTE_NON_GLOBAL      (1 << 11)
#define PTE_VALID           (1 << 10) // Access flag
#define PTE_OUTER_SHAREABLE (2 << 8)
#define PTE_INNER_SHAREABLE (3 << 8)

//#define PTE_LEVEL2_BLOCK    PTE_VALID | (0x1)
#define PTE_LEVEL2_BLOCK    PTE_VALID | (0x0)
#define PTE_LEVEL3_ENTRY    PTE_VALID | 0x3

#define KRW_URW_PERM        (0x60000000000040)
#define KRW_UR_PERM         (0x600000000000C0)

#define PTE_RESERVED        (0x3)
#define PTE_REUSEABLE       (0x1)
#define PTE_UNUSED          (0x0)

#define P_PAGE_SIZE 0x4000
#define P_PAGE_MASK 0x3FFF

#define PTE_TO_PERM(pte)  ((((pte) >> 4ULL) & 0xC) | (((pte) >> 52ULL) & 2) | (((pte) >> 54ULL) & 1))
#define _PERM_TO_PTE(perm) ((((perm) & 0xC) << 4ULL) | (((perm) & 2) << 52ULL) | (((perm) & 1) << 54ULL))
#define PERM_TO_PTE(perm) _PERM_TO_PTE((uint64_t) (perm))

#define AP_RWNA   (0x0ull << 6)
#define AP_RWRW   (0x1ull << 6)
#define AP_RONA   (0x2ull << 6)
#define AP_RORO   (0x3ull << 6)

#define ARM_PTE_TYPE              0x0000000000000003ull
#define ARM_PTE_TYPE_VALID        0x0000000000000003ull
#define ARM_PTE_TYPE_MASK         0x0000000000000002ull
#define ARM_TTE_TYPE_L3BLOCK      0x0000000000000002ull
#define ARM_PTE_ATTRINDX          0x000000000000001cull
#define ARM_PTE_NS                0x0000000000000020ull
#define ARM_PTE_AP                0x00000000000000c0ull
#define ARM_PTE_SH                0x0000000000000300ull
#define ARM_PTE_AF                0x0000000000000400ull
#define ARM_PTE_NG                0x0000000000000800ull
#define ARM_PTE_ZERO1             0x000f000000000000ull
#define ARM_PTE_HINT              0x0010000000000000ull
#define ARM_PTE_PNX               0x0020000000000000ull
#define ARM_PTE_NX                0x0040000000000000ull
#define ARM_PTE_ZERO2             0x0380000000000000ull
#define ARM_PTE_WIRED             0x0400000000000000ull
#define ARM_PTE_WRITEABLE         0x0800000000000000ull
#define ARM_PTE_ZERO3             0x3000000000000000ull
#define ARM_PTE_COMPRESSED_ALT    0x4000000000000000ull
#define ARM_PTE_COMPRESSED        0x8000000000000000ull

#define ARM_TTE_VALID         0x0000000000000001ull
#define ARM_TTE_TYPE_MASK     0x0000000000000002ull
#define ARM_TTE_TYPE_TABLE    0x0000000000000002ull
#define ARM_TTE_TYPE_BLOCK    0x0000000000000000ull
#define ARM_TTE_TABLE_MASK    0x0000fffffffff000ull
#define ARM_TTE_PA_MASK       0x0000fffffffff000ull

#define PMAP_TT_L0_LEVEL    0x0
#define PMAP_TT_L1_LEVEL    0x1
#define PMAP_TT_L2_LEVEL    0x2
#define PMAP_TT_L3_LEVEL    0x3

#define ARM_16K_TT_L0_SIZE          0x0000800000000000ull
#define ARM_16K_TT_L0_OFFMASK       0x00007fffffffffffull
#define ARM_16K_TT_L0_SHIFT         47
#define ARM_16K_TT_L0_INDEX_MASK    0x0000800000000000ull

#define ARM_16K_TT_L1_SIZE          0x0000001000000000ull
#define ARM_16K_TT_L1_OFFMASK       0x0000000fffffffffull
#define ARM_16K_TT_L1_SHIFT         36
#define ARM_16K_TT_L1_INDEX_MASK    0x0000007000000000ull

#define ARM_16K_TT_L2_SIZE          0x0000000002000000ull
#define ARM_16K_TT_L2_OFFMASK       0x0000000001ffffffull
#define ARM_16K_TT_L2_SHIFT         25
#define ARM_16K_TT_L2_INDEX_MASK    0x0000000ffe000000ull

#define ARM_16K_TT_L3_SIZE          0x0000000000004000ull
#define ARM_16K_TT_L3_OFFMASK       0x0000000000003fffull
#define ARM_16K_TT_L3_SHIFT         14
#define ARM_16K_TT_L3_INDEX_MASK    0x0000000001ffc000ull

#define ARM_4K_TT_L0_SIZE           0x0000008000000000ULL
#define ARM_4K_TT_L0_OFFMASK        0x0000007fffffffffULL
#define ARM_4K_TT_L0_SHIFT          39
#define ARM_4K_TT_L0_INDEX_MASK     0x0000ff8000000000ULL

#define ARM_4K_TT_L1_SIZE           0x0000000040000000ULL
#define ARM_4K_TT_L1_OFFMASK        0x000000003fffffffULL
#define ARM_4K_TT_L1_SHIFT          30
#define ARM_4K_TT_L1_INDEX_MASK     0x0000003fc0000000ULL

#define ARM_4K_TT_L2_SIZE           0x0000000000200000ULL
#define ARM_4K_TT_L2_OFFMASK        0x00000000001fffffULL
#define ARM_4K_TT_L2_SHIFT          21
#define ARM_4K_TT_L2_INDEX_MASK     0x000000003fe00000ULL

#define ARM_4K_TT_L3_SIZE           0x0000000000001000ULL
#define ARM_4K_TT_L3_OFFMASK        0x0000000000000fffULL
#define ARM_4K_TT_L3_SHIFT          12
#define ARM_4K_TT_L3_INDEX_MASK     0x00000000001ff000ULL

#endif
