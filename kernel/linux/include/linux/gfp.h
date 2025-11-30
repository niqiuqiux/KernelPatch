#ifndef __LINUX_GFP_H
#define __LINUX_GFP_H



/* Plain integer GFP bitmasks. Do not use this directly. */
// #define __GFP_DMA 0x01u
// #define __GFP_HIGHMEM 0x02u
// #define __GFP_DMA32 0x04u
// #define __GFP_MOVABLE 0x08u
// #define __GFP_RECLAIMABLE 0x10u
// #define __GFP_HIGH 0x20u
// #define __GFP_IO 0x40u
// #define __GFP_FS 0x80u
// #define __GFP_ZERO 0x100u
// #define __GFP_ATOMIC 0x200u
// #define __GFP_DIRECT_RECLAIM 0x400u
// #define __GFP_KSWAPD_RECLAIM 0x800u
// #define __GFP_WRITE 0x1000u
// #define __GFP_NOWARN 0x2000u
// #define __GFP_RETRY_MAYFAIL 0x4000u
// #define __GFP_NOFAIL 0x8000u
// #define __GFP_NORETRY 0x10000u
// #define __GFP_MEMALLOC 0x20000u
// #define __GFP_COMP 0x40000u
// #define __GFP_NOMEMALLOC 0x80000u
// #define __GFP_HARDWALL 0x100000u
// #define __GFP_THISNODE 0x200000u
// #define __GFP_ACCOUNT 0x400000u
// #define __GFP_NOLOCKDEP 0x800000u



// static inline get_gfp_atomic()
// {
//     if (kver >= VERSION(3, 18, 0)) return __GFP_HIGH;

// }

// #define __GFP_RECLAIM ((__force gfp_t)(__GFP_DIRECT_RECLAIM | __GFP_KSWAPD_RECLAIM))

// #define GFP_ATOMIC (__GFP_HIGH | __GFP_ATOMIC | __GFP_KSWAPD_RECLAIM)
// #define GFP_KERNEL (__GFP_RECLAIM | __GFP_IO | __GFP_FS)

// #define GFP_KERNEL_ACCOUNT (GFP_KERNEL | __GFP_ACCOUNT)
// #define GFP_NOWAIT (__GFP_KSWAPD_RECLAIM)
// #define GFP_NOIO (__GFP_RECLAIM)
// #define GFP_NOFS (__GFP_RECLAIM | __GFP_IO)
// #define GFP_USER (__GFP_RECLAIM | __GFP_IO | __GFP_FS | __GFP_HARDWALL)
// #define GFP_DMA __GFP_DMA
// #define GFP_DMA32 __GFP_DMA32
// #define GFP_HIGHUSER (GFP_USER | __GFP_HIGHMEM)
// #define GFP_HIGHUSER_MOVABLE (GFP_HIGHUSER | __GFP_MOVABLE)
// #define GFP_TRANSHUGE_LIGHT ((GFP_HIGHUSER_MOVABLE | __GFP_COMP | __GFP_NOMEMALLOC | __GFP_NOWARN) & ~__GFP_RECLAIM)
// #define GFP_TRANSHUGE (GFP_TRANSHUGE_LIGHT | __GFP_DIRECT_RECLAIM)

/* Convert GFP flags to their corresponding migrate type */
// #define GFP_MOVABLE_MASK (__GFP_RECLAIMABLE | __GFP_MOVABLE)
// #define GFP_MOVABLE_SHIFT 3





#define ___GFP_DMA		0x01u
#define ___GFP_HIGHMEM		0x02u
#define ___GFP_DMA32		0x04u
#define ___GFP_MOVABLE		0x08u
#define ___GFP_RECLAIMABLE	0x10u
#define ___GFP_HIGH		0x20u
#define ___GFP_IO		0x40u
#define ___GFP_FS		0x80u
#define ___GFP_COLD		0x100u
#define ___GFP_NOWARN		0x200u
#define ___GFP_RETRY_MAYFAIL	0x400u
#define ___GFP_NOFAIL		0x800u
#define ___GFP_NORETRY		0x1000u
#define ___GFP_MEMALLOC		0x2000u
#define ___GFP_COMP		0x4000u
#define ___GFP_ZERO		0x8000u
#define ___GFP_NOMEMALLOC	0x10000u
#define ___GFP_HARDWALL		0x20000u
#define ___GFP_THISNODE		0x40000u
#define ___GFP_ATOMIC		0x80000u
#define ___GFP_ACCOUNT		0x100000u
#define ___GFP_DIRECT_RECLAIM	0x400000u
#define ___GFP_WRITE		0x800000u
#define ___GFP_KSWAPD_RECLAIM	0x1000000u
#ifdef CONFIG_LOCKDEP
#define ___GFP_NOLOCKDEP	0x2000000u
#else
#define ___GFP_NOLOCKDEP	0
#endif
#define ___GFP_CMA		0x4000000u



#define __GFP_RECLAIMABLE ((__force gfp_t)___GFP_RECLAIMABLE)
#define __GFP_WRITE	((__force gfp_t)___GFP_WRITE)
#define __GFP_HARDWALL   ((__force gfp_t)___GFP_HARDWALL)
#define __GFP_THISNODE	((__force gfp_t)___GFP_THISNODE)
#define __GFP_ACCOUNT	((__force gfp_t)___GFP_ACCOUNT)


#define __GFP_ATOMIC	((__force gfp_t)___GFP_ATOMIC)
#define __GFP_HIGH	((__force gfp_t)___GFP_HIGH)
#define __GFP_MEMALLOC	((__force gfp_t)___GFP_MEMALLOC)
#define __GFP_NOMEMALLOC ((__force gfp_t)___GFP_NOMEMALLOC)

#define __GFP_COLD	((__force gfp_t)___GFP_COLD)
#define __GFP_NOWARN	((__force gfp_t)___GFP_NOWARN)
#define __GFP_COMP	((__force gfp_t)___GFP_COMP)
#define __GFP_ZERO	((__force gfp_t)___GFP_ZERO)

#define __GFP_IO	((__force gfp_t)___GFP_IO)
#define __GFP_FS	((__force gfp_t)___GFP_FS)
#define __GFP_DIRECT_RECLAIM	((__force gfp_t)___GFP_DIRECT_RECLAIM) /* Caller can reclaim */
#define __GFP_KSWAPD_RECLAIM	((__force gfp_t)___GFP_KSWAPD_RECLAIM) /* kswapd can wake */
#define __GFP_RECLAIM ((__force gfp_t)(___GFP_DIRECT_RECLAIM|___GFP_KSWAPD_RECLAIM))
#define __GFP_RETRY_MAYFAIL	((__force gfp_t)___GFP_RETRY_MAYFAIL)
#define __GFP_NOFAIL	((__force gfp_t)___GFP_NOFAIL)
#define __GFP_NORETRY	((__force gfp_t)___GFP_NORETRY)

#define GFP_ATOMIC	(__GFP_HIGH|__GFP_ATOMIC|__GFP_KSWAPD_RECLAIM)
#define GFP_KERNEL	(__GFP_RECLAIM | __GFP_IO | __GFP_FS)
#define GFP_KERNEL_ACCOUNT (GFP_KERNEL | __GFP_ACCOUNT)
#define GFP_NOWAIT	(__GFP_KSWAPD_RECLAIM)
#define GFP_NOIO	(__GFP_RECLAIM)
#define GFP_NOFS	(__GFP_RECLAIM | __GFP_IO)
#define GFP_USER	(__GFP_RECLAIM | __GFP_IO | __GFP_FS | __GFP_HARDWALL)
#define GFP_DMA		__GFP_DMA
#define GFP_DMA32	__GFP_DMA32
#define GFP_HIGHUSER	(GFP_USER | __GFP_HIGHMEM)
#define GFP_HIGHUSER_MOVABLE	(GFP_HIGHUSER | __GFP_MOVABLE)
#define GFP_TRANSHUGE_LIGHT	((GFP_HIGHUSER_MOVABLE | __GFP_COMP | \
			 __GFP_NOMEMALLOC | __GFP_NOWARN) & ~__GFP_RECLAIM)
#define GFP_TRANSHUGE	(GFP_TRANSHUGE_LIGHT | __GFP_DIRECT_RECLAIM)






#endif