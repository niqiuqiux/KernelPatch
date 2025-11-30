#ifndef __LINUX_COMPILER_H
#define __LINUX_COMPILER_H
#include "ktypes.h"
/*
 * Prevent the compiler from merging or refetching reads or writes. The
 * compiler is also forbidden from reordering successive instances of
 * READ_ONCE, WRITE_ONCE and ACCESS_ONCE (see below), but only when the
 * compiler is aware of some particular ordering.  One way to make the
 * compiler aware of ordering is to put the two invocations of READ_ONCE,
 * WRITE_ONCE or ACCESS_ONCE() in different C statements.
 *
 * In contrast to ACCESS_ONCE these two macros will also work on aggregate
 * data types like structs or unions. If the size of the accessed data
 * type exceeds the word size of the machine (e.g., 32 bits or 64 bits)
 * READ_ONCE() and WRITE_ONCE()  will fall back to memcpy and print a
 * compile-time warning.
 *
 * Their two major use cases are: (1) Mediating communication between
 * process-level code and irq/NMI handlers, all running on the same CPU,
 * and (2) Ensuring that the compiler does not  fold, spindle, or otherwise
 * mutilate accesses that either do not require ordering or that interact
 * with an explicit memory barrier or atomic instruction that provides the
 * required ordering.
 */


/*
 * Following functions are taken from kernel sources and
 * break aliasing rules in their original form.
 *
 * While kernel is compiled with -fno-strict-aliasing,
 * perf uses -Wstrict-aliasing=3 which makes build fail
 * under gcc 4.4.
 *
 * Using extra __may_alias__ type to allow aliasing
 * in this case.
 */
//  typedef __u8  __attribute__((__may_alias__))  __u8_alias_t;
//  typedef __u16 __attribute__((__may_alias__)) __u16_alias_t;
//  typedef __u32 __attribute__((__may_alias__)) __u32_alias_t;
//  typedef __u64 __attribute__((__may_alias__)) __u64_alias_t;
 
//  static __always_inline void __read_once_size(const volatile void *p, void *res, int size)
//  {
//      switch (size) {
//      case 1: *(__u8_alias_t  *) res = *(volatile __u8_alias_t  *) p; break;
//      case 2: *(__u16_alias_t *) res = *(volatile __u16_alias_t *) p; break;
//      case 4: *(__u32_alias_t *) res = *(volatile __u32_alias_t *) p; break;
//      case 8: *(__u64_alias_t *) res = *(volatile __u64_alias_t *) p; break;
//      default:
//          barrier();
//          __builtin_memcpy((void *)res, (const void *)p, size);
//          barrier();
//      }
//  }
 
//  static __always_inline void __write_once_size(volatile void *p, void *res, int size)
//  {
//      switch (size) {
//      case 1: *(volatile  __u8_alias_t *) p = *(__u8_alias_t  *) res; break;
//      case 2: *(volatile __u16_alias_t *) p = *(__u16_alias_t *) res; break;
//      case 4: *(volatile __u32_alias_t *) p = *(__u32_alias_t *) res; break;
//      case 8: *(volatile __u64_alias_t *) p = *(__u64_alias_t *) res; break;
//      default:
//          barrier();
//          __builtin_memcpy((void *)p, (const void *)res, size);
//          barrier();
//      }
//  }
 


// #define READ_ONCE(x)                                \
//     ({                                              \
//         union                                       \
//         {                                           \
//             typeof(x) __val;                        \
//             char __c[1];                            \
//         } __u;                                      \
//         __read_once_size(&(x), __u.__c, sizeof(x)); \
//         __u.__val;                                  \
//     })

// #define WRITE_ONCE(x, val)                              \
//     ({                                                  \
//         typeof(x) __val = (val);                        \
//         __write_once_size(&(x), &__val, sizeof(__val)); \
//         __val;                                          \
//     })

/*
 * Prevent the compiler from merging or refetching accesses.  The compiler
 * is also forbidden from reordering successive instances of ACCESS_ONCE(),
 * but only when the compiler is aware of some particular ordering.  One way
 * to make the compiler aware of ordering is to put the two invocations of
 * ACCESS_ONCE() in different C statements.
 *
 * This macro does absolutely -nothing- to prevent the CPU from reordering,
 * merging, or refetching absolutely anything at any time.  Its main intended
 * use is to mediate communication between process-level code and irq/NMI
 * handlers, all running on the same CPU.
 */
#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))

#endif