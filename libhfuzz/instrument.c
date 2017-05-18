#include <unistd.h>

#include "../common.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../util.h"

/*
 * We require SSE4.2 with x86-(32|64) for the 'popcnt', as it's much faster than the software
 * emulation of gcc/clang
 */
#if defined(__x86_64__) || defined(__i386__)
#define ATTRIBUTE_X86_REQUIRE_SSE42  __attribute__((__target__("sse4.2")))
#else
#define ATTRIBUTE_X86_REQUIRE_SSE42
#endif                          /* defined(__x86_64__) || defined(__i386__) */

static feedback_t bbMapFb;
feedback_t *feedback = &bbMapFb;
uint32_t my_thread_no = 0;

__attribute__ ((constructor))
static void mapBB(void)
{
    char *my_thread_no_str = getenv(_HF_THREAD_NO_ENV);
    if (my_thread_no_str == NULL) {
        return;
    }
    my_thread_no = atoi(my_thread_no_str);

    if (my_thread_no >= _HF_THREAD_MAX) {
        fprintf(stderr, "my_thread_no > _HF_THREAD_MAX (%" PRIu32 " > %d)\n", my_thread_no,
                _HF_THREAD_MAX);
        _exit(1);
    }
    struct stat st;
    if (fstat(_HF_BITMAP_FD, &st) == -1) {
        return;
    }
    if (st.st_size != sizeof(feedback_t)) {
        fprintf(stderr, "st.size != sizeof(feedback_t) (%zu != %zu)\n", (size_t) st.st_size,
                sizeof(feedback_t));
        _exit(1);
    }
    if ((feedback =
         mmap(NULL, sizeof(feedback_t), PROT_READ | PROT_WRITE, MAP_SHARED, _HF_BITMAP_FD,
              0)) == MAP_FAILED) {
        fprintf(stderr, "mmap: %s\n", strerror(errno));
        _exit(1);
    }
    feedback->pidFeedbackPc[my_thread_no] = 0U;
    feedback->pidFeedbackCmp[my_thread_no] = 0U;
}

/*
 * -finstrument-functions
 */
ATTRIBUTE_X86_REQUIRE_SSE42 void __cyg_profile_func_enter(void *func, void *caller)
{
    register size_t pos =
        (((uintptr_t) func << 12) | ((uintptr_t) caller & 0xFFF)) & _HF_PERF_BITMAP_BITSZ_MASK;
    register uint8_t prev = ATOMIC_BTS(feedback->bbMapPc, pos);
    if (!prev) {
        ATOMIC_PRE_INC_RELAXED(feedback->pidFeedbackPc[my_thread_no]);
    }
}

ATTRIBUTE_X86_REQUIRE_SSE42 void __cyg_profile_func_exit(void *func UNUSED, void *caller UNUSED)
{
    return;
}

/*
 * -fsanitize-coverage=trace-pc
 */
ATTRIBUTE_X86_REQUIRE_SSE42 void __sanitizer_cov_trace_pc(void)
{
    register uintptr_t ret = (uintptr_t) __builtin_return_address(0) & _HF_PERF_BITMAP_BITSZ_MASK;
    register uint8_t prev = ATOMIC_BTS(feedback->bbMapPc, ret);
    if (!prev) {
        ATOMIC_PRE_INC_RELAXED(feedback->pidFeedbackPc[my_thread_no]);
    }
}

/*
 * -fsanitize-coverage=indirect-calls
 */
ATTRIBUTE_X86_REQUIRE_SSE42 void __sanitizer_cov_trace_pc_indir(void *callee)
{
    register size_t pos1 = (uintptr_t) __builtin_return_address(0) << 12;
    register size_t pos2 = (uintptr_t) callee & 0xFFF;
    register size_t pos = (pos1 | pos2) & _HF_PERF_BITMAP_BITSZ_MASK;

    register uint8_t prev = ATOMIC_BTS(feedback->bbMapPc, pos);
    if (!prev) {
        ATOMIC_PRE_INC_RELAXED(feedback->pidFeedbackPc[my_thread_no]);
    }
}

/*
 * -fsanitize-coverage=trace-cmp
 */
ATTRIBUTE_X86_REQUIRE_SSE42 void __sanitizer_cov_trace_cmp1(uint8_t Arg1, uint8_t Arg2)
{
    uintptr_t pos = (uintptr_t) __builtin_return_address(0) % _HF_PERF_BITMAP_SIZE_16M;
    register uint8_t v = ((sizeof(Arg1) * 8) - __builtin_popcount(Arg1 ^ Arg2));
    uint8_t prev = ATOMIC_GET(feedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(feedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(feedback->pidFeedbackCmp[my_thread_no], v - prev);
    }
}

ATTRIBUTE_X86_REQUIRE_SSE42 void __sanitizer_cov_trace_cmp2(uint16_t Arg1, uint16_t Arg2)
{
    uintptr_t pos = (uintptr_t) __builtin_return_address(0) % _HF_PERF_BITMAP_SIZE_16M;
    register uint8_t v = ((sizeof(Arg1) * 8) - __builtin_popcount(Arg1 ^ Arg2));
    uint8_t prev = ATOMIC_GET(feedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(feedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(feedback->pidFeedbackCmp[my_thread_no], v - prev);
    }
}

ATTRIBUTE_X86_REQUIRE_SSE42 void __sanitizer_cov_trace_cmp4(uint32_t Arg1, uint32_t Arg2)
{
    uintptr_t pos = (uintptr_t) __builtin_return_address(0) % _HF_PERF_BITMAP_SIZE_16M;
    register uint8_t v = ((sizeof(Arg1) * 8) - __builtin_popcount(Arg1 ^ Arg2));
    uint8_t prev = ATOMIC_GET(feedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(feedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(feedback->pidFeedbackCmp[my_thread_no], v - prev);
    }
}

ATTRIBUTE_X86_REQUIRE_SSE42 void __sanitizer_cov_trace_cmp8(uint64_t Arg1, uint64_t Arg2)
{
    uintptr_t pos = (uintptr_t) __builtin_return_address(0) % _HF_PERF_BITMAP_SIZE_16M;
    register uint8_t v = ((sizeof(Arg1) * 8) - __builtin_popcountll(Arg1 ^ Arg2));
    uint8_t prev = ATOMIC_GET(feedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(feedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(feedback->pidFeedbackCmp[my_thread_no], v - prev);
    }
}

/*
 * Cases[0] is number of comparison entries
 * Cases[1] is length of Val in bits
 */
ATTRIBUTE_X86_REQUIRE_SSE42 void __sanitizer_cov_trace_switch(uint64_t Val, uint64_t * Cases)
{
    for (uint64_t i = 0; i < Cases[0]; i++) {
        uintptr_t pos = ((uintptr_t) __builtin_return_address(0) + i) % _HF_PERF_BITMAP_SIZE_16M;
        uint8_t v = (uint8_t) Cases[1] - __builtin_popcountll(Val ^ Cases[i + 2]);
        uint8_t prev = ATOMIC_GET(feedback->bbMapCmp[pos]);
        if (prev < v) {
            ATOMIC_SET(feedback->bbMapCmp[pos], v);
            ATOMIC_POST_ADD(feedback->pidFeedbackCmp[my_thread_no], v - prev);
        }
    }
}

/*
 * -fsanitize-coverage=trace-pc-guard
 */
ATTRIBUTE_X86_REQUIRE_SSE42 void __sanitizer_cov_trace_pc_guard_init(uint32_t * start,
                                                                     uint32_t * stop)
{
    static bool inited = false;
    if (inited == true) {
        return;
    }
    inited = true;
    uint32_t n = 1U;
    for (uint32_t * x = start; x < stop; x++, n++) {
        if (n >= _HF_PC_GUARD_MAX) {
            fprintf(stderr, "This process has too many PC guards\n");
            exit(1);
        }
        /* If the corresponding PC was already hit, map this specific guard as non-interesting (0) */
        *x = ATOMIC_GET(feedback->pcGuardMap[n]) ? 0U : n;
    }
}

ATTRIBUTE_X86_REQUIRE_SSE42 void __sanitizer_cov_trace_pc_guard(uint32_t * guard)
{
    if (*guard == 0U) {
        return;
    }
    bool prev = ATOMIC_XCHG(feedback->pcGuardMap[*guard], true);
    if (prev == false) {
        ATOMIC_PRE_INC_RELAXED(feedback->pidFeedbackPc[my_thread_no]);
    }
    *guard = 0U;
}
