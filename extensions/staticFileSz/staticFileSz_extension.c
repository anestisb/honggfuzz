#include "common.h"
#include "util.h"
#include "log.h"

/* 
 * Interface functions:
 * 
 * Remember to export defines of implemented callbacks in xxx_Makefile
 * EXTENSION_CFLAGS
 */

/* -D_HF_FILESPREPARSECALLBACK*/

/*
 * PoC method to extract file metadata and store them runtime structure to be
 * available for fuzzing engine at runtime
 */
//bool __hf_FilesPreParseCallback(honggfuzz_t * hfuzz)
//{
//    
//}

/* -D_HF_MANGLERESIZECALLBACK */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
void __hf_MangleResizeCallback(honggfuzz_t * hfuzz, uint8_t * buf, size_t * bufSz)
{
    /*
     * Purpose of this override is to just disable core's default file resize
     * feature during mangling steps. This extensions is mainly for file formats
     * that have strict structure restrictions and require smarter mutations in case
     * size changes.
     */
    return;
}
#pragma GCC diagnostic pop

/* -D_HF_MANGLECALLBACK */
//void __hf_MangleCallback(honggfuzz_t * hfuzz, uint8_t * buf, size_t bufSz, int rnd_index)
//{
//    
//}

/* -D_HF_POSTMANGLECALLBACK */
//void __hf_PostMangleCallback(honggfuzz_t * hfuzz, uint8_t * buf, size_t bufSz)
//{
//    
//}
