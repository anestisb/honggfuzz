#include "common.h"
#include "util.h"
#include "log.h"

#include <string.h>
#include <zlib.h>

#define DEX_MAGIC  "dex"
#define ODEX_MAGIC "dey"
#define API_LE_13  "035"
#define API_GE_14  "036"
#define SHA1Len    20

typedef struct __attribute__((packed)) {
    char dex[3];
    char nl[1];
    char ver[3];
    char zero[1];
} dexMagic;

typedef struct __attribute__((packed)) {
    dexMagic magic;
    uint32_t checksum;
    unsigned char signature[SHA1Len];
    uint32_t fileSize;
    uint32_t headerSize;
    uint32_t endianTag;
    uint32_t linkSize;
    uint32_t linkOff;
    uint32_t mapOff;
    uint32_t stringIdsSize;
    uint32_t stringIdsOff;
    uint32_t typeIdsSize;
    uint32_t typeIdsOff;
    uint32_t protoIdsSize;
    uint32_t protoIdsOff;
    uint32_t fieldIdsSize;
    uint32_t fieldIdsOff;
    uint32_t methodIdsSize;
    uint32_t methodIdsOff;
    uint32_t classDefsSize;
    uint32_t classDefsOff;
    uint32_t dataSize;
    uint32_t dataOff;
} dexHeader;

/* Repair DEX CRC */
static void repairDexCRC(uint8_t *buf, off_t fileSz)
{
    uint32_t adler_checksum = adler32(0L, Z_NULL, 0);
    const uint8_t non_sum = sizeof(dexMagic) + sizeof(uint32_t);
    const uint8_t *non_sum_ptr = (const uint8_t*)buf + non_sum;
    adler_checksum = adler32(adler_checksum, non_sum_ptr, fileSz - non_sum);
    memcpy(buf + sizeof(dexMagic), &adler_checksum, sizeof(uint32_t));
    LOGMSG(l_DEBUG, "CRC repaired (0x%08X)", adler_checksum);
}

/* 
 * Interface functions:
 * 
 * Remember to export defines of implemented callbacks in xxx_Makefile
 * EXTENSION_CFLAGS
 */

/* -D_HF_MANGLERESIZECALLBACK */
//void __hf_MangleResizeCallback(honggfuzz_t * hfuzz, uint8_t * buf, size_t * bufSz)
//{
//    
//}

/* -D_HF_MANGLECALLBACK */
void __hf_MangleCallback(honggfuzz_t * hfuzz, uint8_t * buf, size_t bufSz)
{
    // No mangling, just return
    if (hfuzz->flipRate == 0.0L) {
        return;
    }

    // Ensure at least 1 change rate > 0.0
    uint64_t changesCnt = bufSz * hfuzz->flipRate;
    if (changesCnt == 0ULL) {
        changesCnt = 1;
    }
    changesCnt = util_rndGet(1, changesCnt);

    // Exclude DEX header & trailing MapList from mangling
    const dexHeader *pDexHeader = (const dexHeader*)buf;
    uint32_t start = sizeof(dexHeader);
    uint32_t end = pDexHeader->mapOff;

    for (uint64_t x = 0; x < changesCnt; x++) {
        size_t offset = util_rndGet(start, end - 1);
        // byte level mangling
        buf[offset] = (uint8_t)util_rndGet(0, 255);
    }
}

/* -D_HF_POSTMANGLECALLBACK */
void __hf_PostMangleCallback(honggfuzz_t * hfuzz, uint8_t * buf, size_t bufSz)
{
    if (hfuzz->flipRate != 0.0)
        repairDexCRC(buf, bufSz);
}
