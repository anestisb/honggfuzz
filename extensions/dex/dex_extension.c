#include "common.h"
#include "util.h"
#include "log.h"

#include <string.h>
#include <zlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdlib.h>

#define DEX_MAGIC  "dex"
#define ODEX_MAGIC "dey"
#define API_LE_13  "035"
#define API_GE_14  "036"
#define SHA1Len    20

typedef struct __attribute__ ((packed)) {
    char dex[3];
    char nl[1];
    char ver[3];
    char zero[1];
} dexMagic;

typedef struct __attribute__ ((packed)) {
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

/*
 * Verify if valid DEX file magic number
 */
static inline bool isValidDexMagic(const dexHeader *pDexHeader)
{
    /* Validate DEX magic number */
    if (((memcmp(pDexHeader->magic.dex,  DEX_MAGIC, 3) != 0)    && // Check if DEX
         (memcmp(pDexHeader->magic.dex, ODEX_MAGIC, 3) != 0))   || // Check if ODEX
        (memcmp(pDexHeader->magic.nl,   "\n",      1) != 0)     || // Check for newline
        ((memcmp(pDexHeader->magic.ver, API_LE_13, 3) != 0) &&     // Check for API SDK <= 13
         (memcmp(pDexHeader->magic.ver, API_GE_14, 3) != 0))    || // Check for API SDK >= 14
        (memcmp(pDexHeader->magic.zero, "\0",      1) != 0)) {     // Check for zero
        
        return false;
    }
    else return true;
}

/* Repair DEX CRC */
static void repairDexCRC(uint8_t * buf, off_t fileSz)
{
    uint32_t adler_checksum = adler32(0L, Z_NULL, 0);
    const uint8_t non_sum = sizeof(dexMagic) + sizeof(uint32_t);
    const uint8_t *non_sum_ptr = (const uint8_t *)buf + non_sum;
    adler_checksum = adler32(adler_checksum, non_sum_ptr, fileSz - non_sum);
    memcpy(buf + sizeof(dexMagic), &adler_checksum, sizeof(uint32_t));
    LOGMSG(l_DEBUG, "CRC repaired (0x%08X)", adler_checksum);
}

static uint8_t* mapFileToRead(char *fileName, off_t *fileSz, int *fd)
{
    if ((*fd = open(fileName, O_RDONLY)) == -1) {
        LOGMSG_P(l_ERROR, "Couldn't open() '%s' file in R/O mode", fileName);
        return NULL;
    }

    struct stat st;
    if (fstat(*fd, &st) == -1) {
        LOGMSG_P(l_ERROR, "Couldn't stat() the '%s' file", fileName);
        close(*fd);
        return NULL;
    }

    uint8_t *buf;
    if ((buf = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, *fd, 0)) == MAP_FAILED) {
        LOGMSG_P(l_ERROR, "Couldn't mmap() the '%s' file", fileName);
        close(*fd);
        return NULL;
    }

    *fileSz = st.st_size;
    return buf;
}

/*
 * Runtime data structure
 */
typedef struct __attribute__ ((packed)) {
    uint32_t crc;
    uint32_t size;
    uint32_t dataSize;
} fileInfo;

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
bool __hf_FilesPreParseCallback(honggfuzz_t * hfuzz)
{
    LOGMSG(l_DEBUG, "Pre-parsing input corpus");

    hfuzz->userData = malloc(hfuzz->fileCnt * sizeof(fileInfo*));
    if (!hfuzz->userData) {
        LOGMSG_P(l_ERROR, "malloc() failed");
        return false;
    }

    for (int i = 0; i < hfuzz->fileCnt; i++) {
        off_t fileSz = -1;
        int srcFd = -1;
        uint8_t *buf = NULL;
        bool hasError = false;

        buf = mapFileToRead(hfuzz->files[i], &fileSz, &srcFd);
        if (buf == NULL) {
            LOGMSG(l_ERROR, "'%s' open and map in R/O mode failed", hfuzz->files[i]);
            hasError = true;
            goto bail;
        }

        const dexHeader *pDexHeader = (const dexHeader*)buf;

        /* Validate DEX magic number */
        if (!isValidDexMagic(pDexHeader)) {
            LOGMSG(l_ERROR, "Invalid DEX magic number");
            hasError = true;
            goto bail;
        }

        hfuzz->userData[i] = malloc(sizeof(fileInfo));
        fileInfo *pFileInfo = (fileInfo*)hfuzz->userData[i];

        pFileInfo->crc = pDexHeader->checksum;
        pFileInfo->size = pDexHeader->fileSize;
        pFileInfo->dataSize = pDexHeader->dataSize;

bail:
        if (!buf) {
            munmap(buf, fileSz);
            buf = NULL;
            close(srcFd);
            srcFd = -1;
        }

        /* Check for errors in current file */
        if (hasError) {
            LOGMSG(l_ERROR, "Failed to prepare %s", hfuzz->files[i]);
            return false;
        }
    }
    return true;
}

/* -D_HF_MANGLERESIZECALLBACK */
//void __hf_MangleResizeCallback(honggfuzz_t * hfuzz, uint8_t * buf, size_t * bufSz)
//{
//    
//}

/* -D_HF_MANGLECALLBACK */
void __hf_MangleCallback(honggfuzz_t * hfuzz, uint8_t * buf, size_t bufSz, int rnd_index)
{
    // No mangling, just return
    if (hfuzz->flipRate == 0.0L) {
        return;
    }

    // If data section > 50k, double the rate
    double dexFlipRate = hfuzz->flipRate;
    fileInfo *pFileInfo = (fileInfo*)hfuzz->userData[rnd_index];
    if (pFileInfo->dataSize > 51200) {
        dexFlipRate = 2 * dexFlipRate;
    }

    // Ensure at least 1 change rate > 0.0
    uint64_t changesCnt = bufSz * dexFlipRate;
    if (changesCnt == 0ULL) {
        changesCnt = 1;
    }
    changesCnt = util_rndGet(1, changesCnt);

    // Exclude DEX header & trailing MapList from mangling
    const dexHeader *pDexHeader = (const dexHeader *)buf;
    uint32_t start = sizeof(dexHeader);
    uint32_t end = pDexHeader->mapOff;

    for (uint64_t x = 0; x < changesCnt; x++) {
        size_t offset = util_rndGet(start, end - 1);
        // byte level mangling
        buf[offset] = (uint8_t) util_rndGet(0, 255);
    }
}

/* -D_HF_POSTMANGLECALLBACK */
void __hf_PostMangleCallback(honggfuzz_t * hfuzz, uint8_t * buf, size_t bufSz)
{
    if (hfuzz->flipRate != 0.0)
        repairDexCRC(buf, bufSz);
}
