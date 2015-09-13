#include "common.h"
#include "util.h"
#include "log.h"

#include <string.h>
#include <limits.h>

/* PNG File Format
 * 
 * +-------------------------+
 * | Signature - 8 bytes     |
 * #-------------------------#
 * | Chunk1 length - 4 bytes |
 * #-------------------------#
 * | Chunk1 type - 4 bytes   |
 * #-------------------------#
 * | 13 byte of chunk data   |
 * |  ^ Width      - 4 bytes |
 * |  ^ Height     - 4 bytes |
 * |  ^ Bit depth  - 1 byte  |
 * |  ^ Color type - 1 byte  |
 * |  ^ Cmpr method - 1 byte |
 * |  ^ Fltr method - 1 byte |
 * |  ^ Inrl method - 1 byte |
 * #-------------------------#
 * | CRC - 4 bytes           |
 * |   ^ Chunk type + Data   |
 * #-------------------------#
 * | Chunk2 ...              |
 * +-------------------------+
 */

#define kPNGSIG    8
#define kCHUNKLEN  4
#define kCHUNKTYPE 4
#define kCRC       4
#define kWIDTH     4
#define kHEIGHT    4
#define kBITDEPTH  1
#define kCOLORTYPE 1
#define kCOMPRESS  1
#define kFILTER    1
#define kINTERLACE 1

/*
 * CRC functions from PNG Spec:
 * http://www.w3.org/TR/PNG-CRCAppendix.html
 */

/* Table of CRCs of all 8-bit messages. */
static unsigned long crc_table[256];

/* Flag: has the table been computed? Initially false. */
static int crc_table_computed = 0;

/* Make the table for a fast CRC. */
static void make_crc_table(void)
{
    unsigned long c;

    for (int n = 0; n < 256; n++) {
        c = (unsigned long)n;
        for (int k = 0; k < 8; k++) {
            if (c & 1)
                c = 0xedb88320L ^ (c >> 1);
            else
                c = c >> 1;
        }
        crc_table[n] = c;
    }
    crc_table_computed = 1;
}

/* 
 * Update a running CRC with the bytes buf[0..len-1]--the CRC
 * should be initialized to all 1's, and the transmitted value
 * is the 1's complement of the final running CRC (see the
 * crc() routine below)).
 */
static unsigned long update_crc(unsigned long crc, unsigned char *buf, int len)
{
    unsigned long c = crc;
    if (!crc_table_computed)
        make_crc_table();
    for (int n = 0; n < len; n++)
        c = crc_table[(c ^ buf[n]) & 0xff] ^ (c >> 8);
    return c;
}

/* Return the CRC of the bytes buf[0..len-1]. */
static unsigned long crc(unsigned char *buf, int len)
{
    return update_crc(0xffffffffL, buf, len) ^ 0xffffffffL;
}

static unsigned long readULong(unsigned char *a, int offset, int size)
{
    unsigned int result = 0, shift = 8 * (size - 1);
    for (int i = offset; i < offset + size; i++) {
        result |= a[i] << shift;
        shift -= 8;
    }
    return result;
}

static void writeULong(unsigned char *buf, long offset, int size, unsigned long val)
{
    unsigned long shift = 8 * (size - 1);
    for (long i = offset; i < offset + size; i++) {
        buf[i] = val >> shift;
        shift -= 8;
    }
}

/* Repair DEX CRC */
static void repairPngCRC(uint8_t * buf, off_t fileSz)
{
    unsigned long chunkLen = 0, chunkCRC = 0;

    // Skip PNG file signature
    long curOff = kPNGSIG;

    // Loop chunks
    while (curOff < fileSz) {
        // Chunk length
        chunkLen = readULong(buf, curOff, kCHUNKLEN);
        curOff += kCHUNKLEN;

        // Chunk type
        int crcBegin = curOff;
        curOff += kCHUNKTYPE;

        // CRC
        size_t crcBufLen = (sizeof(unsigned char) * chunkLen) + (sizeof(uint8_t) * kCHUNKTYPE);

        // Overflow check
        if (crcBufLen > LONG_MAX || fileSz - curOff < (long)crcBufLen) {
            LOGMSG(l_DEBUG, "OOB chunk size. Skip CRC repair.");
            return;
        }

        unsigned char crcBuf[crcBufLen];
        memcpy(crcBuf, buf + crcBegin, crcBufLen);
        curOff = crcBegin + crcBufLen;

        // Calculate and update CRC
        chunkCRC = crc(crcBuf, crcBufLen);
        writeULong(buf, curOff, kCRC, chunkCRC);

        curOff += kCRC;
    }
}

/* 
 * Interface functions:
 * 
 * Remember to export defines of implemented callbacks in xxx_Makefile
 * EXTENSION_CFLAGS
 */

/* -D_HF_FILESPREPARSECALLBACK*/
//bool __hf_FilesPreParseCallback(honggfuzz_t * hfuzz)
//{
//
//}

/* -D_HF_MANGLERESIZECALLBACK */
//void __hf_MangleResizeCallback(honggfuzz_t * hfuzz, uint8_t * buf, size_t * bufSz)
//{
//    
//}

/* -D_HF_MANGLECALLBACK */
//void __hf_MangleCallback(honggfuzz_t * hfuzz, uint8_t * buf, size_t bufSz, int rnd_index)
//{
//
//}

/* -D_HF_POSTMANGLECALLBACK */
void __hf_PostMangleCallback(honggfuzz_t * hfuzz, uint8_t * buf, size_t bufSz)
{
    if (hfuzz->flipRate != 0.0)
        repairPngCRC(buf, bufSz);
}
