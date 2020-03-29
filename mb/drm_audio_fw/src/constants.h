#ifndef SRC_CONSTANTS_H_
#define SRC_CONSTANTS_H_

#include "xil_printf.h"

// shared DDR address
#define SHARED_DDR_BASE (0x20000000 + 0x1CC00000)

// memory constants
#define CHUNK_SZ 16000
#define FIFO_CAP 4096*4

// number of seconds to record/playback
#define PREVIEW_TIME_SEC 30
#define SKIP_TIME_SEC 5

// ADC/DAC sampling rate in Hz
#define AUDIO_SAMPLING_RATE 48000
#define BYTES_PER_SAMP 2
#define PREVIEW_SZ (PREVIEW_TIME_SEC * AUDIO_SAMPLING_RATE * BYTES_PER_SAMP)
#define SKIP_SZ (SKIP_TIME_SEC * AUDIO_SAMPLING_RATE * BYTES_PER_SAMP)

// printing utility
#define MB_PROMPT "MB> "
#define mb_printf(...) xil_printf(MB_PROMPT __VA_ARGS__)

// protocol constants
#define MAX_REGIONS 32
#define REGION_NAME_SZ 64
#define MAX_USERS 64
#define USERNAME_SZ 64
#define MAX_PIN_SZ 64
#define MAX_SONG_SZ (1<<25)
#define MD_SZ 100


// LED colors and controller
struct color {
    u32 r;
    u32 g;
    u32 b;
};


// struct to interpret shared buffer as a query
typedef struct {
    int num_regions;
    int num_users;
    char owner[USERNAME_SZ];
    char regions[MAX_REGIONS * REGION_NAME_SZ];
    char users[MAX_USERS * USERNAME_SZ];
} query;


// simulate array of 64B names without pointer indirection
#define q_region_lookup(q, i) (q.regions + (i * REGION_NAME_SZ))
#define q_user_lookup(q, i) (q.users + (i * USERNAME_SZ))


// struct to interpret drm metadata
// max size = (1 + 1 + 1 + 1) + 32 max regions + 
// 63 max users not including owner + 1 for alignment = 100 B
typedef struct __attribute__((__packed__)) {
    char md_size;
    char owner_id;
    char num_regions;
    char num_users;
    char buf[96]; // make sure we allocate 100 bytes for this struct
} drm_md;

/*
===================================
DRM SONG FILE FORMAT (struct song)
===================================
Graphic not to scale

start
 ____________________________
| WAV file format metadata   |
| (44 bytes)                 |
|____________________________|
| Song metadata keyed Blake3 | ---> use 32-bit
| Hash                       |      metadata key
| (32 bytes)                 |
|____________________________|
| Speck CBC Initialization   |
| Vector                     |
| (16 bytes)                 |
|____________________________|
| int - num of encrypted     |
| audio chunks               |
| (4 bytes)                  |
|____________________________|
| int - encrypted audio len  |
| (4 bytes)                  |
|____________________________|
| DRM Song metadata          |
| (100 bytes)                | ---> struct drm_md
|____________________________|
| encrypted [audio+padding]  | ---> use 32-bit key
| (max of 32 Megabytes       |      Speck 128/256
|  = 2098 16000B chunks      |
|____________________________| ___
| Encrypted Audio Chunk #0   |    |
| + IV keyed Blake3 hash     |    |
| (32 bytes)                 |    |
|____________________________|    |
|            ...             |    |--> max of 2098 hashes
|____________________________|    |    = 64 KB total,
| Encrypted Audio Chunk #n   |    |    use 32-bit chunk
| + IV keyed Blake3 hash     |    |    key
| (32 bytes)                 |    |
|____________________________| ___|
end

MAX DRM FILE SIZE = 
   32 MB song --> (44 + 32 + 16 + 4 + 4 + 100 + 33,554,432 + (2098 * 32)) = 33621768
*/

// struct to interpret shared buffer as a drm song file
// packing values skip over non-relevant WAV metadata
typedef struct __attribute__((__packed__)) {
    // WAV metadata
    char packing1[4];
    u32 file_size;          // size of entire wav file
    char packing2[32];
    u32 wav_size;           // size of file
    // drm song metadata
    char mdHash[32];        // metadata hash
    char iv[16];            // Speck initialization vector
    int numChunks;          // number of encrypted audio chunks
    int encAudioLen;        // length of encrypted audio
    drm_md md;              // song metadata
} song;


// accessors for variable-length file fields
#define get_drm_rids(d) (d.md.buf)
#define get_drm_uids(d) (d.md.buf + d.md.num_regions)
#define get_drm_song(d) ((char *)(&d.md) + MD_SZ)
#define get_drm_hash(d, i) (get_drm_song(d) + d.encAudioLen + (i*32))


// shared buffer values
enum commands { QUERY_PLAYER, QUERY_SONG, LOGIN, LOGOUT, SHARE, PLAY, STOP, DIGITAL_OUT, PAUSE, RESTART, FF, RW, EXIT };
enum states   { STOPPED, WORKING, PLAYING, PAUSED };


// struct to interpret shared command channel
typedef volatile struct __attribute__((__packed__)) {
    char cmd;                   // from commands enum
    char drm_state;             // from states enum
    char padding[2];            // unused
    char username[USERNAME_SZ]; // stores logged in or attempted username
    char pin[MAX_PIN_SZ];       // stores logged in or attempted pin

    // shared buffer is either a drm song or a query
    union {
        song song;
        query query;
    };
} cmd_channel;


// local store for drm metadata
typedef struct {
    u8 md_size;
    u8 owner_id;
    u8 num_regions;
    u8 rids[MAX_REGIONS];
    u8 num_users;
    u8 uids[MAX_USERS];
} song_md;


// store of internal state
typedef struct {
    char logged_in;                 // whether or not a user is logged on
    u8 uid;                         // logged on user id
    char username[USERNAME_SZ];     // logged on username
    char pin[MAX_PIN_SZ];           // logged on pin
    song_md song_md;                // current song metadata
    char speckKey[64];              // base64 decoded Speck key
    char mdKey[64];                 // base64 decoded metadata key
    char chunkKey[64];              // base64 decoded encrypted audio chunk key
    u64 rk[64];                     // round keys for Speck
} internal_state;


#endif /* SRC_CONSTANTS_H_ */
