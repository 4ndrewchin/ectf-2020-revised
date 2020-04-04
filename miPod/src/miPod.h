/*
 * miPod.h
 *
 *  Created on: Jan 9, 2020
 *      Author: ectf
 */

#ifndef SRC_MIPOD_H_
#define SRC_MIPOD_H_


// miPod constants
#define USR_CMD_SZ 128

// protocol constants
#define MAX_REGIONS 32
#define REGION_NAME_SZ 64
#define MAX_USERS 64
#define USERNAME_SZ 64
#define MAX_PIN_SZ 64
//#define MAX_SONG_SZ (1<<25)
#define MD_SZ 100
#define MAX_SONG_SZ 33621768 // actual space needed for 32 MB song with our file format

// printing utility
#define MP_PROMPT "mP> "
#define mp_printf(...) printf(MP_PROMPT __VA_ARGS__)

#define USER_PROMPT "miPod %s# "
#define print_prompt() printf(USER_PROMPT, "")
#define print_prompt_msg(...) printf(USER_PROMPT, __VA_ARGS__)


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


/* see '/ectf/mb/drm_audio_fw/src/constants.h' for detailed info on
  DRM audio file format */

// struct to interpret shared buffer as a drm song file
// packing values skip over non-relevant WAV metadata
typedef struct __attribute__((__packed__)) {
    // WAV metadata
    char packing1[4];
    unsigned int file_size; // size of entire wav file
    char packing2[32];
    unsigned int wav_size;  // size of file
    // drm song metadata
    char mdHash[32];        // metadata hash
    char iv[16];            // Speck initialization vector
    int numChunks;          // number of encrypted audio chunks
    int encAudioLen;        // length of encrypted audio
    drm_md md;              // song metadata
} song;


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
        char buf[MAX_SONG_SZ]; // sets correct size of cmd_channel for allocation
    };
} cmd_channel;

#endif /* SRC_MIPOD_H_ */