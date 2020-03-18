/*
 * eCTF Collegiate 2020 MicroBlaze Example Code
 * Audio Digital Rights Management
 */

#include <stdio.h>
#include "platform.h"
#include "xparameters.h"
#include "xil_exception.h"
#include "xstatus.h"
#include "xaxidma.h"
#include "xil_mem.h"
#include "util.h"
#include "secrets.h"
#include "xintc.h"
#include "constants.h"
#include "sleep.h"
#include "wolfssl/wolfcrypt/hash.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/coding.h"
#include "wolfssl/wolfcrypt/wc_encrypt.h"
#include "wolfssl/wolfcrypt/hmac.h"


//////////////////////// GLOBALS ////////////////////////


// audio DMA access
static XAxiDma sAxiDma;

// LED colors and controller
u32 *led = (u32*) XPAR_RGB_PWM_0_PWM_AXI_BASEADDR;
const struct color RED =    {0x01ff, 0x0000, 0x0000};
const struct color YELLOW = {0x01ff, 0x01ff, 0x0000};
const struct color GREEN =  {0x0000, 0x01ff, 0x0000};
const struct color BLUE =   {0x0000, 0x0000, 0x01ff};

// change states
#define change_state(state, color) c->drm_state = state; setLED(led, color);
#define set_stopped() change_state(STOPPED, RED)
#define set_working() change_state(WORKING, YELLOW)
#define set_playing() change_state(PLAYING, GREEN)
#define set_paused()  change_state(PAUSED, BLUE)

// shared command channel -- read/write for both PS and PL
volatile cmd_channel *c = (cmd_channel*)SHARED_DDR_BASE;

// internal state store
internal_state s;


//////////////////////// INTERRUPT HANDLING ////////////////////////


// shared variable between main thread and interrupt processing thread
volatile static int InterruptProcessed = FALSE;
static XIntc InterruptController;

void myISR(void) {
    InterruptProcessed = TRUE;
}


//////////////////////// UTILITY FUNCTIONS ////////////////////////


// returns whether an rid has been provisioned
int is_provisioned_rid(char rid) {
    for (int i = 0; i < NUM_PROVISIONED_REGIONS; i++) {
        if (rid == PROVISIONED_RIDS[i]) {
            return TRUE;
        }
    }
    return FALSE;
}

// looks up the region name corresponding to the rid
int rid_to_region_name(char rid, char **region_name, int provisioned_only) {
    for (int i = 0; i < NUM_REGIONS; i++) {
        if (rid == REGION_IDS[i] &&
            (!provisioned_only || is_provisioned_rid(rid))) {
            *region_name = (char *)REGION_NAMES[i];
            return TRUE;
        }
    }

    mb_printf("Could not find region ID '%d'\r\n", rid);
    *region_name = "<unknown region>";
    return FALSE;
}


// looks up the rid corresponding to the region name
/*int region_name_to_rid(char *region_name, char *rid, int provisioned_only) {
    for (int i = 0; i < NUM_REGIONS; i++) {
        if (!strcmp(region_name, REGION_NAMES[i]) &&
            (!provisioned_only || is_provisioned_rid(REGION_IDS[i]))) {
            *rid = REGION_IDS[i];
            return TRUE;
        }
    }

    mb_printf("Could not find region name '%s'\r\n", region_name);
    *rid = -1;
    return FALSE;
}*/


// returns whether a uid has been provisioned
int is_provisioned_uid(char uid) {
    for (int i = 0; i < NUM_PROVISIONED_USERS; i++) {
        if (uid == PROVISIONED_UIDS[i]) {
            return TRUE;
        }
    }
    return FALSE;
}


// looks up the username corresponding to the uid
int uid_to_username(char uid, char **username, int provisioned_only) {
    for (int i = 0; i < NUM_USERS; i++) {
        if (uid == USER_IDS[i] &&
            (!provisioned_only || is_provisioned_uid(uid))) {
            *username = (char *)USERNAMES[i];
            return TRUE;
        }
    }

    mb_printf("Could not find uid '%d'\r\n", uid);
    *username = "<unknown user>";
    return FALSE;
}


// looks up the uid corresponding to the username
int username_to_uid(char *username, char *uid, int provisioned_only) {
    for (int i = 0; i < NUM_USERS; i++) {
        if (!strcmp(username, USERNAMES[USER_IDS[i]]) &&
            (!provisioned_only || is_provisioned_uid(USER_IDS[i]))) {
            *uid = USER_IDS[i];
            return TRUE;
        }
    }

    mb_printf("Could not find username '%s'\r\n", username);
    *uid = -1;
    return FALSE;
}


// loads the song metadata in the shared buffer into the local struct
void load_song_md() {
    s.song_md.md_size = c->song.md.md_size;
    s.song_md.owner_id = c->song.md.owner_id;
    s.song_md.num_regions = c->song.md.num_regions;
    s.song_md.num_users = c->song.md.num_users;
    memcpy(s.song_md.rids, (void *)get_drm_rids(c->song), s.song_md.num_regions);
    memcpy(s.song_md.uids, (void *)get_drm_uids(c->song), s.song_md.num_users);
}


// checks if the song loaded into the shared buffer is locked for the current user
int is_locked() {
    int locked = TRUE;

    // check for authorized user
    if (!s.logged_in) {
        mb_printf("No user logged in");
    } else {
        load_song_md();

        // check if user is authorized to play song
        if (s.uid == s.song_md.owner_id) {
            locked = FALSE;
        } else {
            for (int i = 0; i < NUM_PROVISIONED_USERS && locked; i++) {
                if (s.uid == s.song_md.uids[i]) {
                    locked = FALSE;
                }
            }
        }

        if (locked) {
            mb_printf("User '%s' does not have access to this song", s.username);
            return locked;
        }
        mb_printf("User '%s' has access to this song", s.username);
        locked = TRUE; // reset lock for region check

        // search for region match
        for (int i = 0; i < s.song_md.num_regions; i++) {
            for (int j = 0; j < (u8)NUM_PROVISIONED_REGIONS; j++) {
                if (PROVISIONED_RIDS[j] == s.song_md.rids[i]) {
                    locked = FALSE;
                }
            }
        }

        if (!locked) {
            mb_printf("Region Match. Full Song can be accessed. Unlocking...");
        } else {
            mb_printf("Invalid region");
        }
    }
    return locked;
}


/* copy the local song metadata into buf in the correct format
 * returns the size of the metadata in buf (including the metadata size field)
 * song metadata should be loaded before call
 */
/*int gen_song_md(char *buf) {
    buf[0] = ((5 + s.song_md.num_regions + s.song_md.num_users) / 2) * 2; // account for parity
    buf[1] = s.song_md.owner_id;
    buf[2] = s.song_md.num_regions;
    buf[3] = s.song_md.num_users;
    memcpy(buf + 4, s.song_md.rids, s.song_md.num_regions);
    memcpy(buf + 4 + s.song_md.num_regions, s.song_md.uids, s.song_md.num_users);

    return buf[0];
}*/


// takes the base64 encoded cryptographic keys from the secrets header and
// decodes them for use
// copy decoded keys into local internal state
// return 0 on success, -1 otherwise
int init_cryptkeys() {
    word32 outLen = b64AES_KEY_SZ;
    if (Base64_Decode((void *)AES_KEY, (word32)b64AES_KEY_SZ, (void *)s.aesKey, &outLen) != 0) {
        return -1;
    }
    outLen = b64HMAC_MD_KEY_SZ;
    if (Base64_Decode((void *)HMAC_MD_KEY, (word32)b64HMAC_MD_KEY_SZ, (void *)s.hmacMdKey, &outLen) != 0) {
        return -1;
    }
    outLen = b64HMAC_CHUNK_KEY_SZ;
    if (Base64_Decode((void *)HMAC_CHUNK_KEY, (word32)b64HMAC_CHUNK_KEY_SZ, (void *)s.hmacChunkKey, &outLen) != 0) {
        return -1;
    }
    return 0;
}

/* verify song metadata using the HMAC
 * returns 0 on success, -1 otherwise
 */
int verify_song() {
    char mdHmac[HMAC_SZ];
    memcpy(mdHmac, (void *)(c->song.mdHmac), HMAC_SZ);
    u32 all_md_len = AES_BLK_SZ + sizeof(int)*2 + MD_SZ;

    mb_printf("Verifying Audio File...");
    char* data[1];
    data[0] = c->song.iv;
    int dataLens[1];
    dataLens[0] = all_md_len;
    if (verify_hmac(s.hmacMdKey, HMAC_MD_KEY_SZ, 1, data, dataLens, mdHmac) != 0) {
        return -1;
    }
    mb_printf("Successfully Verified Audio File");
    return 0;
}

/* compute HMAC using data and key and compare to DRM HMAC
 * return 0 on success, -1 otherwise
 *
 * key      : HMAC key
 * keyLen   : HMAC key length
 * args     : number of different data to update hmac object with
 * data     : array of char pointers (data) to create HMAC with
 * dataLens : length of each data to be included in hash
 * drmHmac  : HMAC to compare computed HMAC to
 */
int verify_hmac(char* key, int keyLen, int args, char* data[], int dataLens[], char* orig) {
    if (key == NULL || keyLen <= 0 || args <= 0 || data == NULL || dataLens == NULL || orig == NULL) {
        return -1;
    }
    Hmac hmac;
    int total = 0;
    if (wc_HmacSetKey(&hmac, SHA256, key, keyLen) != 0) {
        return -1;
    }
    for (int i = 0; i < args; i++) {
        if (wc_HmacUpdate(&hmac, (void *)data[i], dataLens[i]) != 0) {
            return -1;
        }
        total += dataLens[i];
    }
    char hash[total];
    if (wc_HmacFinal(&hmac, hash) != 0) {
        return -1;
    }
    if (memcmp(hash, (void *)orig, HMAC_SZ) != 0) {
        return -1;
    }
    return 0;
}

/* create a new metadata HMAC from [AES IV + num chunks + enc audio len + song MD]
 * return 0 on success, -1 otherwise
 * 
 * out      : pointer to buffer to store created hash
 * new_md   : pointer to newly generated metadata
 */
int create_hmac(char* out, char* new_md) {
    if (out == NULL || new_md == NULL) {
        return -1;
    }
    Hmac hmac;
    if (wc_HmacSetKey(&hmac, SHA256, s.hmacMdKey, HMAC_MD_KEY_SZ) != 0) {
        return -1;
    }

    char* data[4] = {c->song.iv, c->song.iv+AES_BLK_SZ, c->song.iv+AES_BLK_SZ+sizeof(int), new_md};
    int lens[4] = {AES_BLK_SZ, sizeof(int), sizeof(int), MD_SZ};

    for (int i = 0; i < 4; i++) {
        if (wc_HmacUpdate(&hmac, (void *)data[i], lens[i]) != 0) {
            return -1;
        }
    }
    if (wc_HmacFinal(&hmac, out) != 0) {
        return -1;
    }
    return 0;
}


//////////////////////// COMMAND FUNCTIONS ////////////////////////


// attempt to log in to the credentials in the shared buffer
void login() {
    // first, copy attempted username and pin into local internal_state
    memcpy((void*)s.username, (void*)c->username, USERNAME_SZ);
    memcpy((void*)s.pin, (void*)c->pin, MAX_PIN_SZ);

    if (s.logged_in) {
        mb_printf("Already logged in. Please log out first.\r\n");
    } else {
        for (int i = 0; i < NUM_PROVISIONED_USERS; i++) {
            // search for matching username
            if (!strcmp((void*)s.username, USERNAMES[PROVISIONED_UIDS[i]])) {
                // check if pin matches
                if (!strcmp((void*)s.pin, PROVISIONED_PINS[i])) {
                    //update state
                    s.logged_in = 1;
                    s.uid = PROVISIONED_UIDS[i];
                    mb_printf("Logged in for user '%s'\r\n", (void *)s.username);
                    // clear shared memory
                    memset((void*)c->username, 0, USERNAME_SZ);
                    memset((void*)c->pin, 0, MAX_PIN_SZ);
                    return;
                } else {
                    break;
                }
            }
        }
        // reject login attempt and wait 5 seconds
        mb_printf("Login failed\r\n");
        usleep(5000000);
    }
}


// attempt to log out
void logout() {
    if (s.logged_in) {
        mb_printf("Logging out...\r\n");
        s.logged_in = 0;
        memset((void*)c->username, 0, USERNAME_SZ);
        memset((void*)c->pin, 0, MAX_PIN_SZ);
        s.uid = 0;
    } else {
        mb_printf("Not logged in\r\n");
    }
}


// handles a request to query the player's metadata
void query_player() {
    c->query.num_regions = NUM_PROVISIONED_REGIONS;
    c->query.num_users = NUM_PROVISIONED_USERS;

    for (int i = 0; i < NUM_PROVISIONED_REGIONS; i++) {
        strcpy((char *)q_region_lookup(c->query, i), REGION_NAMES[PROVISIONED_RIDS[i]]);
    }

    for (int i = 0; i < NUM_PROVISIONED_USERS; i++) {
        strcpy((char *)q_user_lookup(c->query, i), USERNAMES[i]);
    }
}


// handles a request to query song metadata
void query_song() {
    char *name;

    // verify and load song md
    if (verify_song() != 0) {
        mb_printf("Cannot query song\r\n");
        c->query.num_regions = 0;
        return;
    }
    load_song_md();
    memset((void *)&c->query, 0, sizeof(query));

    c->query.num_regions = s.song_md.num_regions;
    c->query.num_users = s.song_md.num_users;

    // copy owner name
    uid_to_username(s.song_md.owner_id, &name, FALSE);
    strcpy((char *)c->query.owner, name);

    // copy region names
    for (int i = 0; i < s.song_md.num_regions; i++) {
        rid_to_region_name(s.song_md.rids[i], &name, FALSE);
        strcpy((char *)q_region_lookup(c->query, i), name);
    }

    // copy authorized uid names
    for (int i = 0; i < s.song_md.num_users; i++) {
        uid_to_username(s.song_md.uids[i], &name, FALSE);
        strcpy((char *)q_user_lookup(c->query, i), name);
    }
}


// add a user to the song's list of users
void share_song() {
    char uid;

    // reject non-owner attempts to share
    if (!s.logged_in) {
        mb_printf("No user is logged in. Cannot share song\r\n");
        c->song.wav_size = 0;
        return;
    }
    if (verify_song() != 0) {
        mb_printf("Cannot share song\r\n");
        c->song.wav_size = 0;
        return;
    }
    load_song_md();
    if (s.uid != s.song_md.owner_id) {
        mb_printf("User '%s' is not song's owner. Cannot share song\r\n", s.username);
        c->song.wav_size = 0;
        return;
    } else if (!username_to_uid((char *)c->username, &uid, TRUE)) {
        mb_printf("Username not found\r\n");
        c->song.wav_size = 0;
        return;
    }

    // only allow MAX_USERS shares -- much simpler alternative to hash map
    // a song owner may share a song with one user 64 times and
    // prevent it from being shared with anybody else; however,
    // we can no longer overflow s.song_md.num_users
    if (s.song_md.num_users >= MAX_USERS) {
        mb_printf("Cannot share song\r\n");
        c->song.wav_size = 0;
        return;
    }
    
    // update song metadata
    s.song_md.md_size++;
    s.song_md.uids[s.song_md.num_users++] = uid;
    c->song.md.md_size++;
    c->song.md.buf[s.song_md.num_regions + c->song.md.num_users++] = uid;

    // update metadata HMAC
    char newMd[MD_SZ];
    memcpy(newMd, (char*)&c->song.md, MD_SZ);
    char newHmac[HMAC_SZ];
    if (create_hmac(newHmac, newMd) != 0) {
        mb_printf("Cannot share song\r\n");
        c->song.wav_size = 0;
        return;
    }
    memcpy(c->song.mdHmac, newHmac, HMAC_SZ);

    mb_printf("Shared song with '%s'\r\n", c->username);
}


// plays a song and looks for play-time commands
void play_song() {
    u32 counter = 0, cp_num, cp_xfil_cnt, offset, dma_cnt, lenAudio, *fifo_fill;
    int ret, rem; // we need rem to be signed so we can check if under 0
    char mdHmac[HMAC_SZ];
    memcpy(mdHmac, (void *)(c->song.mdHmac), HMAC_SZ);

    mb_printf("Reading Audio File...");
    // verify and load song md
    if (verify_song() != 0) {
        mb_printf("Failed to play audio");
        return;
    }
    load_song_md();

    lenAudio = c->song.encAudioLen;
    unsigned int nchunks = c->song.numChunks;

    // truncate song if locked
    if (lenAudio > PREVIEW_SZ && is_locked()) {
        lenAudio = PREVIEW_SZ;
        mb_printf("Song is locked.  Playing only %ds = %dB\r\n",
                   PREVIEW_TIME_SEC, PREVIEW_SZ);
    } else {
        mb_printf("Song is unlocked. Playing full song\r\n");
    }

    int firstChunk = TRUE; // whether we are operating on the first chunk of the audio
    char iv[AES_BLK_SZ];
    memcpy(iv, (void *)c->song.iv, AES_BLK_SZ);
    // stack size MUST be increased to fit this (default is 1KB)
    char plainChunk[CHUNK_SZ]; // current decrypted chunk
    int chunknum = 0;

    rem = lenAudio;
    fifo_fill = (u32 *)XPAR_FIFO_COUNT_AXI_GPIO_0_BASEADDR;
    
    char paused = FALSE;

    // write entire file to two-block codec fifo
    // writes to one block while the other is being played
    set_playing();
    while(rem > 0) {
        // check for interrupt to stop playback
        while (InterruptProcessed) {
            InterruptProcessed = FALSE;

            switch (c->cmd) {
            case PAUSE:
                mb_printf("Pausing... \r\n");
                set_paused();
                paused = TRUE;
                while (!InterruptProcessed) continue; // wait for interrupt
                break;
            case PLAY:
                mb_printf("Resuming... \r\n");
                set_playing();
                break;
            case STOP:
                mb_printf("Stopping playback...");
                return;
            case RESTART:
                mb_printf("Restarting song... \r\n");
                usleep(100000); // prevent choppy audio on restart
                chunknum = 0;
                rem = lenAudio; // reset song counter
                firstChunk = TRUE;
                set_playing();
                break;
            case FF:
                mb_printf("Fast forwarding 5 seconds... \r\n");
                paused = TRUE;
                rem -= SKIP_SZ;
                if (rem <= 0) {
                    return;
                }
                chunknum += (SKIP_SZ / CHUNK_SZ);
                // TODO: can we overshoot chunknum? i.e. find ourselves in
                // a scenario where last chunk is not unpadded?
                break;
            case RW:
                paused = TRUE;
                mb_printf("Rewinding 5 seconds... \r\n");
                rem += SKIP_SZ;
                if (rem > lenAudio) {
                    usleep(100000); // prevent choppy audio on restart
                    rem = lenAudio;
                    firstChunk = TRUE;
                }
                chunknum -= (SKIP_SZ / CHUNK_SZ);
                if (chunknum < 0) {
                    chunknum = 0;
                }
            default:
                break;
            }
        }

        // calculate write size and offset
        cp_num = (rem > CHUNK_SZ) ? CHUNK_SZ : rem;
        offset = (counter++ % 2 == 0) ? 0 : CHUNK_SZ;

        // if first chunk, grab the IV for decryption
        // if not the first chunk, use the most previous block as the IV
        if (firstChunk) {
            firstChunk = FALSE;
        } else {
            memcpy(iv, (void *)(get_drm_song(c->song) + lenAudio - rem - AES_BLK_SZ), AES_BLK_SZ);
        }

        // verify chunk using HMAC
        // TODO: why does audio skip when this is uncommented?
        //       Initially I thought it was a speed issue, and indeed when I replace this
        //       with sleep(), it also messed up the audio. However, upon inspecting the 
        //       fifo values (*fifo_fill, cp_xfil_cnt, dma_cnt) during runtime, I noticed
        //       that the values oscillate between weird values. You can uncomment the
        //       mb_printf()'s in the fifo/DMA loop below
        /*char* data2[2];
        data2[0] = get_drm_song(c->song) + lenAudio - rem;
        data2[1] = c->song.iv;
        int dataLens2[2];
        dataLens2[0] = cp_num;
        dataLens2[1] = AES_BLK_SZ;
        if (verify_hmac(s.hmacChunkKey, HMAC_CHUNK_KEY_SZ, 2, data2, dataLens2, get_drm_hmac(c->song, chunknum++)) != 0) {
            mb_printf("Failed to play audio");
            return;
        }*/
        chunknum++; // DELETE THIS LINE WHEN UNCOMMENTING ABOVE

        // decrypt chunk
        ret = wc_AesCbcDecryptWithKey((byte*)plainChunk, (void*)(get_drm_song(c->song) + lenAudio - rem), cp_num, (byte*)s.aesKey, (word32)AES_KEY_SZ, (byte*)iv);
        if (ret != 0) {
            mb_printf("Failed to play audio");
            return;
        }

        // if last chunk unpad using PKCS#7
        if (chunknum == nchunks) {
            unsigned int pads = (unsigned int*)plainChunk[cp_num-1];
            if (pads == 0 || pads > 16) {
                mb_printf("Failed to play audio");
                return;
            }
            for (int i = 1; i <= pads; i++) {
                unsigned int bite = (unsigned int*)plainChunk[cp_num-i];
                if (bite != pads) {
                    mb_printf("Failed to play audio");
                    return;
                }
            }
            // padding is valid
            cp_num -= pads;
            rem -= pads;
        }

        // do first mem cpy here into DMA BRAM
        Xil_MemCpy((void *)(XPAR_MB_DMA_AXI_BRAM_CTRL_0_S_AXI_BASEADDR + offset),
                   (void*)plainChunk,
                   (u32)(cp_num));
        
        cp_xfil_cnt = cp_num;

        while (cp_xfil_cnt > 0) {
            //mb_printf("rem %u, cp_num %u, cp_xfil_cnt %u offset %u, fifofill %u", rem, cp_num, cp_xfil_cnt, offset, *fifo_fill);
            // polling while loop to wait for DMA to be ready
            // DMA must run first for this to yield the proper state
            // rem != lenAudio checks for first run
            while (XAxiDma_Busy(&sAxiDma, XAXIDMA_DMA_TO_DEVICE)
                   && rem != lenAudio && *fifo_fill < (FIFO_CAP - 32));

            // do DMA
            dma_cnt = (FIFO_CAP - *fifo_fill > cp_xfil_cnt)
                      ? FIFO_CAP - *fifo_fill
                      : cp_xfil_cnt;
            // prevents choppy audio when resuming from pause
            if (paused) {
                dma_cnt = cp_xfil_cnt;
                paused = FALSE;
            }
            //mb_printf("%u", dma_cnt);
            fnAudioPlay(sAxiDma, offset, dma_cnt);
            cp_xfil_cnt -= dma_cnt;
        }

        rem -= cp_num;
    }
}


// removes DRM data from song for digital out
void digital_out() {
    if (verify_song() != 0) {
        mb_printf("Cannot dump song\r\n");
        c->song.wav_size = 0;
        return;
    }
    load_song_md();

    // remove metadata size from file and chunk sizes
    unsigned int all_md_len = HMAC_SZ + AES_BLK_SZ + sizeof(int)*2 + MD_SZ + c->song.numChunks*HMAC_SZ;
    c->song.file_size -= all_md_len;
    c->song.wav_size -= all_md_len;

    if (is_locked() && PREVIEW_SZ < c->song.wav_size) {
        mb_printf("Only dumping 30 seconds");
        c->song.file_size -= c->song.wav_size - PREVIEW_SZ;
        c->song.wav_size = PREVIEW_SZ;
    }

    mb_printf("Decrypting song (%dB)...", c->song.wav_size);
    //==================taken from play_song===========================================
    int ret;
    unsigned int lenAudio = c->song.wav_size;
    unsigned int nchunks = c->song.numChunks;

    char plainChunk[CHUNK_SZ]; 
    unsigned char iv[AES_BLK_SZ];
    memcpy(iv, (void *)c->song.iv, AES_BLK_SZ);
    int chunknum = 0;

    int rem = lenAudio;
    unsigned int cp_num;

    // decrypt and verify chunks of encrypted audio
    while(rem > 0) {
        // calculate write size and offset
        cp_num = (rem > CHUNK_SZ) ? CHUNK_SZ : rem;

        // verify chunk using HMAC
        /*char* data2[2];
        data2[0] = get_drm_song(c->song) + lenAudio - rem;
        data2[1] = c->song.iv;
        int dataLens2[2];
        dataLens2[0] = cp_num;
        dataLens2[1] = AES_BLK_SZ;
        if (verify_hmac(s.hmacChunkKey, HMAC_CHUNK_KEY_SZ, 2, data2, dataLens2, get_drm_hmac(c->song, chunknum++)) != 0) {
            mb_printf("Failed to dump song");
            c->song.wav_size = 0;
            return;
        }*/chunknum++;

        // decrypt chunk
        ret = wc_AesCbcDecryptWithKey(plainChunk, (get_drm_song(c->song) + lenAudio - rem), cp_num, (void*)s.aesKey, (word32)AES_KEY_SZ, iv);
        if (ret != 0) {
            mb_printf("Failed to dump song");
            return;
        }

        // get next IV before replacing encrypted chunk with decrypted chunk
        memcpy(iv, (void *)(get_drm_song(c->song) + lenAudio - rem + cp_num - AES_BLK_SZ), AES_BLK_SZ);
        memcpy((get_drm_song(c->song) + lenAudio - rem), plainChunk, CHUNK_SZ);

        // if last chunk unpad using PKCS#7
        if (chunknum == nchunks) {
            unsigned int pads = (unsigned int*)(get_drm_song(c->song) + lenAudio - rem)[cp_num-1];
            if (pads == 0 || pads > 16) {
                mb_printf("Failed to dump song");
                return;
            }
            for (int i = 1; i <= pads; i++) {
                unsigned int bite = (unsigned int*)(get_drm_song(c->song) + lenAudio - rem)[cp_num-i];
                if (bite != pads) {
                    mb_printf("Failed to dump song");
                    return;
                }
            }
            c->song.wav_size -= pads;
            c->song.file_size -= pads;
        }
        rem -= cp_num;
    }
    //====================================================================================

    // decrypt song in-place
    // TODO: how to verify audio?
    /*mb_printf("Decrypting song (%dB)...", c->song.wav_size);
    int ret = wc_AesCbcDecryptWithKey((void*)get_drm_song(c->song), (void*)get_drm_song(c->song), c->song.wav_size, (void*)s.aesKey, (word32)AES_KEY_SZ, (void*)c->song.iv);
    if (ret != 0) {
        mb_printf("Failed to dump song");
        return;
    }*/

    // remove padding if needed
    /*if (!cut) {
        char padding = get_drm_song(c->song)[c->song.encAudioLen-1];
        c->song.wav_size -= (int)padding;
        mb_printf("padding %d", (int)padding);
    }*/

    // move WAV file up in buffer, skipping metadata
    mb_printf("Dumping song (%dB)...", c->song.wav_size);
    memmove((void *)&c->song.mdHmac, (void *)get_drm_song(c->song), c->song.wav_size);

    mb_printf("Song dump finished\r\n");
}


//////////////////////// MAIN ////////////////////////


int main() {
    u32 status;

    init_platform();
    microblaze_register_handler((XInterruptHandler)myISR, (void *)0);
    microblaze_enable_interrupts();

    // Initialize the interrupt controller driver so that it is ready to use.
    status = XIntc_Initialize(&InterruptController, XPAR_INTC_0_DEVICE_ID);
    if (status != XST_SUCCESS) {
        return XST_FAILURE;
    }

    // Set up the Interrupt System.
    status = SetUpInterruptSystem(&InterruptController, (XInterruptHandler)myISR);
    if (status != XST_SUCCESS) {
        return XST_FAILURE;
    }

    // Congigure the DMA
    status = fnConfigDma(&sAxiDma);
    if(status != XST_SUCCESS) {
        mb_printf("DMA configuration ERROR\r\n");
        return XST_FAILURE;
    }

    // Start the LED
    enableLED(led);
    set_stopped();

    // clear command channel
    memset((void*)c, 0, sizeof(cmd_channel));

    mb_printf("Audio DRM Module has Booted\n\r");

    // WolfCrypt init
    if (wolfCrypt_Init() != 0) {
        mb_printf("Error in wolfCrypt_Init\r\n");
        return XST_FAILURE;
    }

    // initialize crypto keys
    if (init_cryptkeys() != 0) {
        mb_printf("Error initializing keys\r\n");
        return XST_FAILURE;
    }

    // Handle commands forever
    while(1) {
        // wait for interrupt to start
        if (InterruptProcessed) {
            InterruptProcessed = FALSE;
            set_working();

            // c->cmd is set by the miPod player
            switch (c->cmd) {
            case LOGIN:
                login();
                break;
            case LOGOUT:
                logout();
                break;
            case QUERY_PLAYER:
                query_player();
                break;
            case QUERY_SONG:
                query_song();
                break;
            case SHARE:
                share_song();
                break;
            case PLAY:
                play_song();
                mb_printf("Done Playing Song\r\n");
                break;
            case DIGITAL_OUT:
                digital_out();
                break;
            default:
                break;
            }

            // reset statuses and sleep to allowe player to recognize WORKING state
            usleep(500);
            set_stopped();
        }
    }
    // WolfCrypt cleanup */
    if (wolfCrypt_Cleanup() != 0) {
        mb_printf("Error in wolfCrypt_Cleanup\r\n");
        return XST_FAILURE;
    }
    cleanup_platform();
    return 0;
}
