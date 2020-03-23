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
#include "blake3.h"


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


// loads the song metadata in the shared buffer into the local internal_state struct
void load_song_md() {
    s.song_md.md_size = c->song.md.md_size;
    s.song_md.owner_id = c->song.md.owner_id;
    s.song_md.num_regions = c->song.md.num_regions;
    s.song_md.num_users = c->song.md.num_users;
    memcpy(s.song_md.rids, (void *)get_drm_rids(c->song), s.song_md.num_regions);
    memcpy(s.song_md.uids, (void *)get_drm_uids(c->song), s.song_md.num_users);
}


/* checks if the song loaded into the shared buffer is locked for the current user
 * assume we have already loaded song metadata (load_song_md())
 * return TRUE (1) if song is locked for current user and/or region, FALSE (0) otherwise
 */
int is_locked() {
    int locked = TRUE;

    // check for authorized user
    if (!s.logged_in) {
        mb_printf("No user logged in\r\n");
    } else {
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
            mb_printf("User '%s' does not have access to this song\r\n", s.username);
            return locked;
        }
        mb_printf("User '%s' has access to this song\r\n", s.username);
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
            mb_printf("Region Match. Full Song can be accessed. Unlocking...\r\n");
        } else {
            mb_printf("Invalid region\r\n");
        }
    }
    return locked;
} // end is_locked()


/* takes the base64 encoded cryptographic keys from secrets.h, decodes them, and
 * stores them into the DRM local internal_state struct
 * return 0 on success, -1 otherwise
 */
int init_cryptkeys() {
    word32 outLen = b64SIMON_KEY_SZ;
    if (Base64_Decode((void *)SIMON_KEY, (word32)b64SIMON_KEY_SZ, (void *)s.simonKey, &outLen) != 0) {
        return -1;
    }
    outLen = b64MD_KEY_SZ;
    if (Base64_Decode((void *)MD_KEY, (word32)b64MD_KEY_SZ, (void *)s.mdKey, &outLen) != 0) {
        return -1;
    }
    outLen = b64CHUNK_KEY_SZ;
    if (Base64_Decode((void *)CHUNK_KEY, (word32)b64CHUNK_KEY_SZ, (void *)s.chunkKey, &outLen) != 0) {
        return -1;
    }
    return 0;
}


/*#define glowwormAddBit(b,s,n,t) ( \
    t = s[n % 32] ^ ((b) ? 0xffffffff : 0), \
    t = (t|(t>>1)) ^ (t<<1), \
    t ^= (t>>4) ^ (t>>8) ^ (t>>16) ^ (t>>32),\
    n++, \
    s[n % 32] ^= t \
)


#define glowwormInit(s,n,t,h) { \
    h = 1; \
    n = 0; \
    for (int i=0; i<32; i++) \
        s[i]=0; \
    for (int i=0; i<4096; i++) \
        h=glowwormAddBit((h & 1L),s,n,t); \
    n = 0; \
}*/


// Call glowwormInit once, which returns the hash of the
// empty string, which should equal CHECKVALUE. Repeatedly
// call AddBit to add a new bit to the end, and return the
// hash of the resulting string. DelBit deletes the last
// bit, and must be passed the last bit of the most recent
// string hashed. The macros should be passed these:
// uint64 s[32]; //buffer
// static uint64 n; //current string length
// uint64 t, i, h; //temporary
// const uint64 CHECKVALUE = 0xCCA4220FC78D45E0;

/*
 * create a glowworm hash
 * data    : pointer to data to hash
 * dataLen : length of data to hash in bytes
 * return hash (uint64) on success
 */ 
/*uint64 glowwormHash(char* data, uint64 dataLen) {
    //const uint64 CHECKVALUE = 0xCCA4220FC78D45E0;
    uint64 s[32]; //buffer
    uint64 n; //current string length
    uint64 t, h; //temporary

    //glowwormInit(s,n,t,h); //shave off 3 seconds with precomputation
    n = 0;
    t = (uint64)5699370651900549022;
    h = (uint64)14745948531085624800;
    s[0] = (uint64)14745948531085624800;
    s[1] = (uint64)16120642418826990911;
    s[2] = (uint64)9275000239821960485;
    s[3] = (uint64)4476743750426018428;
    s[4] = (uint64)741912412851399944;
    s[5] = (uint64)17767459926458528083;
    s[6] = (uint64)2469478127305654386;
    s[7] = (uint64)6225995753166195692;
    s[8] = (uint64)4750461123551357503;
    s[9] = (uint64)10555348896626929070;
    s[10] = (uint64)14572814704552083992;
    s[11] = (uint64)2824678681307928227;
    s[12] = (uint64)8198425675642015085;
    s[13] = (uint64)3315257422098907176;
    s[14] = (uint64)13762405054855287671;
    s[15] = (uint64)15186990245784674763;
    s[16] = (uint64)5015234624788364844;
    s[17] = (uint64)8462123041350221017;
    s[18] = (uint64)9974233762935842858;
    s[19] = (uint64)11502466225357323772;
    s[20] = (uint64)17531649588530077495;
    s[21] = (uint64)8670185664686319238;
    s[22] = (uint64)4707560773883213848;
    s[23] = (uint64)10843017560065197706;
    s[24] = (uint64)17676146699030180721;
    s[25] = (uint64)17194224147714809490;
    s[26] = (uint64)4745306135015590921;
    s[27] = (uint64)11298931964348737593;
    s[28] = (uint64)14067901419238702746;
    s[29] = (uint64)15452291037738416485;
    s[30] = (uint64)591116246257296967;
    s[31] = (uint64)15728077675183395515;
    //assert(h == CHECKVALUE);
    
    for (int idx = 0; idx < dataLen; idx++) {
        char currByte = data[idx];
        for (int bIdx = 7; bIdx >= 0; bIdx--) {
            char bit = (currByte>>bIdx&1);
            h = glowwormAddBit(bit,s,n,t);
        }
    }
    return h;
}*/


/* create a new Blake3 hash
 * return 0 on success, -1 otherwise
 *
 * args     : number of different data to update hmac object with
 * data     : array of char pointers (data) to create hash with
 * dataLens : length of each data to be included in hash
 * key      : pointer to 32-bit key
 * out      : buffer to store resulting hash
 */
int create_hash(int args, char* data[], int dataLens[], char* key, char* out) {
    if (args <= 0 || data == NULL || dataLens == NULL || key == NULL || out == NULL) {
        return -1;
    }
    blake3_hasher h;
    blake3_hasher_init_keyed(&h, key);
    for (int i = 0; i < args; i++) {
        blake3_hasher_update(&h, data[i], dataLens[i]);
    }
    blake3_hasher_finalize(&h, out, BLAKE3_OUT_LEN);
    return 0;
}


/* verify integrity of a song using the metadata hash from the song in the shared buffer
 * returns 0 on success, -1 otherwise
 */
int verify_song() {
    char mdHash[BLAKE3_OUT_LEN];
    memcpy(mdHash, c->song.mdHash, BLAKE3_OUT_LEN);

    mb_printf("Verifying Audio File...\r\n");
    char out[BLAKE3_OUT_LEN];
    char* data[1] = { c->song.iv };
    int dataLens[1] = { SIMON_BLK_SZ + sizeof(int)*2 + MD_SZ };
    if (create_hash(1, data, dataLens, s.mdKey, out) != 0) {
        mb_printf("Verification Failed\r\n");
        return -1;
    }
    if (memcmp(mdHash, out, BLAKE3_OUT_LEN) != 0) {
        mb_printf("Verification Failed\r\n");
        return -1;
    }
    mb_printf("Successfully Verified Audio File\r\n");
    return 0;
}


//////////////////////// COMMAND FUNCTIONS ////////////////////////


// attempt to log in to the credentials in the shared buffer
void login() {
    // first, copy attempted username and pin into local internal_state
    memcpy(s.username, c->username, USERNAME_SZ);
    memcpy(s.pin, c->pin, MAX_PIN_SZ);

    if (s.logged_in) {
        mb_printf("Already logged in. Please log out first.\r\n");
    } else {
        for (int i = 0; i < NUM_PROVISIONED_USERS; i++) {
            // search for matching username
            if (!strcmp(s.username, USERNAMES[PROVISIONED_UIDS[i]])) {
                // check if pin matches
                if (!strcmp(s.pin, PROVISIONED_PINS[i])) {
                    //update state
                    s.logged_in = 1;
                    s.uid = PROVISIONED_UIDS[i];
                    mb_printf("Logged in for user '%s'\r\n", (void *)s.username);
                    return;
                } else {
                    // username exists, but password does not match
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
        s.uid = 0;
    } else {
        mb_printf("Not logged in\r\n");
    }
}


// handles a request to query the player's metadata
// copies results into shared memory for miPod to display
// note: this is only called once per miPod boot
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
// just like query_song, results are copied into the shared memory for miPod
// to display
// on error, set c->query.num_regions = 0 to notify miPod
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


// add a user to the song's list of authorized users
// on error, set c->song.wav_size = 0 to notify miPod
void share_song() {
    char uid;
    int nchunks = c->song.numChunks;

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
    // we can no longer overflow s.song_md.num_users in line 463
    if (s.song_md.num_users >= MAX_USERS) {
        mb_printf("Cannot share song\r\n");
        c->song.wav_size = 0;
        return;
    }
    
    // update song metadata in local state
    s.song_md.md_size++;
    s.song_md.uids[s.song_md.num_users++] = uid;

    // actually modify the file in the shared memory
    c->song.md.md_size++;
    c->song.md.buf[s.song_md.num_regions + c->song.md.num_users++] = uid;

    // update metadata hash and copy it into the file in the shared memory
    char* data[1] = { c->song.iv };
    int dataLens[1] = { BLAKE3_OUT_LEN + SIMON_BLK_SZ + sizeof(int)*2 + MD_SZ + nchunks*BLAKE3_OUT_LEN };
    char out[BLAKE3_OUT_LEN];
    if (create_hash(1, data, dataLens, s.mdKey, out) != 0) {
        mb_printf("Cannot share song\r\n");
        c->song.wav_size = 0;
        return;
    }
    memcpy(c->song.mdHash, out, BLAKE3_OUT_LEN);

    // with a max of 32 different regions and 64 different users, the max size
    // of the song metadata is 100 bytes. We preallocate 100 bytes for song metadata
    // at drm file creation to remove the need for the expensive memmove() that
    // used to be here

    mb_printf("Shared song with '%s'\r\n", c->username);
} // end share_song()


// plays a song and enter the playback loop, which has it's own commands
// if the metadata verification fails, set c->song.wav_size = 0 to notify DRM
// if error occurs during playback, simply break out of the playback loop
void play_song() {
    u32 counter = 0, cp_num, cp_xfil_cnt, offset, dma_cnt, lenAudio, *fifo_fill;
    // for function return values
    int ret;
    // rem is the bytes of audio remaining to play during the play loop
    // we need rem to be signed so we can check if under 0
    int rem;

    mb_printf("Reading Audio File...\r\n");
    // verify and load song md
    if (verify_song() != 0) {
        mb_printf("Failed to play audio\r\n");
        c->song.wav_size = 0;
        set_playing();
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

    // whether we are operating on the first chunk of the audio
    int firstChunk = TRUE;
    // save a copy of the initialization vector used for the AES-CBC encryption
    char origIv[SIMON_BLK_SZ];
    memcpy(origIv, c->song.iv, SIMON_BLK_SZ);
    // buffer used to store current "IV" value -- we change this value after decrypting
    // each audio chunk, but initially, it is the original initialization vector
    char iv[SIMON_BLK_SZ];
    memcpy(iv, c->song.iv, SIMON_BLK_SZ);
    // buffer used to hold current decrypted audio chunk
    char plainChunk[CHUNK_SZ];
    // chunk number currently being decrypted
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
                mb_printf("Stopping playback...\r\n");
                return;
            case RESTART:
                mb_printf("Restarting song... \r\n");
                usleep(100000); // prevent choppy audio on restart
                chunknum = 0; // reset chunk number
                rem = lenAudio; // reset song counter
                firstChunk = TRUE;
                set_playing();
                break;
            case FF:
                mb_printf("Fast forwarding 5 seconds... \r\n");
                paused = TRUE;
                rem -= SKIP_SZ; // skip ahead
                // if we try to skip past the end of the song/preview, end playback
                if (rem <= 0) {
                    return;
                }
                chunknum += (SKIP_SZ / CHUNK_SZ);
                // TODO: can we overshoot chunknum? i.e. find ourselves in
                // a scenario where last chunk is not unpadded?
                break;
            case RW:
                mb_printf("Rewinding 5 seconds... \r\n");
                paused = TRUE;
                rem += SKIP_SZ; // rewind
                // if we try to rewind past the beginning, play from the beginning
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

        // if first chunk, do nothing -- we have already copied the initialization
        // vector into the iv buffer
        // if not the first chunk, use the most previous AES block as the IV for the
        // next chunk decryption
        if (firstChunk) {
            firstChunk = FALSE;
        } else {
            memcpy(iv, (get_drm_song(c->song) + lenAudio - rem - SIMON_BLK_SZ), SIMON_BLK_SZ);
        }

        // verify chunk using blake3 chunk hash
        char chunkHash[BLAKE3_OUT_LEN];
        memcpy(chunkHash, get_drm_hash(c->song, chunknum++), BLAKE3_OUT_LEN);

        char* data[2] = { get_drm_song(c->song) + lenAudio - rem, origIv };
        int dataLens[2] = { cp_num, SIMON_BLK_SZ };
        char out[BLAKE3_OUT_LEN];
        if (create_hash(2, data, dataLens, s.chunkKey, out) != 0) {
            mb_printf("Failed to play audio\r\n");
            return;
        }
        if (memcmp(chunkHash, out, BLAKE3_OUT_LEN) != 0) {
            mb_printf("Failed to play audio\r\n");
            return;
        }

        // decrypt chunk
        ret = wc_AesCbcDecryptWithKey(plainChunk, (get_drm_song(c->song) + lenAudio - rem), cp_num, s.simonKey, (word32)SIMON_KEY_SZ, iv);
        if (ret != 0) {
            mb_printf("Failed to play audio\r\n");
            return;
        }

        // if last chunk unpad using PKCS#7
        if (chunknum == nchunks) {
            int pads = (int*)plainChunk[cp_num-1];
            // terminate playback if padding is invalid
            if (pads == 0 || pads > 16) {
                mb_printf("Failed to play audio\r\n");
                return;
            }
            for (int i = 1; i <= pads; i++) {
                int bite = (int*)plainChunk[cp_num-i];
                if (bite != pads) {
                    mb_printf("Failed to play audio\r\n");
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
            mb_printf("rem %u, cp_num %u, cp_xfil_cnt %u offset %u, fifofill %u\r\n", rem, cp_num, cp_xfil_cnt, offset, *fifo_fill);
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
            mb_printf("%u\r\n", dma_cnt);
            fnAudioPlay(sAxiDma, offset, dma_cnt);
            cp_xfil_cnt -= dma_cnt;
        }

        rem -= cp_num;
    } // end playback loop

    xil_printf("\r\n");
    mb_printf("Done Playing Song. Press enter to continue.\r\n");
} // end play_song()


// decrypt song and remove metadata
// miPod should be able to read the WAV metadata and the decrypted audio to
// produce a dout file, an exact copy (aurally) of the original wav
// on error, set c->song.wav_size = 0 to notify DRM
// note: implementation mirrors play_song()
void digital_out() {
    if (verify_song() != 0) {
        mb_printf("Cannot dump song\r\n");
        c->song.wav_size = 0;
        return;
    }
    load_song_md();

    // save metadata locally so we don't depend on values in volatile shared memory
    int file_size = c->song.file_size; // whole .drm file size
    int wav_size = c->song.wav_size; // size not including WAV metadata
    // number of encrypted chunks
    int nchunks = c->song.numChunks;
    // save a copy of the initialization vector used for the AES-CBC encryption
    char origIv[SIMON_BLK_SZ];
    memcpy(origIv, c->song.iv, SIMON_BLK_SZ);
    // buffer used to store current "IV" value -- we change this value after decrypting
    // each audio chunk, but initially, it is the original initialization vector
    char iv[SIMON_BLK_SZ];
    memcpy(iv, c->song.iv, SIMON_BLK_SZ);
    // buffer used to hold current decrypted audio chunk
    char plainChunk[CHUNK_SZ];
    // chunk number currently being decrypted
    int chunknum = 0;

    // remove all metadata size from file sizes to reflect audio only
    unsigned int all_md_len = BLAKE3_OUT_LEN + SIMON_BLK_SZ + sizeof(int)*2 + MD_SZ + nchunks*BLAKE3_OUT_LEN;
    file_size -= all_md_len;
    wav_size -= all_md_len;

    // truncate song if locked
    if (is_locked() && PREVIEW_SZ < wav_size) {
        mb_printf("Only dumping 30 seconds\r\n");
        file_size -= wav_size - PREVIEW_SZ;
        wav_size = PREVIEW_SZ;
    }

    mb_printf("Dumping song (%dB)...\r\n", wav_size);
    // taken & modified from play_song
    int ret;
    unsigned int lenAudio = wav_size;

    int rem = lenAudio;
    unsigned int cp_num;

    // loop to decrypt and verify chunks of encrypted audio
    while(rem > 0) {
        // calculate write size and offset
        cp_num = (rem > CHUNK_SZ) ? CHUNK_SZ : rem;

        // verify chunk using blake3 chunk hash
        char chunkHash[BLAKE3_OUT_LEN];
        memcpy(chunkHash, get_drm_hash(c->song, chunknum++), BLAKE3_OUT_LEN);

        char* data[2] = { get_drm_song(c->song) + lenAudio - rem, origIv };
        int dataLens[2] = { cp_num, SIMON_BLK_SZ };
        char out[BLAKE3_OUT_LEN];
        if (create_hash(2, data, dataLens, s.chunkKey, out) != 0) {
            mb_printf("Failed to play audio\r\n");
            return;
        }
        if (memcmp(chunkHash, out, BLAKE3_OUT_LEN) != 0) {
            mb_printf("Failed to play audio\r\n");
            return;
        }

        // decrypt chunk
        ret = wc_AesCbcDecryptWithKey(plainChunk, (get_drm_song(c->song) + lenAudio - rem), cp_num, s.simonKey, SIMON_KEY_SZ, iv);
        if (ret != 0) {
            mb_printf("Failed to dump song\r\n");
            c->song.wav_size = 0;
            return;
        }

        // get next IV before replacing encrypted chunk with decrypted chunk
        memcpy(iv, (get_drm_song(c->song) + lenAudio - rem + cp_num - SIMON_BLK_SZ), SIMON_BLK_SZ);
        memcpy((get_drm_song(c->song) + lenAudio - rem), plainChunk, CHUNK_SZ);

        // if last chunk unpad using PKCS#7
        if (chunknum == nchunks) {
            int pads = (int*)(get_drm_song(c->song) + lenAudio - rem)[cp_num-1];
            // terminate if invalid padding
            if (pads <= 0 || pads > 16) {
                mb_printf("Failed to dump song\r\n");
                c->song.wav_size = 0;
                return;
            }
            for (int i = 1; i <= pads; i++) {
                int bite = (int*)(get_drm_song(c->song) + lenAudio - rem)[cp_num-i];
                if (bite != pads) {
                    mb_printf("Failed to dump song\r\n");
                    c->song.wav_size = 0;
                    return;
                }
            }
            wav_size -= pads;
            file_size -= pads;
        }
        rem -= cp_num;
    } // end decrypt loop

    // move WAV file up in buffer, to cover song metadata ("removing" it)
    mb_printf("Preparing song (%dB)...\r\n", wav_size);
    c->song.file_size = file_size;
    c->song.wav_size = wav_size;
    memmove((char*)&c->song.mdHash, get_drm_song(c->song), c->song.wav_size);

    mb_printf("Song dump finished\r\n");
} // end digital_out()

// clear internal state on exit (but not cryptokeys -- created once per board boot)
void mb_exit() {
    int sz = sizeof(char) + sizeof(u8) + USERNAME_SZ + MAX_PIN_SZ + sizeof(song_md);
    memset((void*)&s, 0, sz);
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
                break;
            case DIGITAL_OUT:
                digital_out();
                break;
            case EXIT:
                mb_exit();
                break;
            default:
                break;
            }

            // reset statuses and sleep to allow player to recognize WORKING state
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
} // end main()
