#include "secp256k1_blake160.h"

char g_buf[TEMP_BUFFER_SIZE];

// error code
#define ERROR_ARG_COUNT -60
#define ERROR_ONLY_RECEIVER_UNLOCK -61
#define ERROR_LOCK_HASH_LEN -62
#define ERROR_LOCK_HASH_IMAGE -63
#define ERROR_SENDER -64
#define ERROR_RECEIVER -65

int main(int argc, char* argv[])
{
    int ret, len;
    uint64_t length = 0;

    if (argc == 8) {
        // unlock
        // arg[1] is sender
        // arg[2] is receiver
        // arg[3] is lock hash  32bytes
        // arg[4] is hash image 32bytes
        // arg[5] is pubkey
        // arg[6] is signature
        // arg[7] is length of signature

        // only receiver can unlock
        length = *((uint64_t *) argv[7]);
        ret = verify_sighash_all(argv[2], argv[5], argv[6], length);
        if (ret != CKB_SUCCESS) {
            return ret;
        }

        blake2b_hash(argv[4], BLAKE2B_BLOCK_SIZE, g_buf);

        if (memcmp(g_buf, argv[3], BLAKE2B_BLOCK_SIZE) != 0) {
            return ERROR_LOCK_HASH_IMAGE;
        }
        return CKB_SUCCESS;
    } else if (argc == 10) {
        // exit
        // arg[1] is sender
        // arg[2] is receiver
        // arg[3] is lock hash
        // arg[4] is sender pubkey
        // arg[5] is sender signature
        // arg[6] is length of sender signature
        // arg[7] is receiver pubkey
        // arg[8] is receiver signature
        // arg[9] is length of receiver signature

        length = *((uint64_t *) argv[6]);
        ret = verify_sighash_all(argv[1], argv[4], argv[5], length);
        if (ret != CKB_SUCCESS) {
            return ERROR_SENDER;
        }
        length = *((uint64_t *) argv[9]);
        ret = verify_sighash_all(argv[2], argv[7], argv[8], length);
        if (ret != CKB_SUCCESS) {
            return ERROR_RECEIVER;
        }
        return CKB_SUCCESS;
    }
    return ERROR_ARG_COUNT;
}