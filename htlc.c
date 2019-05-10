#include "script.h"

INIT_GLOBAL_BUF


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

    if (argc == 7) {
        // unlock
        // arg[1] is sender
        // arg[2] is receiver
        // arg[3] is lock hash  32bytes
        // arg[4] is hash image 32bytes
        // arg[5] is pubkey
        // arg[6] is signature

        debug(argv[5]);
        debug(argv[6]);
        ret = check_sighash_all(argv[5], argv[6]);
        if (ret != CKB_SUCCESS) {
            return ret;
        }
        // only receiver can unlock
        if (hex_to_bin(g_buf, BLAKE160_SIZE, argv[2]) != BLAKE160_SIZE) {
            return ERROR_PUBKEY_BLAKE160_HASH_LENGTH;
        }
        if (memcmp(g_buf, g_addr, BLAKE160_SIZE) != 0) {
            return ERROR_ONLY_RECEIVER_UNLOCK;
        }

        if (hex_to_bin(g_buf, BLAKE2B_BLOCK_SIZE, argv[4]) != BLAKE2B_BLOCK_SIZE) {
            return ERROR_PUBKEY_BLAKE160_HASH_LENGTH;
        }

        blake2b_hash(g_buf, BLAKE2B_BLOCK_SIZE, &g_buf[BLAKE2B_BLOCK_SIZE]);

        if (hex_to_bin(g_buf, BLAKE2B_BLOCK_SIZE, argv[3]) != BLAKE2B_BLOCK_SIZE) {
            return ERROR_PUBKEY_BLAKE160_HASH_LENGTH;
        }

        if (memcmp(g_buf, &g_buf[BLAKE2B_BLOCK_SIZE], BLAKE2B_BLOCK_SIZE) != 0) {
            return ERROR_LOCK_HASH_IMAGE;
        }
        return CKB_SUCCESS;
    } else if (argc == 8) {
        // exit
        // arg[1] is sender
        // arg[2] is receiver
        // arg[3] is lock hash
        // arg[4] is sender pubkey
        // arg[5] is sender signature
        // arg[6] is receiver pubkey
        // arg[7] is receiver signature
        debug(argv[4]);
        debug(argv[5]);
        ret = check_sighash_all(argv[4], argv[5]);
        if (ret != CKB_SUCCESS) {
            return ret;
        }
        // only receiver can unlock
        if (hex_to_bin(g_buf, BLAKE160_SIZE, argv[1]) != BLAKE160_SIZE) {
            return ERROR_PUBKEY_BLAKE160_HASH_LENGTH;
        }
        if (memcmp(g_buf, g_addr, BLAKE160_SIZE) != 0) {
            return ERROR_SENDER;
        }

        debug(argv[6]);
        debug(argv[7]);
        ret = check_sighash_all(argv[6], argv[7]);
        if (ret != CKB_SUCCESS) {
            return ret;
        }
        // only receiver can unlock
        if (hex_to_bin(g_buf, BLAKE160_SIZE, argv[2]) != BLAKE160_SIZE) {
            return ERROR_PUBKEY_BLAKE160_HASH_LENGTH;
        }
        if (memcmp(g_buf, g_addr, BLAKE160_SIZE) != 0) {
            return ERROR_RECEIVER;
        }
        return CKB_SUCCESS;
    }
    return ERROR_ARG_COUNT;
}