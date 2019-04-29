#include "script.h"

INIT_GLOBAL_BUF

// error code
#define ERROR_NO_PERMISSION -60
#define ERROR_TOO_MANY_OUTPUT -61
#define ERROR_SUMMARY_LEN -62
#define ERROR_SUMMARY -63

/*
arg[0] is "verify"
arg[1] is "cafe" the output[lock][args] which output point by input[previous_output]
if the args include many arguments, they will be flattened here.
arg[2] is "beef" input[args]
same to 2.
arg[3] is witness[0] which is a pubkey
arg[4] is witness[1] which is a signature
 */
int main(int argc, char* argv[])
{
    int ret, len;

    debug(argv[argc - 2]);
    debug(argv[argc - 1]);
    ret = check_sighash_all(argv[argc - 2], argv[argc - 1]);
    if (ret != CKB_SUCCESS) {
        return ret;
    }

    // first pubkey is voter
    debug(argv[1]);
    if (hex_to_bin(g_buf, BLAKE160_SIZE, argv[1]) != BLAKE160_SIZE) {
        return ERROR_PUBKEY_BLAKE160_HASH_LENGTH;
    }
    // voter want to modify the vote
    if (memcmp(g_buf, g_addr, BLAKE160_SIZE) == 0) {
        return CKB_SUCCESS;
    }

    // second pubkey is admin
    debug(argv[2]);
    if (hex_to_bin(g_buf, BLAKE160_SIZE, argv[2]) != BLAKE160_SIZE) {
        return ERROR_PUBKEY_BLAKE160_HASH_LENGTH;
    }
    if (memcmp(g_buf, g_addr, BLAKE160_SIZE) != 0) {
        return ERROR_NO_PERMISSION;
    }

    //tx sender is admin, check the summary
    int total = 0;
    int yes = 0;
    ns(Transaction_table_t) tx;
    if (!(tx = ns(Transaction_as_root(g_tx_buf)))) {
        return ERROR_PARSE_TX;
    }

    ns(CellInput_vec_t) inputs = ns(Transaction_inputs(tx));
    size_t inputs_len = ns(CellInput_vec_len(inputs));
    for (int i = 0; i < inputs_len; i++) {
        if (ckb_load_cell_by_field(g_buf, &len, 0, i, CKB_SOURCE_INPUT, CKB_CELL_FIELD_DATA) != CKB_SUCCESS) {
            return ERROR_LOAD_INPUT_DATA;
        }
        total++;
        if (len > 0) {
            yes++;
        }
    }

    {
        char buf[32];
        snprintf(buf, 32, "total %d yes %d", total, yes);
        debug(buf);
    }

    ns(CellOutput_vec_t) outputs = ns(Transaction_outputs(tx));
    size_t outputs_len = ns(CellOutput_vec_len(outputs));
    if (outputs_len > 1) {
        return ERROR_TOO_MANY_OUTPUT;
    }

    if (ckb_load_cell_by_field(g_buf, &len, 0, 0, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_DATA) != CKB_SUCCESS) {
        return ERROR_LOAD_OUTPUT_DATA;
    }
    if (len != 2) {
        return ERROR_SUMMARY_LEN;
    }
    int summary_total = g_buf[0];
    int summary_yes = g_buf[1];
    if ((summary_total != total) || (summary_yes != yes)) {
        return ERROR_SUMMARY;
    }

    return CKB_SUCCESS;
}