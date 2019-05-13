#include "script.h"

int main(int argc, char* argv[])
{
    char buf[5];

    for(int i = 0; i < argc; i++) {
        memset(buf, 0, 5);
        bin_to_hex(buf, 5, argv[i]);
        ckb_debug(buf);
    }
    return 0;
}
