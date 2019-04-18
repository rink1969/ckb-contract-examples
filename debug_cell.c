#include "ckb_syscalls.h"

int main(int argc, char* argv[])
{
    for(int i = 0; i < argc; i++) {
        ckb_debug(argv[i]);
    }
    return 0;
}
