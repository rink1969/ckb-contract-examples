# ckb-contract-examples

### toolchain
Toolchain for riscv64, there is a [docker image](https://hub.docker.com/r/xxuejie/riscv-gnu-toolchain-rv64imac).

### wallet
[wallet](https://github.com/rink1969/ckb-sdk-ruby)

Please use branch contract_examples 

This is a fork from NervosNetwork, add extra functions support contract development.

### examples
#### debug_cell
This is the most simple lock script, just print all arguments, then return 0.
##### compile
```
docker run -it --rm -v `pwd`:/data  xxuejie/riscv-gnu-toolchain-rv64imac:latest bin/bash
cd /data
riscv64-unknown-elf-gcc -ffunction-sections -fdata-sections -Wl,-gc-sections debug_cell.c -I ./header -o debug_cell
riscv64-unknown-elf-strip -s debug_cell
exit
```

##### run
1. Setup wallet (use branch metioned above).

2. Then miner for a while to get some capacity.

3. Deploy contract. First arg is path of the elf file that we compiled. Seconed arg is name of the contract, we will use it later.
    ```
    c = CKB::Contract.new(wallet)
    c.deploy_contract("/path/to/debug_cell", "test")
    ```

4. Setup contract. Create a cell with some capacity and lock it with debug_cell. First arg is name of contract. Seconed arg is capacity we want to lock.
    ```
    prev_tx_hash = c.setup_contract("test", 10000)
    ```
5. Call contract.
Just send all capacity to a new cell which also locked with debug_cell.
Seconed arg is the prev tx hash. First time prev tx hash is tx hash of setup_contract, then prev tx hash is tx hash of prev call_contract.
    ```
    prev_tx_hash = c.call_contract("test", prev_tx_hash)
    ```
6. [Enable ckb debug log](https://github.com/nervosnetwork/ckb-demo-ruby#custom-log-config), we will see the debug log from script. 

##### result
We will see the args:

0. arg\[0\] is "verify"
1. arg\[1\] is "cafe" the output\[lock\]\[args\] which output point by input\[previous_output\]
2. if tx have multi-inputs, there will be multi-output\[lock\]\[args\] insert here
3. arg\[2\] is "beef" input\[args\]
4. if tx have multi-inputs, there will be multi-input\[args\] insert here
5. arg\[3\] is witness\[0\] which is a pubkey
6. arg\[4\] is witness\[1\] which is a signature

