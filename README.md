# ckb-contract-examples

## toolchain
Toolchain for riscv64, there is a [docker image](https://hub.docker.com/r/xxuejie/riscv-gnu-toolchain-rv64imac).

## wallet
[wallet](https://github.com/rink1969/ckb-sdk-ruby)

Please use branch contract_examples 

This is a fork from NervosNetwork, add extra functions support contract development.

## examples
### debug_cell
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
    api = CKB::API.new
    privkey = "0x***"
    wallet = CKB::Wallet.from_hex(api, privkey)
    c = CKB::Contract.new(wallet)
    c.deploy_contract("/path/to/debug_cell", "test", ["0x#{"dead".unpack1('H*')}"])
    ```

4. Setup contract. Create a cell with some capacity and lock it with debug_cell. First arg is name of contract. Seconed arg is capacity we want to lock.
    ```
    prev_tx_hash = c.setup_contract("test", 10000, "0x", "0x#{"cafe".unpack1('H*')}")
    ```
5. Call contract.
Just send all capacity to a new cell which also locked with debug_cell.
Seconed arg is the prev tx hash. First time prev tx hash is tx hash of setup_contract, then prev tx hash is tx hash of prev call_contract.
    ```
    prev_tx_hash = c.call_contract("test", prev_tx_hash, ["0x#{"beef".unpack1('H*')}"])
    ```
6. [Enable ckb debug log](https://github.com/nervosnetwork/ckb-demo-ruby#custom-log-config), we will see the debug log from script. 

##### result
We will see the args:

0. arg\[0\] is "verify"
1. arg\[1\] is "cafe" the output\[lock\]\[args\] which output point by input\[previous_output\]
2. if the args include many arguments, they will be flattened here.
3. arg\[2\] is "beef" input\[args\]
4. same to 2.
5. arg\[3\] is witness\[0\] which is a pubkey
6. arg\[4\] is witness\[1\] which is a signature

### vote
Three people vote Yes/No, then summary result.

##### compile
```
docker run -it --rm -v `pwd`:/data  xxuejie/riscv-gnu-toolchain-rv64imac:latest bin/bash
cd /data
make vote
```
##### run
1. Setup wallet (use branch metioned above).

2. Then miner for a while to get some capacity.

3. Deploy contract and configure data for multi-signatures(M, N and pubkeys of M multi-signers). First arg is path of the elf file that we compiled.
    ```
    api = CKB::API.new
    privkey = "0x***"
    wallet = CKB::Wallet.from_hex(api, privkey)
    c = CKB::Contract.new(wallet)
    v = CKB::Vote.new(c)
    v.deploy("/path/to/vote", "0x#{wallet.blake160[2..].unpack1('H*')}")
    v.generate_configure_data(3, 2, "0x#{wallet.blake160[2..].unpack1('H*')}", "0x#{wallet1.blake160[2..].unpack1('H*')}", "0x#{wallet2.blake160[2..].unpack1('H*')}")
    ```

4. Publish contract info. In this demo, we use file to share it. Other people need call load_contracts.
    ```
    c.save_contracts
    ```
5. Vote. Second argument is hex string. The empty string("0x") means No. The other value means Yes. The last arg is pubkey of voter.
    ```
    vote_hash = v.vote(200, "0xaa", "0x#{wallet.blake160[2..].unpack1('H*')}")
    ```
6. Other people vote. Make sure the wallet have some capacity.
    ```
    privkey1 = "0x***"
    wallet1 = CKB::Wallet.from_hex(api, privkey1)
    c1 = CKB::Contract.new(wallet1)
    c1.load_contracts
    v1 = CKB::Vote.new(c1)
    vote1_hash = v1.vote(200, "0xbb", "0x#{wallet1.blake160[2..].unpack1('H*')}")

    privkey2 = "0x***"
    wallet2 = CKB::Wallet.from_hex(api, privkey2)
    c2 = CKB::Contract.new(wallet2)
    c2.load_contracts
    v2 = CKB::Vote.new(c2)
    vote2_hash = v2.vote(200, "0x", "0x#{wallet2.blake160[2..].unpack1('H*')}")
    ```
7. Summary. Each one of of M multi-signers call sum to get signed sum transaction. The data filed in output of tx is "0x0302", means total 3 votes and 2 is Yes.
    ```
    tx0 = v.sum(vote_hash, vote1_hash, vote2_hash)
    tx1 = v1.sum(vote_hash, vote1_hash, vote2_hash)
    tx2 = v2.sum(vote_hash, vote1_hash, vote2_hash)
    ```
8. Merge these signed sum transactions, get multi-singatures transaction. Then send it to ckb.
    ```
    v.merge(tx0, tx1, tx2)
    ```