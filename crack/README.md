# Multi-target Profanity MITM (offline crack of profanity v1.12 vanity keys)

recover_mt.cpp: one 2^32 mt19937_64 seed pass tests a whole batch of targets at once.
Table = union over targets of pubkey(target ± idx*2^232), idx in ±(2^24-1). A hit yields
(target, seed, idx) -> privkey = base(seed) - idx*2^232.

targets.txt: "<uncompressed_pubkey_hex> <address>" per line (or get_pubkeys JSONL).

Run: .github/workflows/crack.yml (workflow_dispatch) -- shards the 2^32 seed space.
Build deps: libsecp256k1-dev. API shim handles both pre- and post-0.2.0 libsecp256k1.
