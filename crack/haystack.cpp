// haystack.cpp - TASK F / map v1: seed -> fingerprint file (and a per-shard bloom).
//
// For every 32-bit mt19937_64 seed write the 8-byte fingerprint the MITM matches on
// (low 8 bytes of the compressed pubkey X). The fp file is SEED-INDEXED: byte offset 8*(s-lo)
// is seed s, so concatenating shards in order gives a file whose record index IS the seed.
//
// Also emits a per-shard BLOOM over the same fingerprints (double hashing, k bits). Sized so
// the union of shards is a ~6 GB working filter (~0.5% fp); a query tests the (few) fps against
// each shard's bloom rather than loading 6 GB of RAM.
//
// Build:  g++ -O3 -std=c++17 -pthread [-DSK_MODERN] haystack.cpp -o haystack -lsecp256k1 -lpthread
// Usage:  haystack <fp.bin> --lo N --hi N [--threads N] [--fp-bytes 7] [--bloom F --bloom-bytes M]
#include <secp256k1.h>
#include <atomic>
#include <thread>
#include <vector>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <random>
#include <unistd.h>

#ifdef SK_MODERN
static inline int SK_ser(secp256k1_context* c, unsigned char* o, size_t* n, const secp256k1_pubkey* p, unsigned f){ (void)c; return secp256k1_ec_pubkey_serialize(o, n, p, f); }
static inline int SK_create(secp256k1_context* c, secp256k1_pubkey* p, const unsigned char* s){ (void)c; return secp256k1_ec_pubkey_create(p, s); }
#else
static inline int SK_ser(secp256k1_context* c, unsigned char* o, size_t* n, const secp256k1_pubkey* p, unsigned f){ return secp256k1_ec_pubkey_serialize(c, o, n, p, f); }
static inline int SK_create(secp256k1_context* c, secp256k1_pubkey* p, const unsigned char* s){ return secp256k1_ec_pubkey_create(c, p, s); }
#endif

static inline uint64_t splitmix64(uint64_t x) {
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}

int main(int argc, char** argv) {
    if (argc < 2) { fprintf(stderr, "usage: haystack <fp.bin> --lo N --hi N [--threads N] [--fp-bytes 8] [--bloom F --bloom-bytes M] [--bloom-k K]\n"); return 1; }
    const char* out = argv[1];
    uint64_t lo = 0, hi = 1ULL << 32;
    int nthreads = (int)std::thread::hardware_concurrency();
    int FPB = 8, k = 8;
    std::string bf; uint64_t bbytes = 0;
    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--lo" && i + 1 < argc) lo = strtoull(argv[++i], 0, 0);
        else if (a == "--hi" && i + 1 < argc) hi = strtoull(argv[++i], 0, 0);
        else if (a == "--threads" && i + 1 < argc) nthreads = atoi(argv[++i]);
        else if (a == "--fp-bytes" && i + 1 < argc) FPB = atoi(argv[++i]);
        else if (a == "--bloom" && i + 1 < argc) bf = argv[++i];
        else if (a == "--bloom-bytes" && i + 1 < argc) bbytes = strtoull(argv[++i], 0, 0);
        else if (a == "--bloom-k" && i + 1 < argc) k = atoi(argv[++i]);
    }
    uint64_t span = hi - lo;
    fprintf(stderr, "haystack [%llu,%llu) = %llu seeds x %d B = %llu bytes; bloom=%s %llu B k=%d; %d threads\n",
            (unsigned long long)lo, (unsigned long long)hi, (unsigned long long)span, FPB,
            (unsigned long long)(span * FPB), bf.empty() ? "-" : bf.c_str(),
            (unsigned long long)bbytes, k, nthreads);
    FILE* f = fopen(out, "wb");
    if (!f) { perror("fopen"); return 1; }
    truncate(out, (off_t)(span * FPB));

    std::vector<std::vector<unsigned char> > BL(nthreads);
    uint64_t bbits = bbytes * 8;
    for (int t = 0; t < nthreads; t++) if (bbytes) BL[t].assign(bbytes, 0);

    const uint64_t BLK = 8192;
    std::atomic<uint64_t> nextblk{0};
    std::atomic<uint64_t> done{0};
    uint64_t nblk = (span + BLK - 1) / BLK;
    auto t0 = std::chrono::steady_clock::now();
    auto worker = [&](int tid) {
        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        std::uniform_int_distribution<uint64_t> distr;
        std::vector<unsigned char> buf((size_t)BLK * FPB);
        unsigned char* bl = bbytes ? BL[tid].data() : nullptr;
        for (;;) {
            uint64_t b = nextblk.fetch_add(1);
            if (b >= nblk) break;
            uint64_t s0 = lo + b * BLK;
            uint64_t cnt = span - b * BLK; if (cnt > BLK) cnt = BLK;
            for (uint64_t kk = 0; kk < cnt; kk++) {
                uint64_t s = s0 + kk;
                std::mt19937_64 eng(s);
                uint64_t sk[4];
                for (int i = 0; i < 4; i++) sk[i] = distr(eng);
                unsigned char sec[32];
                for (int i = 0; i < 4; i++) { uint64_t v = sk[3 - i]; for (int j = 0; j < 8; j++) sec[i * 8 + j] = (unsigned char)((v >> (56 - 8 * j)) & 0xFF); }
                secp256k1_pubkey p; uint64_t h = 0;
                if (SK_create(ctx, &p, sec)) {
                    unsigned char ser[33]; size_t sn = 33;
                    SK_ser(ctx, ser, &sn, &p, SECP256K1_EC_COMPRESSED);
                    memcpy(&h, ser + 25, 8);
                }
                memcpy(&buf[(size_t)kk * FPB], &h, FPB);          // low FPB bytes, little-endian
                if (bl) {
                    uint64_t h1 = splitmix64(h), h2 = splitmix64(h ^ 0xD1B54A32D192ED03ULL) | 1;
                    for (int i = 0; i < k; i++) { uint64_t idx = (h1 + (uint64_t)i * h2) % bbits; bl[idx >> 3] |= (unsigned char)(1u << (idx & 7)); }
                }
            }
            pwrite(fileno(f), buf.data(), (size_t)cnt * FPB, (off_t)(b * BLK * FPB));
            uint64_t d = done.fetch_add(cnt) + cnt;
            if ((b & 0x7F) == 0) {
                double dt = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
                fprintf(stderr, "  %llu/%llu (%.1f%%) %.0f k/s\n", (unsigned long long)d,
                        (unsigned long long)span, 100.0 * d / span, d / dt / 1e3);
            }
        }
        secp256k1_context_destroy(ctx);
    };
    std::vector<std::thread> ts;
    for (int i = 0; i < nthreads; i++) ts.emplace_back(worker, i);
    for (auto& th : ts) th.join();
    fclose(f);

    if (bbytes) {
        std::vector<unsigned char> B(bbytes, 0);
        for (int t = 0; t < nthreads; t++) for (uint64_t i = 0; i < bbytes; i++) B[i] |= BL[t][i];
        uint64_t ones = 0; for (uint64_t i = 0; i < bbytes; i++) ones += __builtin_popcount(B[i]);
        FILE* bfo = fopen(bf.c_str(), "wb"); fwrite(B.data(), 1, bbytes, bfo); fclose(bfo);
        fprintf(stderr, "bloom: %llu B, %llu bits set (%.3f%% fill) -> %s\n",
                (unsigned long long)bbytes, (unsigned long long)ones, 100.0 * ones / bbits, bf.c_str());
    }
    double dt = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    fprintf(stderr, "done: %llu seeds in %.1fs (%.0f k/s) -> %s\n",
            (unsigned long long)done.load(), dt, done.load() / dt / 1e3, out);
    return 0;
}
