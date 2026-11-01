// haylook.cpp - TASK 3: a future target batch costs NO EC scan on the seed axis.
//
// The map /home/goose/haystack/fp6.bin is SEED-INDEXED: record s (6 B at offset 6*s) is the
// low-6-byte fingerprint of pubkey(base(s)). So the seed axis needs no re-derivation at all -
// one streaming pass finds every seed whose pubkey lands in the MITM table.
//
// For a CHUNK of targets, materialise the table (fps over base +/- idx*2^232, idx in
// [-(2^24-1), 2^24-1]) with the SAME ADDITION counter series as recover_mt
// (Q = (1<<232)*G, dir>0: R_w = T + w*Q -> idx=+w, dir<0: R_w = T - w*Q -> idx=-w),
// as packed (fp6, meta) records, sort it, then stream the map once and binary-search each
// 6-byte prefix inside its 3-byte bucket. A match is a CANDIDATE; every candidate is VERIFIED
// by reconstructing privkey = base(seed) - idx*2^232 and comparing pubkey(target) - the exact
// check recover_mt does - before it is reported.
//
// The box has 3.8 GB RAM with no swap, so the chunk table lives in a mmap'd temp file, never
// on the heap: chunk 4 = 1.34 GB on disk, ~0 heap.
//
// Build: g++ -O3 -std=c++17 -pthread [-DSK_MODERN] haylook.cpp -o haylook -lsecp256k1 -lpthread
// Run  : haylook <targets> --map <fp6.bin> [--chunk 4] [--tmp DIR] [--report F]
//                      [--threads N] [--max-idx N] [--map-lo S] [--map-hi S]
// Out  : report line 1 = "STATUS candidates=.. confirmed=.." + every CONFIRMED entry,
//        then one count line per target. CONFIRMED lines also go live to stdout.
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
#include <memory>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef SK_MODERN
static inline int SK_parse(secp256k1_context* c, secp256k1_pubkey* p, const unsigned char* in, size_t n){ (void)c; return secp256k1_ec_pubkey_parse(p, in, n); }
static inline int SK_ser(secp256k1_context* c, unsigned char* o, size_t* n, const secp256k1_pubkey* p, unsigned f){ (void)c; return secp256k1_ec_pubkey_serialize(o, n, p, f); }
static inline int SK_create(secp256k1_context* c, secp256k1_pubkey* p, const unsigned char* s){ (void)c; return secp256k1_ec_pubkey_create(p, s); }
static inline int SK_neg(secp256k1_context* c, secp256k1_pubkey* p){ (void)c; return secp256k1_ec_pubkey_negate(p); }
static inline int SK_combine(secp256k1_context* c, secp256k1_pubkey* o, const secp256k1_pubkey** ins, size_t n){ (void)c; return secp256k1_ec_pubkey_combine(o, (const secp256k1_pubkey* const*)ins, n); }
#else
static inline int SK_parse(secp256k1_context* c, secp256k1_pubkey* p, const unsigned char* in, size_t n){ return secp256k1_ec_pubkey_parse(c, p, in, n); }
static inline int SK_ser(secp256k1_context* c, unsigned char* o, size_t* n, const secp256k1_pubkey* p, unsigned f){ return secp256k1_ec_pubkey_serialize(c, o, n, p, f); }
static inline int SK_create(secp256k1_context* c, secp256k1_pubkey* p, const unsigned char* s){ return secp256k1_ec_pubkey_create(c, p, s); }
static inline int SK_neg(secp256k1_context* c, secp256k1_pubkey* p){ return secp256k1_ec_pubkey_negate(c, p); }
static inline int SK_combine(secp256k1_context* c, secp256k1_pubkey* o, const secp256k1_pubkey** ins, size_t n){ return secp256k1_ec_pubkey_combine(c, o, (const secp256k1_pubkey* const*)ins, n); }
#endif

static int32_t HALF = 0xFFFFFF;                 // idx range +-(HALF)
static const size_t FPB = 6;
static const uint32_t META_MASK = 0x1FFFFFFu;   // 25 bit idx field

struct __attribute__((packed)) Rec { unsigned char fp[FPB]; uint32_t meta; };
// meta = (tid << 25) | (idx + 2^24)   [identical packing to recover_mt]
struct Target { std::string addr; unsigned char pub[65]; size_t publen; };

static bool load_targets(const char* path, std::vector<Target>& T) {
    std::ifstream f(path);
    if (!f) { fprintf(stderr, "cannot open %s\n", path); return false; }
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        std::string hex, addr;
        if (line[0] == '{') {                                     // JSONL from get_pubkeys.py
            size_t a = line.find("\"addr\""), p = line.find("\"pubkey\"");
            if (p == std::string::npos) continue;
            size_t q1 = line.find('"', line.find(':', p) + 1), q2 = line.find('"', q1 + 1);
            hex = line.substr(q1 + 1, q2 - q1 - 1);
            if (a != std::string::npos) { size_t r1 = line.find('"', line.find(':', a) + 1), r2 = line.find('"', r1 + 1); addr = line.substr(r1 + 1, r2 - r1 - 1); }
        } else { std::istringstream is(line); is >> hex >> addr; }
        if (hex.rfind("0x", 0) == 0) hex = hex.substr(2);
        size_t nb = hex.size() / 2;
        if (nb != 64 && nb != 65) { fprintf(stderr, "skip %s (len %zu)\n", hex.c_str(), nb); continue; }
        Target t; t.addr = addr.empty() ? "?" : addr;
        if (nb == 64) { t.pub[0] = 0x04; for (size_t i = 0; i < 64; i++) t.pub[1 + i] = (unsigned char)strtoul(hex.substr(2 * i, 2).c_str(), 0, 16); t.publen = 65; }
        else { for (size_t i = 0; i < 65; i++) t.pub[i] = (unsigned char)strtoul(hex.substr(2 * i, 2).c_str(), 0, 16); t.publen = 65; }
        T.push_back(t);
    }
    return !T.empty();
}

// build the per-chunk table by ADDITION counter series, straight into a mmap'd file image.
static void build_chunk(const std::vector<Target>& T, Rec* out, size_t per, int nthreads) {
    secp256k1_context* c0 = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    std::vector<secp256k1_pubkey> base(T.size());
    for (size_t k = 0; k < T.size(); k++) if (!SK_parse(c0, &base[k], T[k].pub, T[k].publen)) { fprintf(stderr, "bad pubkey %zu\n", k); exit(1); }
    secp256k1_context_destroy(c0);
    unsigned char qs[32]; memset(qs, 0, 32); qs[2] = 0x01;        // Q = (1<<232)*G, big-endian
    std::atomic<size_t> next{0}, done{0};
    const size_t NT = T.size() * 2;
    auto worker = [&]() {
        secp256k1_context* c = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        secp256k1_pubkey Q; SK_create(c, &Q, qs);
        secp256k1_pubkey Qn = Q; SK_neg(c, &Qn);
        auto emit = [&](size_t k, int32_t idx, const secp256k1_pubkey* R) {
            unsigned char sb[33]; size_t sn = 33;
            SK_ser(c, sb, &sn, R, SECP256K1_EC_COMPRESSED);
            uint64_t h; memcpy(&h, sb + 25, 8);
            Rec& r = out[(size_t)k * per + (size_t)(idx + HALF)];
            memcpy(r.fp, &h, FPB);
            r.meta = ((uint32_t)k << 25) | (uint32_t)(idx + (1 << 24));
        };
        size_t task;
        while ((task = next.fetch_add(1)) < NT) {
            size_t k = task / 2; int dir = (task % 2) ? -1 : +1;
            secp256k1_pubkey R = base[k], tmp;
            const secp256k1_pubkey* ins[2] = {&R, dir > 0 ? &Q : &Qn};
            if (dir > 0) { emit(k, 0, &R); for (int32_t w = 1; w <= HALF; w++) { SK_combine(c, &tmp, ins, 2); R = tmp; emit(k, w, &R); } }
            else { for (int32_t w = 1; w <= HALF; w++) { SK_combine(c, &tmp, ins, 2); R = tmp; emit(k, -w, &R); } }
            size_t d = done.fetch_add(1) + 1;
            if ((d & 1) == 0 || d == NT) fprintf(stderr, "  series %zu/%zu\n", d, NT);
        }
        secp256k1_context_destroy(c);
    };
    std::vector<std::thread> ts;
    for (int i = 0; i < nthreads; i++) ts.emplace_back(worker);
    for (auto& th : ts) th.join();
}

struct Conf { size_t tid; uint64_t seed; int32_t idx; char key[67]; };

int main(int argc, char** argv) {
    if (argc < 2) { fprintf(stderr, "usage: haylook <targets> --map fp6.bin [--chunk 4] [--tmp DIR] [--report F] [--threads N] [--max-idx N] [--map-lo S] [--map-hi S]\n"); return 1; }
    const char* tpath = argv[1];
    std::string map, tmpdir = ".", report = "haylook_report.txt";
    std::vector<std::string> maps; std::vector<size_t> mfpbs, mbases; size_t pend = FPB, pbase = 0;
    int chunk = 4, nthreads = 2;
    size_t mlo = 0, mhi = 0;
    for (int i = 2; i < argc; i++) { std::string a = argv[i];
        if (a == "--map" && i + 1 < argc) { map = argv[++i]; maps.push_back(map); mfpbs.push_back(pend); mbases.push_back(pbase); pend = FPB; pbase = 0; }
        else if (a == "--map-fpb" && i + 1 < argc) pend = (size_t)strtoul(argv[++i], 0, 10);
        else if (a == "--map-base" && i + 1 < argc) pbase = (size_t)strtoull(argv[++i], 0, 10);
        else if (a == "--chunk" && i + 1 < argc) chunk = atoi(argv[++i]);
        else if (a == "--tmp" && i + 1 < argc) tmpdir = argv[++i];
        else if (a == "--report" && i + 1 < argc) report = argv[++i];
        else if (a == "--threads" && i + 1 < argc) nthreads = atoi(argv[++i]);
        else if (a == "--max-idx" && i + 1 < argc) HALF = (int32_t)strtol(argv[++i], 0, 10);
        else if (a == "--map-lo" && i + 1 < argc) mlo = strtoull(argv[++i], 0, 10);
        else if (a == "--map-hi" && i + 1 < argc) mhi = strtoull(argv[++i], 0, 10);
    }
    if (maps.empty()) { fprintf(stderr, "--map required\n"); return 1; }
    if (chunk < 1) chunk = 1; if (chunk > 16) chunk = 16; if (nthreads < 1) nthreads = 1;
    std::vector<Target> T;
    if (!load_targets(tpath, T)) return 1;
    fprintf(stderr, "%zu targets, chunk %d, threads %d, idx +-%d, %zu map file(s)\n", T.size(), chunk, nthreads, HALF, maps.size());


    const size_t per = (size_t)(2 * (int64_t)HALF + 1);
    std::unique_ptr<std::atomic<uint64_t>[]> per_target(new std::atomic<uint64_t>[T.size()]);
    for (size_t i = 0; i < T.size(); i++) per_target[i].store(0);
    std::vector<Conf> confs;
    uint64_t total_cand = 0;
    const size_t NB = 1u << 24;                     // 3-byte bucket directory
    std::vector<uint32_t> buck(NB + 1, 0);

    for (size_t c0 = 0; c0 < T.size(); c0 += chunk) {
        const size_t nk = std::min((size_t)chunk, T.size() - c0);
        std::vector<Target> sub(T.begin() + c0, T.begin() + c0 + nk);
        const size_t nrecs = per * nk, tblbytes = nrecs * sizeof(Rec);
        std::string tf = tmpdir + "/haylook_" + std::to_string(c0) + ".tmp";
        int tfd = open(tf.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (tfd < 0) { perror("open tmp"); return 1; }
        if (ftruncate(tfd, (off_t)tblbytes) != 0) { perror("ftruncate"); return 1; }
        Rec* R = (Rec*)mmap(nullptr, tblbytes, PROT_READ | PROT_WRITE, MAP_SHARED, tfd, 0);
        if (R == MAP_FAILED) { perror("mmap tmp"); return 1; }
        madvise(R, tblbytes, MADV_RANDOM);            // random search: don't let readahead evict it
        auto t0 = std::chrono::steady_clock::now();
        build_chunk(sub, R, per, nthreads);
        fprintf(stderr, "  chunk @%zu: built %zu recs (%.0fs), sorting...\n", c0, nrecs,
                std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
        std::sort(R, R + nrecs, [](const Rec& a, const Rec& b){ return memcmp(a.fp, b.fp, FPB) < 0; });
        std::fill(buck.begin(), buck.end(), 0);
        for (size_t i = 0; i < nrecs; i++) buck[((uint32_t)R[i].fp[0] << 16 | (uint32_t)R[i].fp[1] << 8 | R[i].fp[2]) + 1]++;
        for (size_t i = 1; i <= NB; i++) buck[i] += buck[i - 1];
        fprintf(stderr, "  chunk @%zu: sorted+bucketed, streaming map...\n", c0);

        std::vector<unsigned char> TSER(nk * 33);
        { secp256k1_context* cx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
          for (size_t k = 0; k < nk; k++) { secp256k1_pubkey p; size_t sn = 33;
              SK_parse(cx, &p, sub[k].pub, sub[k].publen); SK_ser(cx, &TSER[k * 33], &sn, &p, SECP256K1_EC_COMPRESSED); }
          secp256k1_context_destroy(cx); }

        std::atomic<uint64_t> ncand{0};
        std::unique_ptr<std::atomic<uint64_t>[]> lc(new std::atomic<uint64_t>[nk]);
        for (size_t k = 0; k < nk; k++) lc[k].store(0);
        for (size_t mi = 0; mi < maps.size(); mi++) {
        const size_t mfp = mfpbs[mi];
        int fd = open(maps[mi].c_str(), O_RDONLY);
        if (fd < 0) { perror("open map"); return 1; }
        struct stat st; fstat(fd, &st);
        const size_t mbytes = (size_t)st.st_size, nrec = mbytes / mfp;
        const unsigned char* M = (const unsigned char*)mmap(nullptr, mbytes, PROT_READ, MAP_PRIVATE, fd, 0);
        if (M == MAP_FAILED) { perror("mmap map"); return 1; }
        size_t lo0 = mlo, hi0 = (mhi == 0 || mhi > nrec) ? nrec : mhi;
        if (lo0 > hi0) lo0 = hi0;
        std::atomic<size_t> cur{lo0};
        const size_t STRIDE = 1 << 20;                  // 1 Mi records per pread
        auto scan = [&]() {
            secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
            std::uniform_int_distribution<uint64_t> distr;
            std::vector<unsigned char> buf((size_t)STRIDE * mfp);   // explicit pread: no mmap thrash
            size_t s;
            while ((s = cur.fetch_add(STRIDE)) < hi0) {
                size_t cnt = std::min(hi0, s + STRIDE) - s, got = 0;
                while (got < cnt) {
                    ssize_t r = pread(fd, buf.data() + got * mfp, (cnt - got) * mfp, (off_t)((s + got) * mfp));
                    if (r <= 0) break;
                    got += (size_t)r / mfp;
                    if ((size_t)r % mfp) break;
                }
                if (got < cnt) cnt = got;
                for (size_t j = 0; j < cnt; j++) {
                    const unsigned char* fp = buf.data() + j * mfp;
                    const size_t seed = mbases[mi] + s + j;   // global seed
                    uint32_t b = ((uint32_t)fp[0] << 16 | (uint32_t)fp[1] << 8 | fp[2]);
                    size_t lo = buck[b], hi = buck[b + 1];
                    while (lo < hi) {                       // binary search inside the bucket
                        size_t mid = (lo + hi) >> 1;
                        int cc = memcmp(R[mid].fp, fp, FPB);
                        if (cc < 0) lo = mid + 1; else hi = mid;
                    }
                    for (size_t i = lo; i < buck[b + 1] && memcmp(R[i].fp, fp, FPB) == 0; i++) {
                        uint32_t meta = R[i].meta;
                        size_t tid = meta >> 25; int32_t idx = (int32_t)(meta & META_MASK) - (1 << 24);
                        ncand.fetch_add(1);
                        lc[tid].fetch_add(1, std::memory_order_relaxed);
                        // VERIFY (recover_mt's check): key = base(seed) - idx*2^232
                        std::mt19937_64 eng(seed);
                        uint64_t sk[4]; for (int j = 0; j < 4; j++) sk[j] = distr(eng);
                        uint64_t x[4] = {sk[3], sk[2], sk[1], sk[0]};   // big-endian view
                        int64_t d = -(int64_t)idx;
                        if (d >= 0) { uint64_t add = (uint64_t)d << 40, carry = 0;
                            for (int j = 0; j < 4; j++) { uint64_t t = x[j] + add; carry = (t < x[j]); x[j] = t; add = carry; } }
                        else { uint64_t sb2 = (uint64_t)(-d) << 40, borrow = 0;
                            for (int j = 0; j < 4; j++) { uint64_t y = (j == 0 ? sb2 : 0), r = x[j] - y - borrow;
                                borrow = (x[j] < y || x[j] - y < borrow); x[j] = r; } }
                        unsigned char sec2[32];
                        for (int j = 0; j < 4; j++) for (int m = 0; m < 8; m++) sec2[j * 8 + m] = (unsigned char)((x[j] >> (56 - 8 * m)) & 0xFF);
                        secp256k1_pubkey p2; unsigned char s2[33]; size_t n2 = 33;
                        if (SK_create(ctx, &p2, sec2) && (SK_ser(ctx, s2, &n2, &p2, SECP256K1_EC_COMPRESSED), n2 == 33)
                            && memcmp(s2, &TSER[tid * 33], 33) == 0) {
                            char key[67];
                            for (int j = 0; j < 4; j++) sprintf(key + 16 * j, "%016llx", (unsigned long long)x[j]);
                            printf("CONFIRMED target=%zu addr=%s seed=%llu idx=%d privkey=0x%s\n",
                                   c0 + tid, sub[tid].addr.c_str(), (unsigned long long)seed, idx, key);
                            fflush(stdout);
                            fprintf(stderr, "  CONFIRMED target=%zu seed=%llu idx=%d\n", c0 + tid, (unsigned long long)seed, idx);
                            confs.push_back(Conf{c0 + tid, seed, idx, {0}});
                            memcpy(confs.back().key, key, 67);
                        }
                    }
                }
            }
            secp256k1_context_destroy(ctx);
        };
        std::vector<std::thread> ts;
        for (int i = 0; i < nthreads; i++) ts.emplace_back(scan);
        for (auto& th : ts) th.join();
        munmap((void*)M, mbytes); close(fd);
        }
        for (size_t k = 0; k < nk; k++) per_target[c0 + k].fetch_add(lc[k].load(), std::memory_order_relaxed);
        total_cand += ncand.load();
        fprintf(stderr, "  chunk @%zu: candidates=%llu\n", c0, (unsigned long long)ncand.load());
        munmap(R, tblbytes); close(tfd); unlink(tf.c_str());
    }
    uint64_t confirmed = confs.size();
    fprintf(stderr, "TOTAL candidates=%llu confirmed=%llu\n", (unsigned long long)total_cand, (unsigned long long)confirmed);

    FILE* rf = fopen(report.c_str(), "w");
    if (rf) {
        fprintf(rf, "STATUS candidates=%llu confirmed=%llu targets=%zu scanned=[%zu,%zu) idx=+-%d\n",
                (unsigned long long)total_cand, (unsigned long long)confirmed, T.size(), mlo, mhi, HALF);
        for (const Conf& c : confs)
            fprintf(rf, "CONFIRMED addr=%s privkey=0x%s seed=%llu idx=%d balance=CHECK\n",
                    T[c.tid].addr.c_str(), c.key, (unsigned long long)c.seed, c.idx);
        for (size_t i = 0; i < T.size(); i++)
            fprintf(rf, "TARGET %zu %s cand=%llu\n", i, T[i].addr.c_str(), (unsigned long long)per_target[i].load());
        fclose(rf);
    }
    printf("SUMMARY candidates=%llu confirmed=%llu report=%s\n",
           (unsigned long long)total_cand, (unsigned long long)confirmed, report.c_str());
    return confirmed ? 0 : 0;
}
