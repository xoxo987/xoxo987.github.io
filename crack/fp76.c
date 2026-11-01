// fp76.c - stride transform: keep the first 6 bytes of every 7-byte record.
// (fp6 record index/semantics unchanged; no recompute.) Built+run on the box.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char** argv) {
    if (argc < 3) { fprintf(stderr, "usage: fp76 <in.fp7> <out.fp6>\n"); return 1; }
    FILE* in = fopen(argv[1], "rb");
    FILE* out = fopen(argv[2], "wb");
    if (!in || !out) { perror("open"); return 1; }
    const size_t BUF = 1u << 20;                 // records per pass
    unsigned char* b = malloc(BUF * 7);
    unsigned char* o = malloc(BUF * 6);
    size_t n; unsigned long long tot = 0;
    while ((n = fread(b, 7, BUF, in)) > 0) {
        for (size_t i = 0; i < n; i++) memcpy(o + i * 6, b + i * 7, 6);
        if (fwrite(o, 6, n, out) != n) { perror("write"); return 1; }
        tot += n;
    }
    fclose(in); fclose(out);
    fprintf(stderr, "fp76: %llu records\n", tot);
    return 0;
}
