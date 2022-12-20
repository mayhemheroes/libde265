#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>
#include "immintrin.h"

void print128(const char* prefix, __m128i r);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string prefix = provider.ConsumeRandomLengthString();
    int i1 = provider.ConsumeIntegral<int>();
    int i2 = provider.ConsumeIntegral<int>();
    int i3 = provider.ConsumeIntegral<int>();
    int i4 = provider.ConsumeIntegral<int>();

    __m128i r = _mm_setr_epi32(i1, i2, i3, i4);
    print128(prefix.c_str(), r);

    return 0;
}
