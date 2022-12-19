#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" void deadspace(char *str);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);

    char* a = strdup(provider.ConsumeRandomLengthString().c_str());
    deadspace(a);
    free(a);

    return 0;

}
