// Feeds arbitrary bytes to the header blob importer and verifier (headerImport / headerCheck),
// then walks every tag, file and dependency of an imported header.
#include "harness_common.hh"
#include <rpm/rpmlib.h>

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    harness_init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0)
        return -1;  // headerCheck() treats a zero length as "size unknown"
    rpmts ts = rpmtsCreate();
    rpmtsSetVSFlags(ts, _RPMVSF_NOSIGNATURES | _RPMVSF_NODIGESTS);

    char *msg = NULL;
    (void)headerCheck(ts, data, size, &msg);
    free(msg);

    Header h = headerImport((void *)data, size, HEADERIMPORT_COPY);
    if (h != NULL) {
        walk_header(ts, h);
        Header c = headerCopy(h);
        headerFree(c);
        headerFree(h);
    }
    rpmtsFree(ts);
    return 0;
}
