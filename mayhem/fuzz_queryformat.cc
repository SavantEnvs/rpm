// The --queryformat parser/evaluator (headerFormat) with a fuzzed format string against a fixed
// header that carries a representative spread of tag types.
#include <rpm/header.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmtag.h>
#include <stdlib.h>
#include <string.h>
#include <string>

static Header g_hdr;

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    rpmlogSetMask(RPMLOG_MASK(RPMLOG_EMERG));
    Header h = headerNew();
    uint32_t t = 1234567890, size = 4096, mode[] = { 0100755, 040755, 0120777 };
    uint32_t fsize[] = { 10, 0, 5 }, fflags[] = { 1, 0, 2 };
    uint16_t fm16[] = { 0100755, 040755, 0120777 };
    const char *base[] = { "prog", "dir", "link" };
    const char *dirs[] = { "/usr/bin/", "/usr/share/" };
    uint32_t didx[] = { 0, 1, 0 };
    const char *dig[] = { "0123456789abcdef0123456789abcdef", "", "" };
    const char *reqn[] = { "libc.so.6", "bash", "rpmlib(PayloadIsZstd)" };
    const char *reqv[] = { "", "4.4", "5.4.18-1" };
    uint32_t reqf[] = { 0, 0x4 | 0x8, 0x1000000 | 0x2 };
    headerPutString(h, RPMTAG_NAME, "fuzzpkg");
    headerPutString(h, RPMTAG_VERSION, "1.2.3");
    headerPutString(h, RPMTAG_RELEASE, "4.el9");
    headerPutString(h, RPMTAG_ARCH, "x86_64");
    headerPutString(h, RPMTAG_SUMMARY, "A summary");
    headerPutString(h, RPMTAG_DESCRIPTION, "A longer\ndescription with %{NAME} text");
    headerPutUint32(h, RPMTAG_BUILDTIME, &t, 1);
    headerPutUint32(h, RPMTAG_SIZE, &size, 1);
    headerPutUint32(h, RPMTAG_FILESIZES, fsize, 3);
    headerPutUint32(h, RPMTAG_FILEFLAGS, fflags, 3);
    headerPutUint32(h, RPMTAG_DIRINDEXES, didx, 3);
    headerPutUint16(h, RPMTAG_FILEMODES, fm16, 3);
    (void)mode;
    headerPutStringArray(h, RPMTAG_BASENAMES, base, 3);
    headerPutStringArray(h, RPMTAG_DIRNAMES, dirs, 2);
    headerPutStringArray(h, RPMTAG_FILEDIGESTS, dig, 3);
    headerPutStringArray(h, RPMTAG_REQUIRENAME, reqn, 3);
    headerPutStringArray(h, RPMTAG_REQUIREVERSION, reqv, 3);
    headerPutUint32(h, RPMTAG_REQUIREFLAGS, reqf, 3);
    g_hdr = h;
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::string fmt((const char *)data, size);
    fmt.resize(strlen(fmt.c_str()));
    errmsg_t err = NULL;
    char *s = headerFormat(g_hdr, fmt.c_str(), &err);
    free(s);
    return 0;
}
