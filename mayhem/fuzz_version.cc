// Version and dependency-EVR parsing/comparison: rpmvercmp, rpmverParse/rpmverCmp, rpmdsCompare.
#include <rpm/rpmds.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmtag.h>
#include <rpm/rpmver.h>
#include <stdlib.h>
#include <string.h>
#include <string>

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    rpmlogSetMask(RPMLOG_MASK(RPMLOG_EMERG));
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return -1;
    // byte 0 selects the sense flags; the rest is two strings separated by the first NUL or newline
    static const rpmsenseFlags sense[] = { RPMSENSE_EQUAL, RPMSENSE_LESS, RPMSENSE_GREATER,
        (rpmsenseFlags)(RPMSENSE_LESS | RPMSENSE_EQUAL), (rpmsenseFlags)(RPMSENSE_GREATER | RPMSENSE_EQUAL) };
    rpmsenseFlags f1 = sense[data[0] % 5];
    rpmsenseFlags f2 = sense[(data[0] / 5) % 5];
    std::string all((const char *)data + 1, size - 1);
    size_t cut = all.find_first_of(std::string("\0\n", 2));
    std::string a = all.substr(0, cut);
    std::string b = cut == std::string::npos ? std::string() : all.substr(cut + 1);
    a.resize(strlen(a.c_str()));
    b.resize(strlen(b.c_str()));

    int c1 = rpmvercmp(a.c_str(), b.c_str());
    int c2 = rpmvercmp(b.c_str(), a.c_str());
    if (c1 != -c2)
        abort();  // rpmvercmp must be antisymmetric

    rpmver va = rpmverParse(a.c_str());
    rpmver vb = rpmverParse(b.c_str());
    if (va && vb) {
        (void)rpmverCmp(va, vb);
        free(rpmverEVR(va));
        free(rpmverEVR(vb));
    }
    rpmverFree(va);
    rpmverFree(vb);

    rpmds da = rpmdsSingle(RPMTAG_PROVIDENAME, "pkg", a.c_str(), f1);
    rpmds db = rpmdsSingle(RPMTAG_REQUIRENAME, "pkg", b.c_str(), f2);
    if (da && db)
        (void)rpmdsCompare(da, db);
    rpmdsFree(da);
    rpmdsFree(db);
    return 0;
}
