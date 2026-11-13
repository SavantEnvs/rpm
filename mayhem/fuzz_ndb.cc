// Opens an rpm database directory holding fuzzed ndb backend files (Packages.db plus the Index.db index,
// Index.db) read-only and iterates every package and a name lookup.
#include <rpm/header.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmmacro.h>
#include <rpm/rpmts.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>

static std::string g_base;

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    rpmlogSetMask(RPMLOG_MASK(RPMLOG_EMERG));
    const char *tmp = getenv("TMPDIR");
    g_base = std::string(tmp && *tmp ? tmp : "/tmp") + "/rpmfuzz-ndb-XXXXXX";
    std::string dir = g_base;
    if (!mkdtemp(&dir[0]))
        abort();
    g_base = dir;
    rpmPushMacro(NULL, "_db_backend", NULL, "ndb", 0);
    rpmPushMacro(NULL, "_dbpath", NULL, g_base.c_str(), 0);
    return 0;
}

static bool put(const std::string &path, const uint8_t *p, size_t n)
{
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return false;
    bool ok = n == 0 || write(fd, p, n) == (ssize_t)n;
    close(fd);
    return ok;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 4)
        return -1;
    // input = 4-byte big-endian length of Packages.db, then Packages.db, then Index.db
    const uint8_t *body = data + 4;
    size_t bsize = size - 4;
    size_t cut = ((size_t)data[0] << 24 | (size_t)data[1] << 16 | (size_t)data[2] << 8 | data[3]);
    cut = cut > bsize ? bsize : cut;
    std::string pk = g_base + "/Packages.db", nm = g_base + "/Index.db";
    if (!put(pk, body, cut) || !put(nm, body + cut, bsize - cut))
        return -1;

    rpmts ts = rpmtsCreate();
    rpmtsSetRootDir(ts, "/");
    if (rpmtsOpenDB(ts, O_RDONLY) == 0) {
        rpmdbMatchIterator mi = rpmdbInitIterator(rpmtsGetRdb(ts), RPMDBI_PACKAGES, NULL, 0);
        Header h;
        int n = 0;
        while (mi && (h = rpmdbNextIterator(mi)) != NULL && n++ < 256) {
            char *s = headerFormat(h, "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}", NULL);
            free(s);
        }
        rpmdbFreeIterator(mi);
        mi = rpmdbInitIterator(rpmtsGetRdb(ts), RPMDBI_NAME, "hello", 0);
        while (mi && (h = rpmdbNextIterator(mi)) != NULL && n++ < 256)
            ;
        rpmdbFreeIterator(mi);
    }
    rpmtsCloseDB(ts);
    rpmtsFree(ts);
    unlink(pk.c_str());
    unlink(nm.c_str());
    unlink((g_base + "/.rpm.lock").c_str());
    return 0;
}
