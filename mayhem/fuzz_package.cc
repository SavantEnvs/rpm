// Feeds arbitrary bytes to rpmReadPackageFile(): lead, signature header and main header parsing,
// header sanity checks, then walks every tag, file and dependency of whatever header survives.
#include "harness_common.hh"
#include <rpm/rpmio.h>
#include <rpm/rpmlib.h>
#include <sys/mman.h>
#include <unistd.h>

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    harness_init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int mfd = memfd_create("rpmfuzz", 0);
    if (mfd < 0)
        return -1;
    if (size && write(mfd, data, size) != (ssize_t)size) {
        close(mfd);
        return -1;
    }
    lseek(mfd, 0, SEEK_SET);

    FD_t fd = fdDup(mfd);
    close(mfd);
    if (fd == NULL)
        return -1;

    rpmts ts = rpmtsCreate();
    rpmtsSetRootDir(ts, "/");
    rpmtsSetVSFlags(ts, _RPMVSF_NOSIGNATURES | _RPMVSF_NODIGESTS);

    Header h = NULL;
    rpmRC rc = rpmReadPackageFile(ts, fd, "fuzz.rpm", &h);
    if (h != NULL) {
        walk_header(ts, h);
        headerFree(h);
    }
    (void)rc;

    Fclose(fd);
    rpmtsFree(ts);
    return 0;
}
