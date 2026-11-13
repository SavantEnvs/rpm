// Shared helpers for the rpm fuzz harnesses: header walking that touches every tag extension,
// file-info and dependency-set readers.
#pragma once

#include <rpm/header.h>
#include <rpm/rpmds.h>
#include <rpm/rpmfi.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmtag.h>
#include <rpm/rpmtd.h>
#include <rpm/rpmts.h>
#include <stdlib.h>
#include <vector>

static std::vector<rpmTagVal> g_all_tags;

static void harness_init(void)
{
    rpmlogSetMask(RPMLOG_MASK(RPMLOG_EMERG));
    struct rpmtd_s names;
    if (rpmTagGetNames(&names, 1) > 0) {
        const char *n;
        while ((n = rpmtdNextString(&names)) != NULL) {
            rpmTagVal t = rpmTagGetValue(n);
            if (t != RPMTAG_NOT_FOUND)
                g_all_tags.push_back(t);
        }
        rpmtdFreeData(&names);
    }
}

static void touch_td(rpmtd td)
{
    volatile unsigned sink = 0;
    int n = rpmtdCount(td);
    if (n > 64) n = 64;
    for (int i = 0; i < n; i++) {
        td->ix = i;
        switch (rpmtdType(td)) {
        case RPM_STRING_TYPE:
        case RPM_STRING_ARRAY_TYPE:
        case RPM_I18NSTRING_TYPE: {
            const char *s = rpmtdGetString(td);
            if (s) sink += (unsigned char)s[0];
            break;
        }
        case RPM_INT64_TYPE: sink += (unsigned)*rpmtdGetUint64(td); break;
        case RPM_INT32_TYPE: sink += *rpmtdGetUint32(td); break;
        case RPM_INT16_TYPE: sink += *rpmtdGetUint16(td); break;
        default: break;
        }
        char *f = rpmtdFormat(td, RPMTD_FORMAT_STRING, NULL);
        free(f);
    }
    (void)sink;
}

static void walk_header(rpmts ts, Header h)
{
    HeaderIterator hi = headerInitIterator(h);
    struct rpmtd_s td;
    while (headerNext(hi, &td)) {
        touch_td(&td);
        rpmtdFreeData(&td);
    }
    headerFreeIterator(hi);

    for (rpmTagVal t : g_all_tags) {
        if (headerGet(h, t, &td, HEADERGET_EXT)) {
            touch_td(&td);
            rpmtdFreeData(&td);
        }
    }

    char *s = headerFormat(h,
        "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH} %{SIZE} %{BUILDTIME:date} %{SIGMD5:hex} "
        "%{SUMMARY} [%{FILENAMES} %{FILEMODE:perms} %{FILEMODE:octal} %{FILESIZES} %{FILEDIGESTS} "
        "%{FILEFLAGS:fflags} %{FILESTATES:fstate} %{FILELINKTOS} %{FILEDEPENDSX} %{FILESIGNATURES}\n]"
        "[%{REQUIRENAME} %{REQUIREFLAGS:depflags} %{REQUIREVERSION}\n]%{DESCRIPTION} %{DSAHEADER:pgpsig}",
        NULL);
    free(s);

    rpmTagVal deps[] = { RPMTAG_PROVIDENAME, RPMTAG_REQUIRENAME, RPMTAG_CONFLICTNAME,
                         RPMTAG_OBSOLETENAME, RPMTAG_RECOMMENDNAME, RPMTAG_SUGGESTNAME,
                         RPMTAG_SUPPLEMENTNAME, RPMTAG_ENHANCENAME, RPMTAG_ORDERNAME,
                         RPMTAG_TRIGGERNAME, RPMTAG_FILETRIGGERNAME, RPMTAG_TRANSFILETRIGGERNAME };
    for (rpmTagVal t : deps) {
        rpmds ds = rpmdsNew(h, t, 0);
        if (ds) {
            rpmds it = rpmdsInit(ds);
            while (rpmdsNext(it) >= 0)
                (void)rpmdsDNEVR(it);
            rpmdsFree(ds);
        }
    }

    rpmfi fi = rpmfiNew(ts, h, RPMTAG_BASENAMES, RPMFI_FLAGS_QUERY);
    if (fi) {
        rpmfiInit(fi, 0);
        int n = 0;
        while (rpmfiNext(fi) >= 0 && n++ < 4096) {
            int algo;
            size_t len;
            (void)rpmfiFN(fi);
            (void)rpmfiFLink(fi);
            (void)rpmfiFClass(fi);
            (void)rpmfiFSignature(fi, &len);
            free(rpmfiFDigestHex(fi, &algo));
            const int *links;
            (void)rpmfiFLinks(fi, &links);
        }
        rpmfiFree(fi);
    }

    unsigned int sz = 0;
    free(headerExport(h, &sz));
}
