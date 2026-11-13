// The rpm expression evaluator behind %[ ... ] and %if, without macro expansion (flags = 0),
// so no input can reach %(...) shell escapes or %{lua:...}.
#include <rpm/rpmlog.h>
#include <rpm/rpmmacro.h>
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
    std::string expr((const char *)data, size);
    expr.resize(strlen(expr.c_str()));
    (void)rpmExprBoolFlags(expr.c_str(), 0);
    free(rpmExprStrFlags(expr.c_str(), 0));
    return 0;
}
