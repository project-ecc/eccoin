//
// Created by parallels on 8/14/17.
//

#include "fs.h"

namespace fsbridge {

    FILE *fopen(const fs::path& p, const char *mode)
    {
        return ::fopen(p.string().c_str(), mode);
    }

    FILE *freopen(const fs::path& p, const char *mode, FILE *stream)
    {
        return ::freopen(p.string().c_str(), mode, stream);
    }

} // fsbridge
