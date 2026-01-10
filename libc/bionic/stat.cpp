/*
 * Copyright (C) 2013 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include "baikal_filter.h"

extern "C" int __fstatat(int, const char*, struct stat*, int);

int fstatat(int dirfd, const char* pathname, struct stat* sb, int flags) {
    if (is_caller_filtered() && is_blacklisted(pathname)) {
        errno = ENOENT; 
        return -1;
    }
    return __fstatat(dirfd, pathname, sb, flags);
}

__strong_alias(fstatat64, fstatat);

int stat(const char* path, struct stat* sb) {
  return fstatat(AT_FDCWD, path, sb, 0);
}
__strong_alias(stat64, stat);

extern "C" int __utimensat(int, const char*, const struct timespec[2], int);

int utimensat(int dirfd, const char* pathname, const struct timespec times[2], int flags) {
    if (is_caller_filtered() && is_blacklisted(pathname)) {
        errno = ENOENT; 
        return -1;
    }
    return __utimensat(dirfd, pathname, times, flags);
}

__strong_alias(utimensat64, utimensat);
