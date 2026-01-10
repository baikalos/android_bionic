#pragma once

#include <stdint.h>
#include <stdatomic.h>
#include <sys/types.h>

// English comment: Filter control flags
extern "C" _Atomic(int) g_filter_active;
extern "C" _Atomic(int) g_filter_extra;
extern "C" _Atomic(int) g_filter_debug;

// English comment: Public interface
extern "C" bool is_caller_filtered();
extern "C" bool is_blacklisted(const char* name);
extern "C" int filter_dirent_buffer(void* buffer, int ret);
