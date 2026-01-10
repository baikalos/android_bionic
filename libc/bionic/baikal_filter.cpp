#include "baikal_filter.h"
#include <string.h>
#include <unistd.h>
#include <async_safe/log.h>
#include <sys/prctl.h>
#include <stdarg.h>
#include <sched.h>

#define LOG_TAG "BaikalFS"

#define AID_ISOLATED_START 99000
#define AID_ISOLATED_END   99999

#define AID_SDK_SANDBOX_START 20000
#define AID_SDK_SANDBOX_END   29999

// English comment: Global flags initialized to 0 (disabled)
_Atomic(int) g_filter_active = 0;
_Atomic(int) g_filter_extra  = 0;
_Atomic(int) g_filter_debug  = 0;

// English comment: Direct syscall wrapper for prctl
extern "C" int __prctl(int, unsigned long, unsigned long, unsigned long, unsigned long);

static const char* F_PREFIX[] = {
    "/system/addon.d",
    "/data/adbroot",
    "/sys/fs/selinux/load",
    "/dev/socket/adbd",
    "/sdcard/TWRP",
    "/storage/emulated/0/TWRP",
    "Addon.d",
    "addon.d",
    ".TWRP",
    "TWRP",
    ".ext",
    "/proc/filesystems",
    "/proc/mounts",
    "/proc/self/mounts",
    "/proc/self/filesystems",
    nullptr
};

static const char* F_SUBSTR[] = {
    "zygisk",
    "magisk",
    "system/addon.d",
    "system/Addon.d",
    "com.noshufou.android.su",
    "supersu",
    "busybox",
    "toybox",
    "bin/which",
    "xposed.prop",
    "libxposed",
    "xposed.installer",
    "Xposed",
    "-recovery.sh",
    "vendor_sepolicy.cil",
    "compatibility_matrix.device.xml",
    "gapps.rc",
    "/adb/",
    "/vendor/etc/vintf/manifest/vendor.lineage",
    "apatch",
    "/etc/init/init.lineage",
    "/system/xbin",
    nullptr
};

static const char* F_POSTFIX[] = {
    "/su",
    "/daemonsu",
    "/adbd",
    "/supolicy",
    "/busybox",
    "/vboxuser",
    "/vboxguest",
    "/vboxsf-1",
    "/qemud",
    "/qemu_trace",
    "/qemu_pipe",
    "/rcvboxadd",
    "/bst_gps",
    "/bstfolderd",
    "/bstmods",
    "/noxd",
    "/noxspeedup",
    "/nox-prop",
    "/nox-vbox-sf",
    "/selinux",
    "/install-recovery.sh",
    "/libsupol.so",
    "bin/mount",
    nullptr
};

static const char* F_SUBSTR_EXTRA_EQ[] = {
    "sh",
    "ls",
    "ps",
    "which",
    "mount",
    "umount",
    "cat",
    "getprop",
    nullptr
};

static const char* F_SUBSTR_EXTRA[] = {
    "crdroid",
    "lineage",
    "Lineage",
    "baikal",
    "magisk",
    "supersu",
    "su.d",
    "busybox",
    "daemonsu",
    ".subackup",
    "0_jupiter",       // English comment: Magisk-specific hidden paths
    "amnezia",         // English comment: Popular bypass tools detection
    "/proc/net/unix",  // English comment: Detection of Magisk sockets
    "/proc/mounts",    // English comment: Detection of mounted overlayfs
    "/proc/self/smaps",
    "/proc/self/maps",
    "/proc/self/mountinfo",
    "/bin/sh",
    "jit-zygote-cache (deleted)",
    nullptr
};


// English comment: Internal helper for conditional logging with UID/PID
static bool return_log(const char* name, bool result, const char* rule, int type) {
    if (result && atomic_load(&g_filter_debug)) {
        async_safe_format_log(ANDROID_LOG_DEBUG, LOG_TAG, 
            "baikalfs: blocked [%s] for UID %d (PID %d) rule [%s] type [%d]", 
            name, getuid(), getpid(), rule, type);
    }
    return result;
}

bool is_blacklisted(const char* name) {
    if (!name || name[0] == '\0') return false;

    // 1. Prefix
    for (int i = 0; F_PREFIX[i]; i++) {
        if (strncmp(F_PREFIX[i], name, strlen(F_PREFIX[i])) == 0) 
            return return_log(name, true, F_PREFIX[i], 1);
    }

    // 2. Substring
    for (int i = 0; F_SUBSTR[i]; i++) {
        if (strstr(name, F_SUBSTR[i])) 
            return return_log(name, true, F_SUBSTR[i], 2);
    }

    // 3. Postfix
    size_t n_len = strlen(name);
    for (int i = 0; F_POSTFIX[i]; i++) {
        size_t s_len = strlen(F_POSTFIX[i]);
        if (n_len >= s_len && strcmp(name + n_len - s_len, F_POSTFIX[i]) == 0) 
            return return_log(name, true, F_POSTFIX[i], 3);
    }

    // 4. Extra filtering (if flag 2 is active)
    if (atomic_load(&g_filter_extra)) {
        for (int i = 0; F_SUBSTR_EXTRA[i]; i++) {
            if (strstr(name, F_SUBSTR_EXTRA[i])) 
                return return_log(name, true, F_SUBSTR_EXTRA[i], 4);
        }
    }

    // 5. Extra EQ filtering (if flag 2 is active)
    if (atomic_load(&g_filter_extra)) {
        size_t n_len = strlen(name);
        for (int i = 0; F_SUBSTR_EXTRA_EQ[i]; i++) {
            size_t s_len = strlen(F_SUBSTR_EXTRA_EQ[i]);
            size_t len = s_len > n_len ? s_len : n_len;
            if (strncmp(name, F_SUBSTR_EXTRA_EQ[i], len) == 0) 
                return return_log(name, true, F_SUBSTR_EXTRA_EQ[i], 5);
        }
    }

    if (atomic_load(&g_filter_debug)) {
        async_safe_format_log(ANDROID_LOG_DEBUG, LOG_TAG, "baikalfs: allowed [%s] for UID %d (PID %d)", 
                              name, getuid(), getpid());
    }
    return false;
}

// English comment: 0 - not started, 1 - in progress, 2 - done
static _Atomic(int) g_env_init_state = 0;

// English comment: Thread-safe environment sync
static void sync_env_flags() {
    int expected = 0;
    // English comment: Only one thread will succeed in changing state 0 -> 1
    if (atomic_compare_exchange_strong(&g_env_init_state, &expected, 1)) {
        
        if (getenv("BAIKAL_FILTER_ACTIVE")) atomic_store(&g_filter_active, 1);
        if (getenv("BAIKAL_FILTER_EXTRA"))  atomic_store(&g_filter_extra, 1);
        if (getenv("BAIKAL_FILTER_DEBUG"))  atomic_store(&g_filter_debug, 1);
        
        // English comment: Initialization complete
        atomic_store(&g_env_init_state, 2);
    } else {
        // English comment: If another thread is initializing, wait for it (spin-lock)
        while (atomic_load(&g_env_init_state) == 1) {
            sched_yield(); 
        }
    }
}

bool is_caller_filtered() {
    // English comment: Fast check if already initialized
    if (atomic_load(&g_env_init_state) != 2) {
        sync_env_flags();
    }

    // 2. Check if filter is active via prctl or env
    if (atomic_load(&g_filter_active) != 0) return true;

    // 3. Fallback for Sandbox/Isolated
    uid_t uid = getuid();
    if ((uid >= AID_ISOLATED_START && uid <= AID_ISOLATED_END) ||
        (uid >= AID_SDK_SANDBOX_START && uid <= AID_SDK_SANDBOX_END)) {
        
        // English comment: Always force EXTRA mode for Sandboxes to be safe
        atomic_store(&g_filter_extra, 1); 
        return true;
    }

    return false;
}

extern "C" __attribute__((weak)) int prctl(int option, ...) {
    va_list args;
    va_start(args, option);
    
    // English comment: Extract all 4 potential arguments as unsigned long
    unsigned long arg2 = va_arg(args, unsigned long);
    unsigned long arg3 = va_arg(args, unsigned long);
    unsigned long arg4 = va_arg(args, unsigned long);
    unsigned long arg5 = va_arg(args, unsigned long);
    
    va_end(args);

    if (option == 0x626169) {
        // English comment: Using static_cast to satisfy -Wold-style-cast
        int val = static_cast<int>(arg3);
        switch (arg2) {
            case 1: 
                atomic_store(&g_filter_active, val);
                setenv("BAIKAL_FILTER_ACTIVE", val ? "1" : "0", 1);
                break;
            case 2: 
                atomic_store(&g_filter_extra, val);
                setenv("BAIKAL_FILTER_EXTRA", val ? "1" : "0", 1);
                break;
            case 3: 
                atomic_store(&g_filter_debug, val);
                setenv("BAIKAL_FILTER_DEBUG", val ? "1" : "0", 1);
                break;
        }
        
        if (atomic_load(&g_filter_debug)) {
            async_safe_format_log(ANDROID_LOG_DEBUG, LOG_TAG, 
                "baikalfs: flag %lu set to %lu for UID %d (PID %d)", 
                arg2, arg3, getuid(), getpid());
        }
        return 0;
    }

    // English comment: Pass arguments to the real syscall
    return __prctl(option, arg2, arg3, arg4, arg5);
}

struct linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

int filter_dirent_buffer(void* buffer, int ret) {
    if (ret <= 0 || !is_caller_filtered()) return ret;

    int bpos = 0;
    while (bpos < ret) {
        struct linux_dirent64* d = reinterpret_cast<linux_dirent64*>(static_cast<char*>(buffer) + bpos);
        if (is_blacklisted(d->d_name)) {
            int reclen = d->d_reclen;
            int remaining = ret - (bpos + reclen);
            if (remaining > 0) memmove(d, reinterpret_cast<char*>(d) + reclen, remaining);
            ret -= reclen;
            continue;
        }
        bpos += d->d_reclen;
    }
    return ret;
}