/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include "system_properties/system_properties.h"

#include <errno.h>
#include <private/android_filesystem_config.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <new>

#include <async_safe/CHECK.h>
#include <async_safe/log.h>

#include "private/ErrnoRestorer.h"
#include "private/bionic_futex.h"

#include "system_properties/context_node.h"
#include "system_properties/prop_area.h"
#include "system_properties/prop_info.h"

#define SERIAL_DIRTY(serial) ((serial)&1)
#define SERIAL_VALUE_LEN(serial) ((serial) >> 24)
#define APPCOMPAT_PREFIX "ro.appcompat_override."

extern _Atomic(int) g_filter_active;
extern _Atomic(int) g_filter_extra;
extern _Atomic(int) g_filter_debug;
extern _Atomic(int) g_filter_spoofer;
extern _Atomic(int) g_filter_adb;

static bool is_dir(const char* pathname) {
  struct stat info;
  if (stat(pathname, &info) == -1) {
    return false;
  }
  return S_ISDIR(info.st_mode);
}

bool SystemProperties::Init(const char* filename) {
  // This is called from __libc_init_common, and should leave errno at 0 (http://b/37248982).
  ErrnoRestorer errno_restorer;

  if (initialized_) {
    contexts_->ResetAccess();
    return true;
  }

  properties_filename_ = filename;

  if (!InitContexts(false)) {
    return false;
  }

  initialized_ = true;
  return true;
}

bool SystemProperties::InitContexts(bool load_default_path) {
  if (is_dir(properties_filename_.c_str())) {
    if (access(PROP_TREE_FILE, R_OK) == 0) {
      auto serial_contexts = new (contexts_data_) ContextsSerialized();
      contexts_ = serial_contexts;
      if (!serial_contexts->Initialize(false, properties_filename_.c_str(), nullptr,
                                       load_default_path)) {
        return false;
      }
    } else {
      contexts_ = new (contexts_data_) ContextsSplit();
      if (!contexts_->Initialize(false, properties_filename_.c_str(), nullptr)) {
        return false;
      }
    }
  } else {
    contexts_ = new (contexts_data_) ContextsPreSplit();
    if (!contexts_->Initialize(false, properties_filename_.c_str(), nullptr)) {
      return false;
    }
  }
  return true;
}

bool SystemProperties::AreaInit(const char* filename, bool* fsetxattr_failed) {
  return AreaInit(filename, fsetxattr_failed, false);
}

// Note: load_default_path is only used for testing, as it will cause properties to be loaded from
// one file (specified by PropertyInfoAreaFile.LoadDefaultPath), but be written to "filename".
bool SystemProperties::AreaInit(const char* filename, bool* fsetxattr_failed,
                                bool load_default_path) {
  properties_filename_ = filename;
  auto serial_contexts = new (contexts_data_) ContextsSerialized();
  contexts_ = serial_contexts;
  if (!serial_contexts->Initialize(true, properties_filename_.c_str(), fsetxattr_failed,
                                   load_default_path)) {
    return false;
  }

  appcompat_filename_ = PropertiesFilename(properties_filename_.c_str(), "appcompat_override");
  appcompat_override_contexts_ = nullptr;
  if (access(appcompat_filename_.c_str(), F_OK) != -1) {
    auto* appcompat_contexts = new (appcompat_override_contexts_data_) ContextsSerialized();
    if (!appcompat_contexts->Initialize(true, appcompat_filename_.c_str(), fsetxattr_failed,
                                        load_default_path)) {
      // The appcompat folder exists, but initializing it failed
      return false;
    } else {
      appcompat_override_contexts_ = appcompat_contexts;
    }
  }

  initialized_ = true;
  return true;
}

bool SystemProperties::Reload(bool load_default_path) {
  if (!initialized_) {
    return true;
  }

  return InitContexts(load_default_path);
}

uint32_t SystemProperties::AreaSerial() {
  if (!initialized_) {
    return -1;
  }

  prop_area* pa = contexts_->GetSerialPropArea();
  if (!pa) {
    return -1;
  }

  // Make sure this read fulfilled before __system_property_serial
  return atomic_load_explicit(pa->serial(), memory_order_acquire);
}

const prop_info* SystemProperties::Find(const char* name) {
  if (!initialized_) {
    return nullptr;
  }

  prop_area* pa = contexts_->GetPropAreaForName(name);
  if (!pa) {
    async_safe_format_log(ANDROID_LOG_WARN, "libc", "Access denied finding property \"%s\"", name);
    return nullptr;
  }

  return pa->find(name);
}

static bool is_appcompat_override(const char* name) {
  return strncmp(name, APPCOMPAT_PREFIX, strlen(APPCOMPAT_PREFIX)) == 0;
}

static bool is_read_only(const char* name) {
  return strncmp(name, "ro.", 3) == 0;
}

static bool overrideMutableKeyValue(const char *key, const char *value, const char* name,  char *value_buf) {
    if( strstr(name,key) != NULL ) {
        memcpy(value_buf,value,strlen(value)+1);
        return true;
    }
    return false;
}

static bool overrideMutableValue(const char* key, char *value_buf) {

    if( !g_filter_adb ) return false;
    if( overrideMutableKeyValue("ro.adb.secure","1",key,value_buf) ) return true;

    if( overrideMutableKeyValue("sys.usb.config","mtp",key,value_buf) ) return true;
    if( overrideMutableKeyValue("persist.sys.usb.config","mtp",key,value_buf) ) return true;

    if( overrideMutableKeyValue("init.svc.adbd","stopped",key,value_buf) ) return true;
    if( overrideMutableKeyValue("init.svc.adb_root","stopped",key,value_buf) ) return true;
    if( overrideMutableKeyValue("init.svc_debug_pid.adbd","",key,value_buf) ) return true;
    if( overrideMutableKeyValue("sys.usb.adb.disabled","1",key,value_buf) ) return true;


    if( overrideMutableKeyValue("ro.boottime.adbd","",key,value_buf) ) return true;
    if( overrideMutableKeyValue("init.svc_debug_pid","",key,value_buf) ) return true;
    if( overrideMutableKeyValue("persist.adb.","",key,value_buf) ) return true;

    if( overrideMutableKeyValue("vendor.sys.usb.adb.disabled","1",key,value_buf) ) return true;
    if( overrideMutableKeyValue("vendor.usb.config","mtp",key,value_buf) ) return true;
    if( overrideMutableKeyValue("adb","0",key,value_buf) ) return true;
    return false;
}


uint32_t SystemProperties::ReadMutablePropertyValue(const prop_info* pi, char* value) {
  // We assume the memcpy below gets serialized by the acquire fence.
  uint32_t new_serial = load_const_atomic(&pi->serial, memory_order_acquire);
  uint32_t serial;
  unsigned int len;
  for (;;) {
    serial = new_serial;
    len = SERIAL_VALUE_LEN(serial);
    if (__predict_false(SERIAL_DIRTY(serial))) {
      // See the comment in the prop_area constructor.
      prop_area* pa = contexts_->GetPropAreaForName(pi->name);
      memcpy(value, pa->dirty_backup_area(), len + 1);
    } else {
      memcpy(value, pi->value, len + 1);
    }

    overrideMutableValue(pi->name, value);

    atomic_thread_fence(memory_order_acquire);
    new_serial = load_const_atomic(&pi->serial, memory_order_relaxed);
    if (__predict_true(serial == new_serial)) {
      break;
    }
    // We need another fence here because we want to ensure that the memcpy in the
    // next iteration of the loop occurs after the load of new_serial above. We could
    // get this guarantee by making the load_const_atomic of new_serial
    // memory_order_acquire instead of memory_order_relaxed, but then we'd pay the
    // penalty of the memory_order_acquire even in the overwhelmingly common case
    // that the serial number didn't change.
    atomic_thread_fence(memory_order_acquire);
  }
  return serial;
}

int SystemProperties::Read(const prop_info* pi, char* name, char* value) {
  uint32_t serial = ReadMutablePropertyValue(pi, value);
  if (name != nullptr) {
    size_t namelen = strlcpy(name, pi->name, PROP_NAME_MAX);
    if (namelen >= PROP_NAME_MAX) {
      async_safe_format_log(ANDROID_LOG_ERROR, "libc",
                            "The property name length for \"%s\" is >= %d;"
                            " please use __system_property_read_callback"
                            " to read this property. (the name is truncated to \"%s\")",
                            pi->name, PROP_NAME_MAX - 1, name);
    }
  }
  if (is_read_only(pi->name) && pi->is_long()) {
    async_safe_format_log(
        ANDROID_LOG_ERROR, "libc",
        "The property \"%s\" has a value with length %zu that is too large for"
        " __system_property_get()/__system_property_read(); use"
        " __system_property_read_callback() instead.",
        pi->name, strlen(pi->long_value()));
  } else {
    if( g_filter_debug ) {
      async_safe_format_log(ANDROID_LOG_INFO, "BaikalBionic", "BAIKAL_LOG LG | UID: %d | PID: %d | PROC: %s | PROP: %s | VALUE: %s | RETURN: %s", (int)getuid(), (int)getpid(), (getprogname() ? getprogname() : "unknown"), pi->name, pi->value, value);
    }
  }

  return SERIAL_VALUE_LEN(serial);
}

bool overrideValue(const char *name, const char *ovr, void* cookie, const char *key, const char *value, uint32_t serial,
                                    void (*callback)(void* cookie, const char* name,
                                                     const char* value, uint32_t serial) ) {
    char value_buf[PROP_VALUE_MAX];

    (void)value;

    if (strstr(key, name) != NULL) {
        strlcpy(value_buf, ovr, PROP_VALUE_MAX);
        callback(cookie, key, value_buf, serial);

        if( g_filter_debug ) {
            async_safe_format_log(ANDROID_LOG_INFO, "BaikalBionic", "BAIKAL_LOG | UID: %d | PID: %d | PROC: %s | PROP: %s | VALUE: %s | OVERRIDE: %s", 
            (int)getuid(), (int)getpid(), (getprogname() ? getprogname() : "unknown"), key, value, value_buf);
        }

        return true;
    }

    return false;
}

bool overridePropertyValue(void* cookie, const char *key, const char *value, uint32_t serial,
                                    void (*callback)(void* cookie, const char* name,
                                                     const char* value, uint32_t serial) ) {


    char value_buf[PROP_VALUE_MAX];

    (void)value;

    if (strcmp(key, "ro.baikal.build.date.utc") == 0) {
        strlcpy(value_buf, "1767991008", PROP_VALUE_MAX);
        callback(cookie, key, value_buf, serial);
        return true;
    }

    /*
    if (strcmp(key, "ro.vendor.api_level") == 0) {
        strlcpy(value_buf, "34", PROP_VALUE_MAX);
        callback(cookie, key, value_buf, serial);
        return true;
    }

    if (strcmp(key, "ro.product.first_api_level") == 0) {
        strlcpy(value_buf, "34", PROP_VALUE_MAX);
        callback(cookie, key, value_buf, serial);
        return true;
    }

    if (strcmp(key, "ro.build.version.security_patch") == 0) {
        strlcpy(value_buf, "2026-01-05", PROP_VALUE_MAX);
        callback(cookie, key, value_buf, serial);
        return true;
    }*/

    return false;
}



bool overrideAdbPropertyValue(void* cookie, const char *key, const char *value, uint32_t serial,
                                    void (*callback)(void* cookie, const char* name,
                                                     const char* value, uint32_t serial) ) {


    if ( overrideValue("ro.adb.secure","1",cookie,key,value,serial,callback) ) return true;

    if ( overrideValue("sys.usb.config","mtp",cookie,key,value,serial,callback) ) return true;
    if ( overrideValue("persist.sys.usb.config","mtp",cookie,key,value,serial,callback) ) return true;

    if ( overrideValue("init.svc.adbd","stopped",cookie,key,value,serial,callback) ) return true;
    if ( overrideValue("init.svc.adb_root","stopped",cookie,key,value,serial,callback) ) return true;
    if ( overrideValue("init.svc_debug_pid.adbd","",cookie,key,value,serial,callback) ) return true;
    if ( overrideValue("sys.usb.adb.disabled","1",cookie,key,value,serial,callback) ) return true;


    if ( overrideValue("ro.boottime.adbd","",cookie,key,value,serial,callback) ) return true;
    if ( overrideValue("init.svc_debug_pid","",cookie,key,value,serial,callback) ) return true;
    if ( overrideValue("persist.adb.","",cookie,key,value,serial,callback) ) return true;

    if ( overrideValue("vendor.sys.usb.adb.disabled","1",cookie,key,value,serial,callback) ) return true;
    if ( overrideValue("vendor.usb.config","mtp",cookie,key,value,serial,callback) ) return true;
    if ( overrideValue("adb","0",cookie,key,value,serial,callback) ) return true;

    //if ( overrideValue("persist.adb.","",key,value,serial,callback) ) return true;

    return false;
}


void SystemProperties::ReadCallback(const prop_info* pi,
                                    void (*callback)(void* cookie, const char* name,
                                                     const char* value, uint32_t serial),
                                    void* cookie) {
  // Read only properties don't need to copy the value to a temporary buffer, since it can never
  // change.  We use relaxed memory order on the serial load for the same reason.
  if (is_read_only(pi->name)) {
    uint32_t serial = load_const_atomic(&pi->serial, memory_order_relaxed);
    if (pi->is_long()) {
      if( g_filter_debug ) {
        async_safe_format_log(ANDROID_LOG_INFO, "BaikalBionic", "BAIKAL_LOG RO LONG | UID: %d | PID: %d | PROC: %s | PROP: %s | VALUE: %s", (int)getuid(), (int)getpid(), (getprogname() ? getprogname() : "unknown"), pi->name, pi->long_value());
      }
      callback(cookie, pi->name, pi->long_value(), serial);
    } else {
      if( g_filter_adb && overrideAdbPropertyValue(cookie,pi->name, pi->value,serial,callback) ) return;
      if( g_filter_spoofer && overridePropertyValue(cookie,pi->name, pi->value,serial,callback) ) return;
      if( g_filter_debug ) {
        async_safe_format_log(ANDROID_LOG_INFO, "BaikalBionic", "BAIKAL_LOG RO | UID: %d | PID: %d | PROC: %s | PROP: %s | VALUE: %s", (int)getuid(), (int)getpid(), (getprogname() ? getprogname() : "unknown"), pi->name, pi->value);
      }
      callback(cookie, pi->name, pi->value, serial);
    }

    return;
  }

  char value_buf[PROP_VALUE_MAX];
  uint32_t serial = ReadMutablePropertyValue(pi, value_buf);
  if( g_filter_adb && overrideAdbPropertyValue(cookie,pi->name, value_buf,serial,callback) ) return;
  if( g_filter_spoofer && overridePropertyValue(cookie,pi->name, value_buf,serial,callback) ) return;
  if( g_filter_debug ) {
    async_safe_format_log(ANDROID_LOG_INFO, "BaikalBionic", "BAIKAL_LOG | UID: %d | PID: %d | PROC: %s | PROP: %s | VALUE: %s", (int)getuid(), (int)getpid(), (getprogname() ? getprogname() : "unknown"), pi->name, value_buf);
  }
  callback(cookie, pi->name, value_buf, serial);
}

int SystemProperties::Get(const char* name, char* value) {
  const prop_info* pi = Find(name);

  if (pi != nullptr) {
    return Read(pi, nullptr, value);
  } else {
    value[0] = 0;
    return 0;
  }
}

int SystemProperties::Update(prop_info* pi, const char* value, unsigned int len) {
  if (len >= PROP_VALUE_MAX) {
    return -1;
  }

  if (!initialized_) {
    return -1;
  }
  bool have_override = appcompat_override_contexts_ != nullptr;

  prop_area* serial_pa = contexts_->GetSerialPropArea();
  prop_area* override_serial_pa =
      have_override ? appcompat_override_contexts_->GetSerialPropArea() : nullptr;
  if (!serial_pa) {
    return -1;
  }
  prop_area* pa = contexts_->GetPropAreaForName(pi->name);
  prop_area* override_pa =
      have_override ? appcompat_override_contexts_->GetPropAreaForName(pi->name) : nullptr;
  if (__predict_false(!pa)) {
    async_safe_format_log(ANDROID_LOG_ERROR, "libc", "Could not find area for \"%s\"", pi->name);
    return -1;
  }
  CHECK(!have_override || (override_pa && override_serial_pa));

  auto* override_pi = const_cast<prop_info*>(have_override ? override_pa->find(pi->name) : nullptr);

  uint32_t serial = atomic_load_explicit(&pi->serial, memory_order_relaxed);
  unsigned int old_len = SERIAL_VALUE_LEN(serial);

  // The contract with readers is that whenever the dirty bit is set, an undamaged copy
  // of the pre-dirty value is available in the dirty backup area. The fence ensures
  // that we publish our dirty area update before allowing readers to see a
  // dirty serial.
  memcpy(pa->dirty_backup_area(), pi->value, old_len + 1);
  if (have_override) {
    memcpy(override_pa->dirty_backup_area(), override_pi->value, old_len + 1);
  }
  serial |= 1;
  atomic_store_explicit(&pi->serial, serial, memory_order_release);
  atomic_thread_fence(memory_order_release);  // Order preceding store w.r.t. memcpy().
  memcpy(pi->value, value, len + 1);
  // TODO: Eventually replace the above with something like atomic_store_per_byte_memcpy from
  // wg21.link/p1478 . This is needed for the preceding memcpy and the reader-side copies as well.
  // In general, memcpy uses near atomic_thread_fence() are suspect.
  if (have_override) {
    atomic_store_explicit(&override_pi->serial, serial, memory_order_relaxed);
    memcpy(override_pi->value, value, len + 1);
  }
  // Now the primary value property area is up-to-date. Let readers know that they should
  // look at the property value instead of the backup area.
  int new_serial = (len << 24) | ((serial + 1) & 0xffffff);
  atomic_store_explicit(&pi->serial, new_serial, memory_order_release);
  if (have_override) {
    atomic_store_explicit(&override_pi->serial, new_serial, memory_order_relaxed);
  }
  // Implicitly includes a fence to ensure the serial number update becomes visible before
  // we reuse the backup area the next time.
  __futex_wake(&pi->serial, INT32_MAX);
  atomic_store_explicit(serial_pa->serial(),
                        atomic_load_explicit(serial_pa->serial(), memory_order_relaxed) + 1,
                        memory_order_release);
  if (have_override) {
    atomic_store_explicit(override_serial_pa->serial(),
                          atomic_load_explicit(serial_pa->serial(), memory_order_relaxed) + 1,
                          memory_order_release);
  }
  __futex_wake(serial_pa->serial(), INT32_MAX);

  return 0;
}

int SystemProperties::Add(const char* name, unsigned int namelen, const char* value,
                          unsigned int valuelen) {
  if (namelen < 1) {
    async_safe_format_log(ANDROID_LOG_ERROR, "libc",
                          "__system_property_add failed: name length 0");
    return -1;
  }

  if (valuelen >= PROP_VALUE_MAX && !is_read_only(name)) {
    async_safe_format_log(ANDROID_LOG_ERROR, "libc",
                          "__system_property_add failed: \"%s\" value too long: %d >= PROP_VALUE_MAX",
                          name, valuelen);
    return -1;
  }

  if (!initialized_) {
    async_safe_format_log(ANDROID_LOG_ERROR, "libc",
                          "__system_property_add failed: properties not initialized");
    return -1;
  }

  prop_area* serial_pa = contexts_->GetSerialPropArea();
  if (serial_pa == nullptr) {
    async_safe_format_log(ANDROID_LOG_ERROR, "libc",
                          "__system_property_add failed: property area not found");
    return -1;
  }

  prop_area* pa = contexts_->GetPropAreaForName(name);
  if (!pa) {
    async_safe_format_log(ANDROID_LOG_ERROR, "libc",
                          "__system_property_add failed: access denied for \"%s\"", name);
    return -1;
  }

  if (!pa->add(name, namelen, value, valuelen)) {
    async_safe_format_log(ANDROID_LOG_ERROR, "libc",
                          "__system_property_add failed: add failed for \"%s\"", name);
    return -1;
  }

  if (appcompat_override_contexts_ != nullptr) {
    bool is_override = is_appcompat_override(name);
    const char* override_name = name;
    if (is_override) override_name += strlen(APPCOMPAT_PREFIX);
    prop_area* other_pa = appcompat_override_contexts_->GetPropAreaForName(override_name);
    prop_area* other_serial_pa = appcompat_override_contexts_->GetSerialPropArea();
    CHECK(other_pa && other_serial_pa);
    // We may write a property twice to overrides, once for the ro.*, and again for the
    // ro.appcompat_override.ro.* property. If we've already written, then we should essentially
    // perform an Update, not an Add.
    auto other_pi = const_cast<prop_info*>(other_pa->find(override_name));
    if (!other_pi) {
      if (other_pa->add(override_name, strlen(override_name), value, valuelen)) {
        atomic_store_explicit(
            other_serial_pa->serial(),
            atomic_load_explicit(other_serial_pa->serial(), memory_order_relaxed) + 1,
            memory_order_release);
      }
    } else if (is_override) {
      // We already wrote the ro.*, but appcompat_override.ro.* should override that. We don't
      // need to do the usual dirty bit setting, as this only happens during the init process,
      // before any readers are started. Check that only init or root can write appcompat props.
      CHECK(getpid() == 1 || getuid() == 0);
      atomic_thread_fence(memory_order_release);
      memcpy(other_pi->value, value, valuelen + 1);
    }
  }

  // There is only a single mutator, but we want to make sure that
  // updates are visible to a reader waiting for the update.
  atomic_store_explicit(serial_pa->serial(),
                        atomic_load_explicit(serial_pa->serial(), memory_order_relaxed) + 1,
                        memory_order_release);
  __futex_wake(serial_pa->serial(), INT32_MAX);
  return 0;
}

uint32_t SystemProperties::WaitAny(uint32_t old_serial) {
  uint32_t new_serial;
  Wait(nullptr, old_serial, &new_serial, nullptr);
  return new_serial;
}

bool SystemProperties::Wait(const prop_info* pi, uint32_t old_serial, uint32_t* new_serial_ptr,
                            const timespec* relative_timeout) {
  // Are we waiting on the global serial or a specific serial?
  atomic_uint_least32_t* serial_ptr;
  if (pi == nullptr) {
    if (!initialized_) {
      return -1;
    }

    prop_area* serial_pa = contexts_->GetSerialPropArea();
    if (serial_pa == nullptr) {
      return -1;
    }

    serial_ptr = serial_pa->serial();
  } else {
    serial_ptr = const_cast<atomic_uint_least32_t*>(&pi->serial);
  }

  uint32_t new_serial;
  do {
    int rc;
    if ((rc = __futex_wait(serial_ptr, old_serial, relative_timeout)) != 0 && rc == -ETIMEDOUT) {
      return false;
    }
    new_serial = load_const_atomic(serial_ptr, memory_order_acquire);
  } while (new_serial == old_serial);

  *new_serial_ptr = new_serial;
  return true;
}

const prop_info* SystemProperties::FindNth(unsigned n) {
  struct find_nth {
    const uint32_t sought;
    uint32_t current;
    const prop_info* result;

    explicit find_nth(uint32_t n) : sought(n), current(0), result(nullptr) {
    }
    static void fn(const prop_info* pi, void* ptr) {
      find_nth* self = reinterpret_cast<find_nth*>(ptr);
      if (self->current++ == self->sought) self->result = pi;
    }
  } state(n);
  Foreach(find_nth::fn, &state);
  return state.result;
}

int SystemProperties::Foreach(void (*propfn)(const prop_info* pi, void* cookie), void* cookie) {
  if (!initialized_) {
    return -1;
  }

  contexts_->ForEach(propfn, cookie);

  return 0;
}
