/*
 * Copyright The async-profiler authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "nativeLockTracer.h"
#include "codeCache.h"
#include "profiler.h"
#include "symbols.h"

#define SAVE_IMPORT(FUNC) \
    _orig_##FUNC = (decltype(_orig_##FUNC))*lib->findImport(im_##FUNC)

bool NativeLockTracer::_initialized = false;
bool NativeLockTracer::_running = false;
u64 NativeLockTracer::_interval = 0;
u64 NativeLockTracer::_total_duration = 0;

Mutex NativeLockTracer::_patch_lock;
int NativeLockTracer::_patched_libs = 0;

static int (*_orig_pthread_mutex_lock)(pthread_mutex_t*);

extern "C" int pthread_mutex_lock_hook(pthread_mutex_t* mutex) {
    if (!NativeLockTracer::running()) {
        return _orig_pthread_mutex_lock(mutex);
    }

    // attempt to acquire lock
    int result = pthread_mutex_trylock(mutex);
    if (result == 0) {
        return result;
    }

    u64 time_before = OS::nanotime();
    result = _orig_pthread_mutex_lock(mutex);
    u64 time_after = OS::nanotime();

    NativeLockTracer::recordLock(mutex, time_before, time_after);
    return result;
}

void NativeLockTracer::initialize() {
    CodeCache* lib = Profiler::instance()->findLibraryByAddress((void*)NativeLockTracer::initialize);

    SAVE_IMPORT(pthread_mutex_lock);
}

void NativeLockTracer::patchLibraries() {
    MutexLocker ml(_patch_lock);

    CodeCacheArray* native_libs = Profiler::instance()->nativeLibs();
    int native_lib_count = native_libs->count();

    while (_patched_libs < native_lib_count) {
        CodeCache* cc = (*native_libs)[_patched_libs++];

        UnloadProtection handle(cc);
        if (!handle.isValid()) {
            continue;
        }

        cc->patchImport(im_pthread_mutex_lock, (void*)pthread_mutex_lock_hook);
    }
}

void NativeLockTracer::recordLock(void* address, u64 start_time, u64 end_time) {
    u64 duration_nanos = end_time - start_time;
    if (updateCounter(_total_duration, end_time - start_time, _interval)) {
        NativeLockEvent event;
        event._start_time = start_time;
        event._end_time = end_time;
        event._address = (uintptr_t)address;

        Profiler::instance()->recordSample(NULL, duration_nanos, NATIVE_LOCK_SAMPLE, &event);
    }
}


Error NativeLockTracer::start(Arguments& args) {
    if (!_initialized) {
        initialize();
        _initialized = true;
    }

    _interval = 0;
    _total_duration = 0;

    _running = true;
    patchLibraries();

    return Error::OK;
}

void NativeLockTracer::stop() {
    // Ideally, we should reset original malloc entries, but it's not currently safe
    // in the view of library unloading. Consider using dl_iterate_phdr.
    _running = false;
}