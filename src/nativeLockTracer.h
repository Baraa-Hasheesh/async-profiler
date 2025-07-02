/*
 * Copyright The async-profiler authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NATIVELOCKTRACER_H
#define NATIVELOCKTRACER_H

#include "arch.h"
#include "engine.h"
#include "mutex.h"

class NativeLockTracer : public Engine {
  private:
    static bool _initialized;
    static bool _running;
    static u64 _interval;
    static u64 _total_duration;

    static Mutex _patch_lock;
    static int _patched_libs;

    static void initialize();
    static void patchLibraries();

  public:
    const char* type() {
        return "native_lock_tracer";
    }

    const char* title() {
        return "Native lock profile";
    }

    const char* units() {
        return "ns";
    }

    Error start(Arguments& args);
    void stop();

    static inline bool running() {
        return _running;
    }

    static inline void installHooks() {
        if (running()) {
            patchLibraries();
        }
    }

    static void recordLock(void* address, u64 start_time, u64 end_time);
};



#endif //NATIVELOCKTRACER_H
