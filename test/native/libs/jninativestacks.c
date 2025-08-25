/*
 * Copyright The async-profiler authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <jni.h>
#include <math.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "asprof.h"

JNIEXPORT double doCpuTask() {
    int i = 0;
    double result = 0;

    while (i < 100000000) {
        i++;
        result += sqrt(i);
        result += pow(i, sqrt(i));
    }
    return result;
}

JNIEXPORT double generateDeepStack(int count) {
    char frame[0x20000];
    // Prevent from being optimized by compiler
    (void)frame;

    if (count == 0) {
        return doCpuTask();
    } else {
        return generateDeepStack(count - 1);
    }
}

JNIEXPORT jdouble JNICALL Java_test_stackwalker_StackGenerator_largeFrame(JNIEnv* env, jclass cls) {
    char frame[0x50000];
    // Prevent from being optimized by compiler
    (void)frame;
    return doCpuTask();
}

JNIEXPORT jdouble JNICALL Java_test_stackwalker_StackGenerator_deepFrame(JNIEnv* env, jclass cls) {
    char frame[0x30000];
    // Prevent from being optimized by compiler
    (void)frame;
    return generateDeepStack(6);
}

JNIEXPORT jdouble JNICALL Java_test_stackwalker_StackGenerator_leafFrame(JNIEnv* env, jclass cls) {
    return doCpuTask();
}

#include <stdio.h>

int main() {
    void* lib = dlopen("/Volumes/workplace/async-profiler/build/lib/libasyncProfiler.dylib", RTLD_NOW);
    asprof_init_t asprof_init = dlsym(lib, "asprof_init");
    asprof_init();

    asprof_execute_t asprof_execute = dlsym(lib, "asprof_execute");
    asprof_error_t err = asprof_execute("start,event=cpu,collapsed,file=output", NULL);

    fprintf(stderr, "%.02f\n", doCpuTask());

    err = asprof_execute("stop", NULL);
}