/*
 * Copyright The async-profiler authors
 * SPDX-License-Identifier: Apache-2.0
 */

package test.comptask;

import one.profiler.test.*;

public class ComptaskTests {
    @Test(
        mainClass = Main.class,
        agentArgs = "start,features=comptask,collapsed,interval=1ms,file=%profile",
        jvmArgs = "-Xcomp",
        jvm = Jvm.HOTSPOT
    )
    @Test(
        mainClass = Main.class,
        agentArgs = "start,features=comptask,collapsed,cstack=vm,interval=1ms,file=%profile",
        jvmArgs = "-Xcomp",
        jvm = Jvm.HOTSPOT,
        nameSuffix = "VM"
    )
    @Test(
        mainClass = Main.class,
        agentArgs = "start,features=comptask,collapsed,cstack=vmx,interval=1ms,file=%profile",
        jvmArgs = "-Xcomp",
        jvm = Jvm.HOTSPOT,
        nameSuffix = "VMX"
    )
    public void testCompTask(TestProcess p) throws Exception {
        Output out = p.waitForExit("%profile");
        assert p.exitCode() == 0;
        assert out.contains(";Compiler::compile_method;(java|sun|jdk)/[^;]+[^;/]\\.[^;/]+;");
        assert out.contains(";C2Compiler::compile_method;(java|sun|jdk)/[^;]+[^;/]\\.[^;/]+;");
    }
}
