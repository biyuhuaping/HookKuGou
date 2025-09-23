// hook_crash_first_method.js
// 用法：frida -U -f com.kugou.kugou1002 -l demo.js --no-pause
// 或 先启动 app 再 frida -U -n <procname> -l hook_crash_first_method.js

'use strict';
/*
if (ObjC.available) {
    console.log("[*] ObjC available, installing exception hook...");

    var attached = false;      // 是否已经 attach 到疑似函数（防止重复 attach）
    var hookedInfo = null;

    // Helper: 判断模块名是否为“系统框架”，用于跳过系统帧
    function isSystemModule(moduleName) {
        if (!moduleName) return true;
        var sysRe = /(libobjc|UIKit|Foundation|CoreFoundation|CFNetwork|libsystem|dyld|SpringBoard|BackBoard|MobileCoreServices|ImageIO|Security|AVFoundation|CFNetwork)/i;
        return sysRe.test(moduleName);
    }

    // Hook objc_exception_throw
    var excPtr = Module.findExportByName(null, "objc_exception_throw");
    if (!excPtr) {
        console.log("[-] objc_exception_throw not found!");
    } else {
        Interceptor.attach(excPtr, {
            onEnter: function (args) {
                try {
                    var ex = new ObjC.Object(args[0]);
                    var name = (ex.name && ex.name()) ? ex.name().toString() : "(no name)";
                    var reason = (ex.reason && ex.reason()) ? ex.reason().toString() : "(no reason)";
                    console.log("\n[objc_exception_throw] name:", name);
                    console.log("[objc_exception_throw] reason:", reason);
                } catch (e) {
                    console.log("[objc_exception_throw] can't parse exception object:", e);
                }

                // 打印回溯
                var bt = Thread.backtrace(this.context, Backtracer.FUZZY)
                            .map(DebugSymbol.fromAddress);
                console.log("[Backtrace at exception time]");
                bt.forEach(function (s, i) {
                    console.log(i + ":", s.toString());
                });

                // 如果还没 attach，尝试在回溯中找到第一个非系统帧并 attach（捕获“第一个崩溃方法”）
                if (!attached) {
                    for (var i = 0; i < bt.length; i++) {
                        var s = bt[i];
                        if (!s) continue;
                        var mod = s.moduleName || "";
                        // 跳过系统 module、lib 或无意义帧
                        if (isSystemModule(mod)) continue;

                        // 缓存地址与符号信息，注意用 IIFE 捕获当前 s 和 addr
                        (function(sym) {
                            var addr = sym.address;
                            if (!addr) return;
                            try {
                                Interceptor.attach(addr, {
                                    onEnter: function (callArgs) {
                                        console.log("\n[Attached] Enter suspected crashing method:");
                                        console.log("symbol:", sym.name || "(unknown)");
                                        console.log("module:", sym.moduleName || "(unknown)");
                                        console.log("address:", addr);

                                        // 打印寄存器（arm64 常用前 6 个参数 x0..x5）
                                        try {
                                            var c = this.context;
                                            // some printing defensive: .toString may be needed
                                            console.log("regs: x0=" + ptr(c.x0) + ", x1=" + ptr(c.x1) + ", x2=" + ptr(c.x2) + ", x3=" + ptr(c.x3) + ", x4=" + ptr(c.x4) + ", x5=" + ptr(c.x5));
                                        } catch (errReg) {
                                            console.log("failed to read regs:", errReg);
                                        }

                                        // 打印调用时回溯
                                        var bt_now = Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress);
                                        console.log("[Backtrace at call time]");
                                        bt_now.forEach(function (ss, idx) {
                                            console.log(idx + ":", ss.toString());
                                        });
                                    }
                                });
                                attached = true;
                                hookedInfo = { address: addr, symbol: sym.name, module: sym.moduleName };
                                console.log("[+] Successfully attached to suspected method:", sym.name, "at", addr);
                            } catch (errAttach) {
                                console.log("[-] failed to attach to", addr, ":", errAttach);
                            }
                        })(s);

                        // 已 attach（成功或尝试过）则跳出循环（只 attach 第一个匹配）
                        if (attached) break;
                    }

                    if (!attached) {
                        console.log("[!] Didn't find a non-system frame to attach to. You can adjust the module filter.");
                    }
                } // end if !attached
            } // end onEnter
        }); // end Interceptor.attach
        console.log("[*] objc_exception_throw hook installed at", excPtr);
    }

} else {
    console.log("[-] ObjC not available in this process.");
}
*/

// demo_minimal.js - minimal injector that only prints and waits
console.log("[demo_minimal] script loaded - keeping alive for debugging");
setTimeout(function(){ console.log("[demo_minimal] keep-alive timeout done"); }, 60000*10);

try {
    // 防御性等待 ObjC 就绪（如果你不需要 ObjC 可以删掉）
    if (this.ObjC && ObjC.available) {
        ObjC.schedule(ObjC.mainQueue, function() {
            console.log("[demo_minimal] ObjC available");
        });
    } else {
        console.log("[demo_minimal] ObjC not available or not needed");
    }
} catch (e) {
    console.log("[demo_minimal] error:", e);
}

// 保持脚本运行一段时间以便观察（可选）
setTimeout(function() {
    console.log("[demo_minimal] timeout reached - keep alive to observe runtime");
}, 10000);
