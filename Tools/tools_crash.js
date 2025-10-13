// 观察崩溃
if (typeof Module === 'undefined') {
    console.error('This script must run inside Frida.');
}

function sym(addr) {
    try {
        var d = DebugSymbol.fromAddress(ptr(addr));
        return d ? d.toString() : ptr(addr).toString();
    } catch (e) {
        return ptr(addr).toString();
    }
}

function printBacktrace(context) {
    // context 可以是 this.context 或 null（then use Thread.backtrace(NULL,...)?）
    try {
        var bt = Thread.backtrace(context || this.context, Backtracer.FUZZY)
                    .map(function (addr) { return sym(addr); });
        console.log("=== backtrace ===");
        bt.forEach(function (l, i) {
            console.log("  " + i + ": " + l);
        });
        console.log("=== end backtrace ===");
    } catch (e) {
        console.log("printBacktrace error:", e);
    }
}

function safeObjToString(ptrArg) {
    try {
        if (ptrArg.isNull && ptrArg.isNull()) return "<NULL>";
        var o = new ObjC.Object(ptrArg);
        // try toString / description
        try {
            return o.toString();
        } catch (e) {
            try { return ObjC.Object(ptrArg).description().toString(); } catch(e2) {}
        }
        return "<ObjC object>";
    } catch (e) {
        return "<not ObjC>";
    }
}

try {
    // Hook objc_exception_throw
    var objc_exc = Module.findExportByName(null, 'objc_exception_throw');
    if (objc_exc) {
        Interceptor.attach(objc_exc, {
            onEnter: function (args) {
                console.log("[CRASH-WATCH] objc_exception_throw called");
                try {
                    var excPtr = args[0];
                    console.log("  exception ptr:", excPtr);
                    // try to print class & description
                    try {
                        var excObj = new ObjC.Object(excPtr);
                        console.log("  exception class:", excObj.$className);
                        // description can be large
                        try { console.log("  exception description:", excObj.toString()); } catch(e){}
                    } catch (e) {
                        console.log("  (not ObjC) describe error:", e);
                    }
                } catch (e) {
                    console.log("  error reading args:", e);
                }
                printBacktrace(this.context);
            }
        });
        console.log("[CRASH-WATCH] hooked objc_exception_throw @", objc_exc);
    } else {
        console.log("[CRASH-WATCH] objc_exception_throw not found");
    }
} catch (e) {
    console.log("hook objc_exception_throw failed:", e);
}

try {
    // Hook C++ exceptions: __cxa_throw
    var cxa = Module.findExportByName(null, '__cxa_throw');
    if (cxa) {
        Interceptor.attach(cxa, {
            onEnter: function (args) {
                console.log("[CRASH-WATCH] __cxa_throw called");
                try {
                    console.log("  thrown exception ptr:", args[0]);
                } catch (e) {}
                printBacktrace(this.context);
            }
        });
        console.log("[CRASH-WATCH] hooked __cxa_throw @", cxa);
    } else {
        console.log("[CRASH-WATCH] __cxa_throw not found");
    }
} catch (e) {
    console.log("hook __cxa_throw failed:", e);
}

function hookAbortRaise() {
    var abortPtr = Module.findExportByName(null, 'abort');
    if (abortPtr) {
        Interceptor.attach(abortPtr, {
            onEnter: function (args) {
                console.log("[CRASH-WATCH] abort() called");
                printBacktrace(this.context);
            }
        });
        console.log("[CRASH-WATCH] hooked abort @", abortPtr);
    } else {
        console.log("[CRASH-WATCH] abort not found");
    }

    var raisePtr = Module.findExportByName(null, 'raise');
    if (raisePtr) {
        Interceptor.attach(raisePtr, {
            onEnter: function (args) {
                try {
                    var sig = args[0].toInt32();
                    console.log("[CRASH-WATCH] raise(sig) called sig=", sig);
                } catch (e) {}
                printBacktrace(this.context);
            }
        });
        console.log("[CRASH-WATCH] hooked raise @", raisePtr);
    } else {
        console.log("[CRASH-WATCH] raise not found");
    }

    // hook kill (process kill)
    var killPtr = Module.findExportByName(null, 'kill');
    if (killPtr) {
        Interceptor.attach(killPtr, {
            onEnter: function (args) {
                try {
                    var pid = args[0].toInt32();
                    var sig = args[1].toInt32();
                    console.log("[CRASH-WATCH] kill(pid,sig) called pid=", pid, " sig=", sig);
                } catch (e) {}
                printBacktrace(this.context);
            }
        });
        console.log("[CRASH-WATCH] hooked kill @", killPtr);
    } else {
        console.log("[CRASH-WATCH] kill not found");
    }
}
hookAbortRaise();

try {
    // Hook signal() and sigaction() so we know if app installs custom handlers
    var sigPtr = Module.findExportByName(null, 'signal');
    if (sigPtr) {
        Interceptor.attach(sigPtr, {
            onEnter: function (args) {
                try {
                    var signum = args[0].toInt32();
                    console.log("[CRASH-WATCH] signal() called signum=", signum, " handler=", args[1]);
                    printBacktrace(this.context);
                } catch (e) {}
            }
        });
        console.log("[CRASH-WATCH] hooked signal @", sigPtr);
    }
    var sigactPtr = Module.findExportByName(null, 'sigaction');
    if (sigactPtr) {
        Interceptor.attach(sigactPtr, {
            onEnter: function (args) {
                try {
                    var signum = args[0].toInt32();
                    console.log("[CRASH-WATCH] sigaction() called signum=", signum, "act=", args[1]);
                    printBacktrace(this.context);
                } catch (e) {}
            }
        });
        console.log("[CRASH-WATCH] hooked sigaction @", sigactPtr);
    }
} catch (e) {
    console.log("hook signal/sigaction failed:", e);
}

// Optional: catch uncaught ObjC exceptions earlier via NSSetUncaughtExceptionHandler
try {
    var nsset = Module.findExportByName(null, 'NSSetUncaughtExceptionHandler');
    if (nsset) {
        Interceptor.attach(nsset, {
            onEnter: function(args) {
                console.log("[CRASH-WATCH] NSSetUncaughtExceptionHandler set handler:", args[0]);
                printBacktrace(this.context);
            }
        });
        console.log("[CRASH-WATCH] hooked NSSetUncaughtExceptionHandler @", nsset);
    }
} catch (e) {
    // ignore
}

// Small helper to print a marker when we load
console.log("[CRASH-WATCH] installed. watching objc_exception_throw, __cxa_throw, abort, raise, kill, signal, sigaction.");
