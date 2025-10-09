// if (ObjC.available) {
//     const cls = ObjC.classes.KGHttpRequest;
//     const sel = "- willStartRequest";

//     if (cls && cls[sel]) {
//         Interceptor.attach(cls[sel].implementation, {
//             onEnter: function (args) {
//                 // args[0] = self
//                 // args[1] = selector
//                 // args[2] = level (NSInteger)
//                 // args[3] = moduleName (NSString *)
//                 // args[4] = format (NSString *)

//                 const selfObj = new ObjC.Object(args[0]);
//                 // const moduleName = new ObjC.Object(args[2]).toString();
//                 console.log("\n[Hook]", sel);
//                 // console.log("  moduleName:", moduleName);
//                 // 打印调用栈
//                 var backtrace = Thread.backtrace(this.context, Backtracer.FUZZY)
//                     .map(DebugSymbol.fromAddress)
//                     .join("\n");
//                 console.log("[*] Call stack:\n" + backtrace);
//             },
//             onLeave: function (retval) {
//                 try {
//                     if (retval && !retval.isNull()) {
//                         var retStr = new ObjC.Object(retval).toString();
//                         console.log("  return:", retStr);
//                     } else {
//                         console.log("  return: <null>");
//                     }
//                 } catch (e) {
//                     console.log("  return: <error converting retval>", e);
//                 }
//                 console.log("  return:", retval);
//             }
//         });
//     } else {
//         console.log("❌ Method not found!");
//     }
// }

/*
if (!ObjC.available) {
    console.log("ObjC runtime not available");
    throw new Error("ObjC not available");
}

function shortAddr(addr) {
    try { return DebugSymbol.fromAddress(addr).toString(); } catch (e) { return addr; }
}

function safeToString(obj) {
    try {
        if (!obj || obj.isNull()) return "<nil>";
        var o = new ObjC.Object(obj);
        return o.toString();
    } catch (e) {
        return "<conversion error>";
    }
}

// Small helper to print a backtrace (use FUZZY to avoid perf issues)
function getBacktrace(context) {
    try {
        return Thread.backtrace(context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join("\n");
    } catch (e) {
        return "<backtrace error: " + e + ">";
    }
}

// Hook NSMutableURLRequest -setValue:forHTTPHeaderField:
try {
    var mReqCls = ObjC.classes.NSMutableURLRequest;
    var sel_set = "- setValue:forHTTPHeaderField:";
    if (mReqCls && mReqCls[sel_set]) {
        Interceptor.attach(mReqCls[sel_set].implementation, {
            onEnter: function (args) {
                try {
                    this.self = args[0];
                    this.sel = args[1];
                    var val = args[2] ? new ObjC.Object(args[2]).toString() : "<nil>";
                    var key = args[3] ? new ObjC.Object(args[3]).toString() : "<nil>";
                    console.log("\n[HOOK] NSMutableURLRequest setValue:forHTTPHeaderField: => key:", key, " value:", val);
                    console.log("  self class:", this.self ? new ObjC.Object(this.self).$className : "<nil>");
                    console.log("  bt:\n" + getBacktrace(this.context));
                } catch (e) {
                    console.log("[error] setValue hook onEnter:", e);
                }
            }
        });
        console.log("[*] Hook installed: NSMutableURLRequest -setValue:forHTTPHeaderField:");
    } else {
        console.log("[-] NSMutableURLRequest or selector not found");
    }
} catch (err) {
    console.log("setup error (NSMutableURLRequest):", err);
}

// Hook NSURLRequest -allHTTPHeaderFields (instance method)
try {
    var nReqCls = ObjC.classes.NSURLRequest;
    var sel_all = "- allHTTPHeaderFields";
    if (nReqCls && nReqCls[sel_all]) {
        Interceptor.attach(nReqCls[sel_all].implementation, {
            onEnter: function (args) {
                // nothing heavy here
                this.bt = getBacktrace(this.context);
            },
            onLeave: function (retval) {
                try {
                    var headersPreview = "<nil>";
                    if (retval && !retval.isNull()) {
                        try {
                            var dict = new ObjC.Object(retval);
                            if (dict && dict.isKindOfClass(ObjC.classes.NSDictionary)) {
                                var keys = dict.allKeys();
                                var len = Math.min(20, keys.count());
                                var parts = [];
                                for (var i=0;i<len;i++) {
                                    var k = keys.objectAtIndex_(i);
                                    var v = dict.objectForKey_(k);
                                    parts.push(k.toString() + "=" + (v ? v.toString() : "<nil>"));
                                }
                                if (keys.count() > len) parts.push("...(" + (keys.count()-len) + " more)");
                                headersPreview = "{ " + parts.join("; ") + " }";
                            } else {
                                headersPreview = dict.toString();
                            }
                        } catch (e) {
                            headersPreview = "<conversion error>";
                        }
                    }
                    console.log("\n[HOOK] NSURLRequest -allHTTPHeaderFields returned: " + headersPreview);
                    console.log("  bt:\n" + (this.bt || "<no bt>"));
                } catch (e) {
                    console.log("[error] allHTTPHeaderFields onLeave:", e);
                }
            }
        });
        console.log("[*] Hook installed: NSURLRequest -allHTTPHeaderFields");
    } else {
        console.log("[-] NSURLRequest or selector not found");
    }
} catch (err) {
    console.log("setup error (NSURLRequest):", err);
}

// Hook NSURLSession -dataTaskWithRequest:completionHandler:
try {
    var nsCls = ObjC.classes.NSURLSession;
    var sel_data = "- dataTaskWithRequest:completionHandler:";
    if (nsCls && nsCls[sel_data]) {
        Interceptor.attach(nsCls[sel_data].implementation, {
            onEnter: function (args) {
                try {
                    var req = new ObjC.Object(args[2]);
                    var url = req.URL ? req.URL.absoluteString().toString() : "<nil>";
                    console.log("\n[HOOK] NSURLSession dataTaskWithRequest: url =", url);
                    // print headers if possible
                    try {
                        var h = req.allHTTPHeaderFields();
                        if (h) {
                            console.log("  headers preview:", h.toString());
                        }
                    } catch (e) {  }
                    console.log("  bt:\n" + getBacktrace(this.context));
                } catch (e) {
                    console.log("[error] dataTask hook onEnter:", e);
                }
            }
        });
        console.log("[*] Hook installed: NSURLSession -dataTaskWithRequest:completionHandler:");
    } else {
        console.log("[-] NSURLSession or selector not found");
    }
} catch (err) {
    console.log("setup error (NSURLSession):", err);
}

// (Optional) tiny heartbeat to show script is alive
setInterval(function(){}, 1000);
*/




/*
// print_ua_only.js
if (!ObjC.available) {
    console.log("ObjC runtime not available");
    throw new Error("ObjC not available");
}

function safeObjToString(ptr) {
    try {
        if (!ptr || ptr.isNull()) return null;
        var o = new ObjC.Object(ptr);
        // sometimes CFString/NSString prints nicely with toString()
        return o.toString();
    } catch (e) {
        return null;
    }
}

function printUA(source, ua) {
    if (!ua) return;
    console.log("\n[User-Agent] source:", source, "\n  =>", ua);
}

// 1) NSMutableURLRequest -setValue:forHTTPHeaderField:
try {
    var MReq = ObjC.classes.NSMutableURLRequest;
    var selSet = "- setValue:forHTTPHeaderField:";
    if (MReq && MReq[selSet]) {
        Interceptor.attach(MReq[selSet].implementation, {
            onEnter: function (args) {
                try {
                    var val = safeObjToString(args[2]);
                    var key = safeObjToString(args[3]);
                    if (key && key.toLowerCase && key.toLowerCase() === "user-agent") {
                        printUA("NSMutableURLRequest.setValue:forHTTPHeaderField:", val || "<nil>");
                    }
                } catch (e) {
                    // ignore
                }
            }
        });
        console.log("[*] Hooked NSMutableURLRequest -setValue:forHTTPHeaderField:");
    } else {
        console.log("[-] NSMutableURLRequest selector not found");
    }
} catch (e) {
    console.log("error hooking NSMutableURLRequest:", e);
}

// 2) NSURLRequest -allHTTPHeaderFields
try {
    var NReq = ObjC.classes.NSURLRequest;
    var selAll = "- allHTTPHeaderFields";
    if (NReq && NReq[selAll]) {
        Interceptor.attach(NReq[selAll].implementation, {
            onLeave: function (retval) {
                try {
                    if (!retval || retval.isNull()) return;
                    var dict = new ObjC.Object(retval);
                    if (dict && dict.isKindOfClass(ObjC.classes.NSDictionary)) {
                        // try direct lookup (faster)
                        var ua = null;
                        try {
                            var k = ObjC.classes.NSString.stringWithString_("User-Agent");
                            var v = dict.objectForKey_(k);
                            if (v && !v.isNull()) ua = v.toString();
                        } catch (ee) {
                            // fallback iterate keys
                        }
                        if (!ua) {
                            var keys = dict.allKeys ? dict.allKeys() : null;
                            if (keys) {
                                var count = keys.count();
                                for (var i = 0; i < count; i++) {
                                    var kk = keys.objectAtIndex_(i).toString();
                                    if (kk && kk.toLowerCase() === "user-agent") {
                                        var vv = dict.objectForKey_(keys.objectAtIndex_(i));
                                        ua = vv ? vv.toString() : null;
                                        break;
                                    }
                                }
                            }
                        }
                        if (ua) printUA("NSURLRequest.allHTTPHeaderFields", ua);
                    }
                } catch (e) {
                    // ignore conversion errors
                }
            }
        });
        console.log("[*] Hooked NSURLRequest -allHTTPHeaderFields");
    } else {
        console.log("[-] NSURLRequest selector not found");
    }
} catch (e) {
    console.log("error hooking NSURLRequest:", e);
}

// 3) NSURLSession -dataTaskWithRequest:completionHandler:
try {
    var NSUrlSession = ObjC.classes.NSURLSession;
    var selData = "- dataTaskWithRequest:completionHandler:";
    if (NSUrlSession && NSUrlSession[selData]) {
        Interceptor.attach(NSUrlSession[selData].implementation, {
            onEnter: function (args) {
                try {
                    var reqPtr = args[2];
                    if (reqPtr && !reqPtr.isNull()) {
                        var req = new ObjC.Object(reqPtr);
                        // try direct valueForHTTPHeaderField:
                        try {
                            if (req.valueForHTTPHeaderField_) {
                                var ua = req.valueForHTTPHeaderField_("User-Agent");
                                if (ua && ua.toString) {
                                    printUA("NSURLSession.dataTaskWithRequest: (valueForHTTPHeaderField)", ua.toString());
                                    return;
                                }
                            }
                        } catch (e) { }

                        // fallback to allHTTPHeaderFields
                        try {
                            if (req.allHTTPHeaderFields) {
                                var headers = req.allHTTPHeaderFields();
                                if (headers && !headers.isNull()) {
                                    var dict = new ObjC.Object(headers);
                                    var keys = dict.allKeys();
                                    var cnt = keys.count();
                                    for (var i = 0; i < cnt; i++) {
                                        var k = keys.objectAtIndex_(i).toString();
                                        if (k && k.toLowerCase && k.toLowerCase() === "user-agent") {
                                            var v = dict.objectForKey_(keys.objectAtIndex_(i));
                                            if (v) {
                                                printUA("NSURLSession.dataTaskWithRequest: (allHTTPHeaderFields)", v.toString());
                                            }
                                            break;
                                        }
                                    }
                                }
                            }
                        } catch (ee) {
                            // ignore
                        }
                    }
                } catch (e) {
                    // guard
                }
            }
        });
        console.log("[*] Hooked NSURLSession -dataTaskWithRequest:completionHandler:");
    } else {
        console.log("[-] NSURLSession selector not found");
    }
} catch (e) {
    console.log("error hooking NSURLSession:", e);
}

// keep script alive
setInterval(function(){}, 1000);
*/


/*
if (!ObjC.available) {
    console.log("ObjC runtime not available");
    throw new Error("ObjC not available");
}

var MAX_FRAMES = 30; // 限制深度，避免太重

function collectBacktraceAddrs(context) {
    try {
        // 返回 NativePointer 的数组（不做符号解析）
        var bt = Thread.backtrace(context, Backtracer.FUZZY);
        if (!bt) return [];
        // 限制帧数
        var out = [];
        for (var i = 0; i < Math.min(bt.length, MAX_FRAMES); i++) {
            out.push(bt[i]);
        }
        return out;
    } catch (e) {
        // 若回溯本身失败，返回空
        return [];
    }
}

function addrArrayToHexList(arr) {
    try {
        return arr.map(function (p) {
            try { return p.toString(); } catch (e) { return "<addr?>"; }
        }).join("\n");
    } catch (e) {
        return "<addr conversion error>";
    }
}

function resolveSymbolsAsync(addrArray, label) {
    // 异步解析符号（避免在 hook 上下文做重工作）
    var doResolve = function () {
        try {
            console.log("  [symbol-resolve start] " + label);
            for (var i = 0; i < addrArray.length; i++) {
                try {
                    var sym = DebugSymbol.fromAddress(addrArray[i]);
                    // DebugSymbol.fromAddress 也可能抛异常，单帧 try/catch
                    console.log("    " + i + ": " + addrArray[i] + " -> " + sym);
                } catch (e) {
                    console.log("    " + i + ": " + addrArray[i] + " -> <no symbol> (" + e + ")");
                }
            }
            console.log("  [symbol-resolve end]");
        } catch (e) {
            console.log("[symbol-resolve error]", e);
        }
    };

    // 优先使用 setImmediate（如果运行时支持），否则退到 setTimeout(...,0)
    if (typeof setImmediate !== "undefined") {
        setImmediate(doResolve);
    } else {
        setTimeout(doResolve, 0);
    }
}

function safeObjToString(ptr) {
    try {
        if (!ptr || ptr.isNull()) return null;
        var o = new ObjC.Object(ptr);
        return o.toString();
    } catch (e) {
        return null;
    }
}

function printUA_with_possible_bt(source, ua, context) {
    if (!ua) return;
    console.log("\n[User-Agent] source:", source, "\n  =>", ua);

    // 匹配 16_7_11（如果你还需要匹配 16.7.11 等，可用正则）
    if (ua.indexOf("16_7_11") >= 0) {
        try {
            // 1) 采集地址（尽量轻量）
            var addrs = collectBacktraceAddrs(context || this.context);
            if (!addrs || addrs.length === 0) {
                console.log("  [MATCH] contains 16_7_11 -> backtrace: <empty or failed to collect>");
                return;
            }
            // 打印调用栈
            var backtrace = Thread.backtrace(context, Backtracer.FUZZY)
                .map(DebugSymbol.fromAddress)
                .join("\n");
            console.log("[*] Call stack:\n" + backtrace);
            // 2) 立刻打印地址列表（安全）
            // console.log("  [MATCH] contains 16_7_11 -> printing raw addresses (" + addrs.length + "):\n" + addrArrayToHexList(addrs));

            // // 3) 异步解析符号（不会阻塞/干扰当前线程）
            // resolveSymbolsAsync(addrs, "UA match " + source);
        } catch (e) {
            // 任何异常都在这里捕获
            console.log("[error] printing backtrace:", e);
        }
    }
}

// hook 实现（同你之前脚本：NSMutableURLRequest / NSURLRequest / NSURLSession）
try {
    // 1) NSMutableURLRequest -setValue:forHTTPHeaderField:
    var MReq = ObjC.classes.NSMutableURLRequest;
    var selSet = "- setValue:forHTTPHeaderField:";
    if (MReq && MReq[selSet]) {
        Interceptor.attach(MReq[selSet].implementation, {
            onEnter: function (args) {
                try {
                    var val = safeObjToString(args[2]);
                    var key = safeObjToString(args[3]);
                    if (key && key.toLowerCase && key.toLowerCase() === "user-agent") {
                        printUA_with_possible_bt("NSMutableURLRequest.setValue:forHTTPHeaderField:", val || "<nil>", this.context);
                    }
                } catch (e) {  }
            }
        });
        console.log("[*] Hooked NSMutableURLRequest -setValue:forHTTPHeaderField:");
    } else {
        console.log("[-] NSMutableURLRequest selector not found");
    }
} catch (e) {
    console.log("error hooking NSMutableURLRequest:", e);
}

try {
    // 2) NSURLRequest -allHTTPHeaderFields
    var NReq = ObjC.classes.NSURLRequest;
    var selAll = "- allHTTPHeaderFields";
    if (NReq && NReq[selAll]) {
        Interceptor.attach(NReq[selAll].implementation, {
            onLeave: function (retval) {
                try {
                    if (!retval || retval.isNull()) return;
                    var dict = new ObjC.Object(retval);
                    if (dict && dict.isKindOfClass(ObjC.classes.NSDictionary)) {
                        var ua = null;
                        try {
                            // direct lookup first
                            var k = ObjC.classes.NSString.stringWithString_("User-Agent");
                            var v = dict.objectForKey_(k);
                            if (v && !v.isNull()) ua = v.toString();
                        } catch (ee) {}
                        if (!ua) {
                            var keys = dict.allKeys ? dict.allKeys() : null;
                            if (keys) {
                                for (var i = 0, cnt = keys.count(); i < cnt; i++) {
                                    var kk = keys.objectAtIndex_(i).toString();
                                    if (kk && kk.toLowerCase && kk.toLowerCase() === "user-agent") {
                                        var vv = dict.objectForKey_(keys.objectAtIndex_(i));
                                        ua = vv ? vv.toString() : null;
                                        break;
                                    }
                                }
                            }
                        }
                        if (ua) printUA_with_possible_bt("NSURLRequest.allHTTPHeaderFields", ua, this.context);
                    }
                } catch (e) {  }
            }
        });
        console.log("[*] Hooked NSURLRequest -allHTTPHeaderFields");
    } else {
        console.log("[-] NSURLRequest selector not found");
    }
} catch (e) {
    console.log("error hooking NSURLRequest:", e);
}

try {
    // 3) NSURLSession -dataTaskWithRequest:completionHandler:
    var NSUrlSession = ObjC.classes.NSURLSession;
    var selData = "- dataTaskWithRequest:completionHandler:";
    if (NSUrlSession && NSUrlSession[selData]) {
        Interceptor.attach(NSUrlSession[selData].implementation, {
            onEnter: function (args) {
                try {
                    var reqPtr = args[2];
                    if (reqPtr && !reqPtr.isNull()) {
                        var req = new ObjC.Object(reqPtr);
                        try {
                            if (req.valueForHTTPHeaderField_) {
                                var ua = req.valueForHTTPHeaderField_("User-Agent");
                                if (ua && ua.toString) {
                                    printUA_with_possible_bt("NSURLSession.dataTaskWithRequest: (valueForHTTPHeaderField)", ua.toString(), this.context);
                                    return;
                                }
                            }
                        } catch (e) {}
                        try {
                            if (req.allHTTPHeaderFields) {
                                var headers = req.allHTTPHeaderFields();
                                if (headers && !headers.isNull()) {
                                    var dict = new ObjC.Object(headers);
                                    var keys = dict.allKeys();
                                    for (var i = 0, cnt = keys.count(); i < cnt; i++) {
                                        var k = keys.objectAtIndex_(i).toString();
                                        if (k && k.toLowerCase && k.toLowerCase() === "user-agent") {
                                            var v = dict.objectForKey_(keys.objectAtIndex_(i));
                                            if (v) {
                                                printUA_with_possible_bt("NSURLSession.dataTaskWithRequest: (allHTTPHeaderFields)", v.toString(), this.context);
                                            }
                                            break;
                                        }
                                    }
                                }
                            }
                        } catch (e) {}
                    }
                } catch (e) {  }
            }
        });
        console.log("[*] Hooked NSURLSession -dataTaskWithRequest:completionHandler:");
    } else {
        console.log("[-] NSURLSession selector not found");
    }
} catch (e) {
    console.log("error hooking NSURLSession:", e);
}

// keep script alive
setInterval(function(){}, 1000);
*/



/*
if (!ObjC.available) {
    console.log("ObjC runtime not available");
    throw new Error("ObjC not available");
}

const MAX_FRAMES = 20;
function safeBacktrace(context) {
    try {
        return Thread.backtrace(context || this.context, Backtracer.FUZZY)
            .slice(0, MAX_FRAMES)
            .map(DebugSymbol.fromAddress)
            .join("\n");
    } catch (e) { return "<backtrace failed: " + e + ">"; }
}

function safeObjToString(ptr) {
    try {
        if (!ptr || ptr.isNull()) return null;
        var o = new ObjC.Object(ptr);
        return o.toString();
    } catch (e) {
        return null;
    }
}

// Helper to attach to native exported function if exists
function tryAttachNative(symName, onEnter, onLeave) {
    var addr = Module.findExportByName(null, symName);
    if (addr) {
        try {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    try { if (onEnter) onEnter.call(this, args); } catch(e){ console.log(symName,"onEnter err",e); }
                },
                onLeave: function (retval) {
                    try { if (onLeave) onLeave.call(this, retval); } catch(e){ console.log(symName,"onLeave err",e); }
                }
            });
            console.log("[+] attached native:", symName, "at", addr);
        } catch (e) {
            console.log("[-] attach failed:", symName, e);
        }
    } else {
        console.log("[-] native symbol not found:", symName);
    }
}

// 4) +[NSString stringWithFormat:] — 只打印包含 iPhone 或 CPU 的格式（避免噪声）
try {
    var NSString = ObjC.classes.NSString;
    if (NSString && NSString["+ stringWithFormat:"]) {
        Interceptor.attach(NSString["+ stringWithFormat:"].implementation, {
            onEnter: function (args) {
                try {
                    // args[2] 是 format NSString*
                    var fmt = safeObjToString(args[2]);
                    if (!fmt) return;
                    if (fmt.indexOf("iPhone") >= 0 || fmt.indexOf("CPU iPhone OS") >= 0 || fmt.indexOf("iOS") >= 0) {
                        this._watch = true;
                        this._fmt = fmt;
                    } else {
                        this._watch = false;
                    }
                } catch (e) { this._watch = false; }
            },
            onLeave: function (retval) {
                try {
                    if (!this._watch) return;
                    var out = safeObjToString(retval);
                    console.log("\n[TRACE] +[NSString stringWithFormat:] fmt:", this._fmt, " => ", out);
                    console.log("  backtrace:\n", safeBacktrace(this.context));
                } catch (e) {}
            }
        });
        console.log("[*] hooked +[NSString stringWithFormat:] (filtered)");
    } else {
        console.log("[-] NSString +stringWithFormat: not found");
    }
} catch (e) { console.log(e); }

// 6) __CFUserAgentString (native)
tryAttachNative("__CFUserAgentString",
    function(args){},
    function(retval){
        try {
            if (!retval.isNull()) {
                var s = new ObjC.Object(retval).toString();
                console.log("\n[TRACE] __CFUserAgentString =>", s);
                console.log("  backtrace:\n", safeBacktrace(this.context));
            } else {
                console.log("\n[TRACE] __CFUserAgentString => <null>");
            }
        } catch (e) { console.log("err __CFUserAgentString", e); }
    }
);

// 8) As extra: hook NSURLSession valueForHTTPHeaderField: to catch when UA pulled from request
try {
    var NSURLRequestClass = ObjC.classes.NSURLRequest;
    if (NSURLRequestClass && NSURLRequestClass["- valueForHTTPHeaderField:"]) {
        Interceptor.attach(NSURLRequestClass["- valueForHTTPHeaderField:"].implementation, {
            onEnter: function (args) { this.key = safeObjToString(args[2]); },
            onLeave: function (retval) {
                try {
                    if (this.key && this.key.toLowerCase && this.key.toLowerCase() === "user-agent") {
                        console.log("\n[TRACE] -[NSURLRequest valueForHTTPHeaderField:] key=User-Agent => ", safeObjToString(retval));
                        console.log("  backtrace:\n", safeBacktrace(this.context));
                    }
                } catch (e) {}
            }
        });
        console.log("[*] hooked -[NSURLRequest valueForHTTPHeaderField:]");
    } else {
        console.log("[-] NSURLRequest -valueForHTTPHeaderField: not found");
    }
} catch (e) { console.log(e); }

// keep script alive
setInterval(function(){}, 1000);
*/


/*
if (!ObjC.available) {
    throw "ObjC not available";
}

function safeBacktrace(context) {
    try {
        return Thread.backtrace(context || this.context, Backtracer.FUZZY)
            .slice(0, 20)
            .map(DebugSymbol.fromAddress)
            .join("\n");
    } catch (e) { return "<backtrace failed>"; }
}

function safeObjToString(ptr) {
    try {
        if (!ptr || ptr.isNull()) return null;
        return new ObjC.Object(ptr).toString();
    } catch (e) { return null; }
}

// Hook stringByReplacingOccurrencesOfString:withString:
try {
    var NSString = ObjC.classes.NSString;

    if (NSString && NSString['- stringByReplacingOccurrencesOfString:withString:']) {
        Interceptor.attach(NSString['- stringByReplacingOccurrencesOfString:withString:'].implementation, {
            onEnter: function(args) {
                this.original = safeObjToString(args[2]); // old string
                this.replacement = safeObjToString(args[3]); // new string
            },
            onLeave: function(retval) {
                try {
                    if (this.original && this.replacement && this.original.indexOf('.') >=0 && this.replacement.indexOf('_') >=0) {
                        console.log("\n[STRING-REPLACE] %@ -> %@", this.original, this.replacement);
                        console.log("  backtrace:\n", safeBacktrace(this.context));
                    }
                } catch (e) {}
            }
        });
        console.log("[*] hooked -stringByReplacingOccurrencesOfString:withString:");
    }

    // 也 hook 带 options/range 的版本
    if (NSString && NSString['- stringByReplacingOccurrencesOfString:withString:options:range:']) {
        Interceptor.attach(NSString['- stringByReplacingOccurrencesOfString:withString:options:range:'].implementation, {
            onEnter: function(args) {
                this.original = safeObjToString(args[2]);
                this.replacement = safeObjToString(args[3]);
            },
            onLeave: function (retval) {
                try {
                    if (this.original && this.replacement && this.original.indexOf('.') >= 0 && this.replacement.indexOf('_') >= 0) {
                        console.log("\n[STRING-REPLACE-OPTIONS] %@ -> %@", this.original, this.replacement);
                        console.log("  backtrace:\n", safeBacktrace(this.context));
                    }
                } catch (e) { }
            }
        });
        Interceptor.attach(NSString['- stringByReplacingOccurrencesOfString:withString:options:range:'].implementation, {
            onEnter: function (args) {
                this.orig = safeObjToString(args[2]);
                this.repl = safeObjToString(args[3]);
                if (this.orig === "16.7.11") {
                    console.log("[HOOK] changing 16.7.11 -> 16_9_99");
                    args[3] = ObjC.classes.NSString.stringWithString_("16_9_99").handle;
                }
            }
        });

        console.log("[*] hooked -stringByReplacingOccurrencesOfString:withString:options:range:");
    }

} catch (e) { console.log("hook string replace error", e); }
*/


/*
// hook_replace_only_underscore.js
if (!ObjC.available) {
    console.log("ObjC runtime not available");
    throw new Error("ObjC not available");
}

const MAX_FRAMES = 30;

function safeToString(ptr) {
    try {
        if (!ptr || ptr.isNull()) return null;
        return new ObjC.Object(ptr).toString();
    } catch (e) {
        return null;
    }
}

function resolveAndPrintAddrs(addrs) {
    for (var i = 0; i < addrs.length; i++) {
        try {
            var sym = DebugSymbol.fromAddress(addrs[i]);
            console.log("    " + i + ": " + addrs[i] + " -> " + sym.toString());
        } catch (e) {
            console.log("    " + i + ": " + addrs[i] + " -> <no symbol>");
        }
    }
}

try {
    var cls = ObjC.classes.NSString;
    var selName = "- stringByReplacingOccurrencesOfString:withString:options:range:";
    if (!(cls && cls[selName])) {
        console.log("[-] NSString method not found:", selName);
    } else {
        Interceptor.attach(cls[selName].implementation, {
            onEnter: function (args) {
                // args[2] = target, args[3] = replacement
                this.origArg = safeToString(args[2]);
                this.replaceArg = safeToString(args[3]);

                // Only collect backtrace addresses lazily if replacement === "_"
                if (this.replaceArg === "_") {
                    try {
                        var bt = Thread.backtrace(this.context, Backtracer.FUZZY);
                        if (bt && bt.length) {
                            this._bt = bt.slice(0, Math.min(bt.length, MAX_FRAMES));
                        } else {
                            this._bt = [];
                        }
                    } catch (e) {
                        this._bt = [];
                    }
                } else {
                    this._bt = null; // indicate no need
                }
                this._ts = Date.now();
            },
            onLeave: function (retval) {
                try {
                    var retStr = safeToString(retval);

                    // If replacement is exactly "_" -> print details + stack
                    if (this.replaceArg === "_") {
                        console.log("\n[HOOK NSString stringByReplacingOccurrencesOfString:withString:options:range:] (replacement == \"_\")");
                        console.log("  original(arg):", this.origArg === null ? "<nil>" : this.origArg);
                        console.log("  replacement(arg):", this.replaceArg === null ? "<nil>" : this.replaceArg);
                        console.log("  returned:", retStr === null ? "<nil>" : retStr);

                        if (this._bt && this._bt.length) {
                            console.log("  backtrace (top " + this._bt.length + "):");
                            resolveAndPrintAddrs(this._bt);
                        } else {
                            console.log("  backtrace: <empty>");
                        }
                        console.log("  elapsed(ms):", (Date.now() - this._ts));
                    } else {
                        // Minimal logging to avoid noise/perf hit
                        // Uncomment next line for light debugging:
                        // console.log("[HOOK NSString] replaceArg != '_' -> skip stack (rep='" + this.replaceArg + "')");
                    }
                } catch (e) {
                    console.log("[HOOK] onLeave error:", e);
                }
            }
        });

        console.log("[+] Hooked NSString " + selName + " (will print stack only when replacement == '_')");
    }
} catch (err) {
    console.log("Hook setup failed:", err);
}
*/




//TMEWebUserAgent
if (!ObjC.available) {
    console.log("[-] ObjC runtime is not available!");
    throw new Error("ObjC not available");
}

try {
    var clsName = "TMEWebUserAgent";
    var selName = "- readLocalUserAgentCaches";

    if (!(ObjC.classes[clsName] && ObjC.classes[clsName][selName])) {
        console.log("[-] Class or selector not found:", clsName, selName);
    } else {
        var impl = ObjC.classes[clsName][selName].implementation;
        console.log("[*] Hooking", clsName, selName, "impl:", impl);

        Interceptor.attach(impl, {
            onEnter: function (args) {
                // args[0] = self, args[1] = SEL, any other args follow
                try {
                    this.self = new ObjC.Object(args[0]);
                    this.sel = ObjC.selectorAsString(args[1]);
                    console.log("\n[Enter] %s %s", this.self.$className, this.sel);

                    // 如果方法有入参（本方法看来没有），可以打印更多 args：
                    // for (var i = 2; i < 6; i++) { 
                    //     if (!args[i].isNull()) console.log(" arg[%d] => %s", i, new ObjC.Object(args[i]).toString());
                    // }
                    // 打印调用栈（可选）
                    try {
                        var bt = Thread.backtrace(this.context, Backtracer.FUZZY)
                            .map(DebugSymbol.fromAddress).join("\n");
                        console.log("Backtrace:\n" + bt);
                    } catch (e) {  }
                } catch (e) {
                    console.log("[onEnter error]", e);
                }
            },
            onLeave: function (retval) {
                try {
                    console.log("[Leave] selector:", this.sel);

                    if (retval.isNull()) {
                        console.log(" return: <null>");
                        return;
                    }

                    // 转换为 ObjC 对象（如果是 Objective-C 对象）
                    try {
                        var obj = new ObjC.Object(retval);
                        console.log(" return class:", obj.$className);

                        // 常见类型打印
                        if (obj.$className === 'NSString' || obj.$className === '__NSCFString') {
                            console.log(" return NSString:", obj.toString());
                        } else if (obj.$className === 'NSDictionary') {
                            console.log(" return NSDictionary description:\n", obj.toString());
                            // 更友好的遍历打印 key/value（注意性能）
                            try {
                                var keys = obj.allKeys();
                                var kcount = keys.count();
                                for (var i = 0; i < kcount; i++) {
                                    var k = keys.objectAtIndex_(i).toString();
                                    var v = obj.objectForKey_(keys.objectAtIndex_(i));
                                    // v 可能为 NSString/NSNumber/NSArray/NSDictionary...
                                    var vs = (v && (new ObjC.Object(v)).toString()) || "<null>";
                                    console.log("   %s => %s", k, vs);
                                }
                            } catch (e) {  }
                        } else if (obj.$className === 'NSArray') {
                            console.log(" return NSArray description:\n", obj.toString());
                        } else {
                            // fallback: call description/toString
                            console.log(" return (toString):", obj.toString());
                        }
                    } catch (e) {
                        // 不是 ObjC 对象（可能是 CFTypeRef 或原生类型）
                        console.log(" return (non-ObjC) ptr:", retval);
                    }
                } catch (e) {
                    console.log("[onLeave error]", e);
                }
            }
        });
        console.log("[*] Hook installed:", clsName, selName);
    }
} catch (err) {
    console.log("[-] Exception while installing hook:", err);
}


// SystemUserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_11 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148";
//       UserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_11 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 QQJSSDK/1.0.0 WKWebView";

/*
if (!ObjC.available) {
    console.log("[-] ObjC runtime not available");
    throw new Error("ObjC runtime not available");
}

function dumpObjCArg(ptr) {
    if (!ptr || ptr.isNull()) return "<nil>";
    try {
        var o = new ObjC.Object(ptr);
        // common types
        if (o.$className === "NSString" || o.$className.indexOf("__NSCFString") === 0) {
            return "(NSString) " + o.toString();
        } else if (o.$className === "NSDictionary") {
            return "(NSDictionary) " + o.toString();
        } else if (o.$className === "NSArray") {
            return "(NSArray) " + o.toString();
        } else if (o.$className === "__NSCFNumber" || o.$className === "NSNumber") {
            return "(NSNumber) " + o.toString();
        } else {
            return "(" + o.$className + ") " + o.toString();
        }
    } catch (e) {
        // not ObjC object — print numeric / pointer
        try {
            return "(ptr) " + ptr;
        } catch (ee) {
            return "(unknown arg)";
        }
    }
}

function dumpReturnValue(retval) {
    if (!retval) return "<no retval>";
    try {
        if (retval.isNull()) return "<nil>";
    } catch (e) {}

    // try ObjC conversion
    try {
        var o = new ObjC.Object(retval);
        if (o.$className === "NSString" || o.$className.indexOf("__NSCFString") === 0) {
            return "(NSString) " + o.toString();
        } else if (o.$className === "NSDictionary") {
            return "(NSDictionary) " + o.toString();
        } else if (o.$className === "NSArray") {
            return "(NSArray) " + o.toString();
        } else if (o.$className === "__NSCFNumber" || o.$className === "NSNumber") {
            return "(NSNumber) " + o.toString();
        } else {
            return "(" + o.$className + ") " + o.toString();
        }
    } catch (e) {
        // not ObjC object: print pointer or integer
        try {
            return "(ptr) " + retval;
        } catch (ee) {
            return "(unknown retval)";
        }
    }
}

try {
    var cls = "TMEWebUserAgent";
    // instance selector
    var instSel = "- getCustomUserAgent:";
    // class selector
    var clsSel = "+ getCustomUserAgent:";

    // hook instance method
    if (ObjC.classes[cls] && ObjC.classes[cls][instSel]) {
        var impl = ObjC.classes[cls][instSel].implementation;
        console.log("[*] Attaching to", cls, instSel, "impl:", impl);
        Interceptor.attach(impl, {
            onEnter: function (args) {
                try {
                    this.self = new ObjC.Object(args[0]);
                    this.sel = ObjC.selectorAsString(args[1]);
                    // first explicit arg for ObjC instance method is args[2]
                    this.arg1 = args[2];
                    console.log("\n[ENTER] %s %s", this.self.$className, this.sel);
                    console.log("  self =>", this.self.toString());
                    console.log("  arg1 =>", dumpObjCArg(this.arg1));
                    // small stack backtrace
                    try {
                        var bt = Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join("\n");
                        console.log("  backtrace:\n" + bt);
                    } catch (e) {}
                } catch (e) {
                    console.log("[onEnter error]", e);
                }
            },
            onLeave: function (retval) {
                try {
                    console.log("[LEAVE] %s %s", this.self ? this.self.$className : "?", this.sel);
                    console.log("  return =>", dumpReturnValue(retval));
                } catch (e) {
                    console.log("[onLeave error]", e);
                }
            }
        });
    } else {
        console.log("[-] Instance selector not found:", cls, instSel);
    }

    // hook class method (prefix '+' methods available under ObjC.classes["ClassName"]["+ selector"])
    if (ObjC.classes[cls] && ObjC.classes[cls][clsSel]) {
        var impl2 = ObjC.classes[cls][clsSel].implementation;
        console.log("[*] Attaching to", cls, clsSel, "impl:", impl2);
        Interceptor.attach(impl2, {
            onEnter: function (args) {
                try {
                    // for class method, args[0] is the metaclass object (treated as self)
                    this.self = new ObjC.Object(args[0]);
                    this.sel = ObjC.selectorAsString(args[1]);
                    this.arg1 = args[2];
                    console.log("\n[ENTER] %s %s", this.self.$className, this.sel);
                    console.log("  self =>", this.self.toString());
                    console.log("  arg1 =>", dumpObjCArg(this.arg1));
                    try {
                        var bt = Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join("\n");
                        console.log("  backtrace:\n" + bt);
                    } catch (e) {}
                } catch (e) {
                    console.log("[onEnter(class) error]", e);
                }
            },
            onLeave: function (retval) {
                try {
                    console.log("  arg1 =>", dumpObjCArg(this.arg1));
                    console.log("[LEAVE CLASS] %s %s", this.self ? this.self.$className : "?", this.sel);
                    console.log("  return =>", dumpReturnValue(retval));
                } catch (e) {
                    console.log("[onLeave(class) error]", e);
                }
            }
        });
    } else {
        console.log("[-] Class selector not found:", cls, clsSel);
    }
} catch (err) {
    console.log("[-] Exception installing hooks:", err);
}
*/

/*
if (!Module) {
    console.log("This script must run under Frida.");
}

const TARGET_BASENAME = "com.kugou.kugou1002.plist";
const TARGET_SUFFIX = "/Library/Preferences/" + TARGET_BASENAME;

function isTargetPath(path) {
    if (!path) return false;
    try {
        var s = path.toString();
        if (s.length === 0) return false;
        // 常见情况：绝对路径以 /var/.../Library/Preferences/com.kugou...
        if (s.endsWith(TARGET_SUFFIX)) return true;
        // 也接受包含目标文件名的任意路径（更宽松）
        if (s.indexOf(TARGET_BASENAME) !== -1) return true;
        // file:// URL 形式
        if (s.indexOf("file://") === 0 && s.indexOf(TARGET_BASENAME) !== -1) return true;
    } catch (e) {  }
    return false;
}

function bt() {
    try {
        return Thread.backtrace(this.context || {}, Backtracer.FUZZY)
            .map(DebugSymbol.fromAddress)
            .join("\n");
    } catch (e) {
        return "<backtrace error: " + e + ">";
    }
}

function safeReadCString(ptrAddr, maxLen) {
    try {
        if (!ptrAddr || ptrAddr.isNull()) return null;
        return Memory.readUtf8String(ptrAddr, maxLen || 256);
    } catch (e) {
        return "<error reading string>";
    }
}

function shortHex(ptr) {
    return ptr ? ptr.toString() : "null";
}

console.log("[watch_plist] starting hooks for " + TARGET_BASENAME);

// ----- POSIX / libc level hooks -----
const exportsToHook = [
    "open", "openat", "fopen", "fopen$UNIX2003",
    "read", "write", "rename", "unlink", "stat", "stat$INODE64",
    "lstat", "access"
];

exportsToHook.forEach(function(sym) {
    var addr = null;
    try {
        addr = Module.findExportByName(null, sym);
    } catch (e) { addr = null; }
    if (addr) {
        try {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    try {
                        this._sym = sym;
                        // log common path arg positions
                        if (sym === "open" || sym === "openat" || sym === "fopen" || sym === "fopen$UNIX2003" || sym === "access" || sym === "stat" || sym === "lstat") {
                            var p = args[0];
                            var path = safeReadCString(p);
                            if (isTargetPath(path)) {
                                console.log("\n[POSIX ENTER] " + sym + " path => " + path);
                                console.log("  pid:", Process.id, "tid:", Process.getCurrentThreadId());
                                console.log("  backtrace:\n" + bt.call(this));
                                this._targetPath = path;
                            }
                        } else if (sym === "rename") {
                            var oldp = safeReadCString(args[0]);
                            var newp = safeReadCString(args[1]);
                            if (isTargetPath(oldp) || isTargetPath(newp)) {
                                console.log("\n[POSIX ENTER] rename => from: " + oldp + " to: " + newp);
                                console.log("  backtrace:\n" + bt.call(this));
                                this._targetPath = isTargetPath(oldp) ? oldp : newp;
                            }
                        } else if (sym === "write") {
                            // write(fd, buf, count)
                            this._isWrite = true;
                            this._fd = args[0].toInt32();
                            this._buf = args[1];
                            this._count = args[2].toInt32();
                            // We don't know path here; use later if fd maps to target (not implemented)
                        } else if (sym === "read") {
                            // read(fd, buf, count) - can't know path here
                            this._isRead = true;
                        }
                    } catch (e) {
                        // ignore
                    }
                },
                onLeave: function(retval) {
                    try {
                        if (this._targetPath) {
                            console.log("  [POSIX LEAVE] " + sym + " return => " + retval);
                        } else if (this._isWrite && this._buf && this._count > 0) {
                            // Optionally dump small writes (not safe for binary large writes)
                            var len = Math.min(this._count, 256);
                            var s = "";
                            try {
                                s = Memory.readUtf8String(this._buf, len);
                            } catch (e) {
                                s = "<binary or unreadable>";
                            }
                            console.log("\n[POSIX WRITE] fd=" + this._fd + " count=" + this._count + " sample => " + s);
                            // backtrace to find who wrote
                            console.log("  backtrace:\n" + bt.call(this));
                        }
                    } catch (e) {}
                }
            });
            // console.log("hooked " + sym + " at " + addr);
        } catch (e) {
            console.log("failed to attach " + sym + ": " + e);
        }
    } else {
        // console.log("export not found: " + sym);
    }
});

// ----- Foundation / Objective-C layer hooks -----
// Helper to safe convert ObjC object to string
function objToString(obj) {
    try {
        if (!obj) return "<null>";
        return obj.toString();
    } catch (e) {
        return "<toString error>";
    }
}

// Hook NSUserDefaults setObject:forKey: and objectForKey:
if (ObjC.available) {
    try {
        var NSUserDefaults = ObjC.classes.NSUserDefaults;
        if (NSUserDefaults) {
            var sel_set = "setObject:forKey:";
            if (NSUserDefaults[sel_set]) {
                Interceptor.attach(NSUserDefaults[sel_set].implementation, {
                    onEnter: function(args) {
                        try {
                            var selfObj = new ObjC.Object(args[0]);
                            var obj = args[2] ? new ObjC.Object(args[2]) : null;
                            var key = args[3] ? new ObjC.Object(args[3]).toString() : null;
                            if (key && key.indexOf(TARGET_BASENAME) !== -1) {
                                console.log("\n[NSUserDefaults setObject:forKey:] key => " + key + " value => " + objToString(obj));
                                console.log("  self class:", selfObj.$className);
                                console.log("  backtrace:\n" + bt.call(this));
                            } else {
                                // also log if value is NSDictionary/NSString contains target filename
                                if (obj && (obj.toString && obj.toString().indexOf(TARGET_BASENAME) !== -1)) {
                                    console.log("\n[NSUserDefaults setObject:forKey:] maybe contains path => key:" + key + " val: " + objToString(obj));
                                    console.log("  backtrace:\n" + bt.call(this));
                                }
                            }
                        } catch (e) {}
                    }
                });
            }

            var sel_get = "objectForKey:";
            if (NSUserDefaults[sel_get]) {
                Interceptor.attach(NSUserDefaults[sel_get].implementation, {
                    onEnter: function(args) {
                        try {
                            var key = args[2] ? new ObjC.Object(args[2]).toString() : null;
                            if (key && key.indexOf(TARGET_BASENAME) !== -1) {
                                console.log("\n[NSUserDefaults objectForKey:] key => " + key);
                                console.log("  backtrace:\n" + bt.call(this));
                            }
                        } catch (e) {}
                    },
                    onLeave: function(retval) {
                        try {
                            if (retval && !retval.isNull()) {
                                var o = new ObjC.Object(retval);
                                // only print small objects safely
                                console.log("  return => " + objToString(o));
                            } else {
                                // null
                            }
                        } catch (e) {}
                    }
                });
            }
        }
    } catch (e) {
        console.log("NSUserDefaults hook error: " + e);
    }

    // Hook NSDictionary/NSMutableDictionary read/write from file
    try {
        var NSDictionaryClass = ObjC.classes.NSDictionary;
        var NSMutableDictionaryClass = ObjC.classes.NSMutableDictionary;
        var dictReadSels = ["dictionaryWithContentsOfFile:", "dictionaryWithContentsOfURL:"];
        dictReadSels.forEach(function(sel) {
            if (NSDictionaryClass[sel]) {
                Interceptor.attach(NSDictionaryClass[sel].implementation, {
                    onEnter: function(args) {
                        try {
                            var path = args[2] ? ObjC.Object(args[2]).toString() : null;
                            if (isTargetPath(path)) {
                                console.log("\n[NSDictionary read] " + sel + " path => " + path);
                                console.log("  backtrace:\n" + bt.call(this));
                                this._hit = true;
                            }
                        } catch (e) {}
                    },
                    onLeave: function(retval) {
                        try {
                            if (this._hit) {
                                if (retval && !retval.isNull()) {
                                    var o = new ObjC.Object(retval);
                                    console.log("  return class: " + o.$className);
                                    try {
                                        // dump small dictionary
                                        var s = o.description ? o.description().toString() : "<no desc>";
                                        console.log("  return (toString): " + s);
                                    } catch (e) {}
                                } else {
                                    console.log("  return: null");
                                }
                            }
                        } catch (e) {}
                    }
                });
            }
        });

        // writeToFile:atomically:
        var writeSel = "writeToFile:atomically:";
        if (NSDictionaryClass[writeSel]) {
            Interceptor.attach(NSDictionaryClass[writeSel].implementation, {
                onEnter: function(args) {
                    try {
                        var selfObj = new ObjC.Object(args[0]);
                        var path = args[2] ? ObjC.Object(args[2]).toString() : null;
                        if (isTargetPath(path)) {
                            console.log("\n[NSDictionary write] writeToFile path => " + path);
                            console.log("  dictionary class: " + selfObj.$className);
                            console.log("  backtrace:\n" + bt.call(this));
                            this._hit = true;
                        }
                    } catch (e) {}
                },
                onLeave: function(retval) {
                    try {
                        if (this._hit) {
                            console.log("  write result => " + retval);
                        }
                    } catch (e) {}
                }
            });
        }

        // NSMutableDictionary might use same selector
        if (NSMutableDictionaryClass && NSMutableDictionaryClass[writeSel]) {
            Interceptor.attach(NSMutableDictionaryClass[writeSel].implementation, {
                onEnter: function(args) {
                    try {
                        var selfObj = new ObjC.Object(args[0]);
                        var path = args[2] ? ObjC.Object(args[2]).toString() : null;
                        if (isTargetPath(path)) {
                            console.log("\n[NSMutableDictionary write] writeToFile path => " + path);
                            console.log("  dictionary class: " + selfObj.$className);
                            console.log("  backtrace:\n" + bt.call(this));
                            this._hit = true;
                        }
                    } catch (e) {}
                },
                onLeave: function(retval) {
                    try {
                        if (this._hit) {
                            console.log("  write result => " + retval);
                        }
                    } catch (e) {}
                }
            });
        }
    } catch (e) {
        console.log("NSDictionary hook error: " + e);
    }

    // Hook NSUserDefaults initWithSuiteName: or standardUserDefaults access to detect where they're reading/writing files
    try {
        var sel_std = "standardUserDefaults";
        if (NSUserDefaults && NSUserDefaults[sel_std]) {
            Interceptor.attach(NSUserDefaults[sel_std].implementation, {
                onEnter: function(args) {},
                onLeave: function(retval) {
                    try {
                        if (retval && !retval.isNull()) {
                            var s = new ObjC.Object(retval);
                            // console.log("[NSUserDefaults] standardUserDefaults => " + s);
                        }
                    } catch (e) {}
                }
            });
        }
    } catch (e) {}

    // Hook CFPreferences (C API) if present: CFPreferencesSetValue / CFPreferencesCopyAppValue etc.
    try {
        var cfNames = ["CFPreferencesSetValue", "CFPreferencesCopyAppValue", "CFPreferencesAppSynchronize"];
        cfNames.forEach(function(n) {
            var a = Module.findExportByName("CoreFoundation", n) || Module.findExportByName(null, n);
            if (a) {
                Interceptor.attach(a, {
                    onEnter: function(args) {
                        try {
                            // Can't safely convert CFTypes here in all cases; just log backtrace
                            console.log("\n[CFPreferences call] " + n + " called");
                            console.log("  backtrace:\n" + bt.call(this));
                        } catch (e) {}
                    }
                });
            }
        });
    } catch (e) {}

} else {
    console.log("ObjC runtime not available - skipping ObjC hooks");
}

console.log("[watch_plist] hooks installed.");
*/