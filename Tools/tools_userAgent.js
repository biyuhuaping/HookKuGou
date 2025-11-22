// 监控 NSUserDefaults 指定字段的读写（仅观察，不替换）
// 运行：frida -U -f com.kugou.kugou1002 -l tools_userAgent.js

const WATCH_KEYS = ["UserAgent", "SystemUserAgent", "kTencentStatic_Qimei"];

function quickCheckKey(keyPtr) {
    if (!keyPtr || keyPtr.isNull()) return false;
    try {
        var key = ObjC.Object(keyPtr).toString();
        if (!key) return false;
        for (var i = 0; i < WATCH_KEYS.length; i++) {
            if (key.indexOf(WATCH_KEYS[i]) !== -1) return true;
        }
        return false;
    } catch (e) {
        return false;
    }
}

function safeDescribeValue(ptr) {
    if (!ptr || ptr.isNull()) return "<nil>";
    try {
        var obj = ObjC.Object(ptr);
        // 只处理字符串类型，其他类型简单显示
        try {
            var className = obj.$className;
            if (className === "NSString" || className === "__NSCFString" || className === "__NSCFConstantString") {
                return obj.toString();
            }
            return "[" + className + "]";
        } catch (e) {
            // 如果无法获取类名，尝试直接转字符串
            try {
                return obj.toString();
            } catch (e2) {
                return "<unknown>";
            }
        }
    } catch (e) {
        return "<unknown>";
    }
}

if (!ObjC.available) {
    console.log("Objective-C runtime is not available!");
} else {
    try {
        var NSUserDefaults = ObjC.classes.NSUserDefaults;
        var sel1 = "- objectForKey:";
        var sel2 = "- setObject:forKey:";
        
        if (NSUserDefaults && NSUserDefaults[sel1]) {
            Interceptor.attach(NSUserDefaults[sel1].implementation, {
                onEnter: function(args) {
                    // 快速检查 key，不匹配则跳过
                    this._shouldLog = quickCheckKey(args[2]);
                    if (this._shouldLog) {
                        this._keyPtr = args[2];
                    }
                },
                onLeave: function(retval) {
                    if (!this._shouldLog) return;
                    try {
                        var key = ObjC.Object(this._keyPtr).toString();
                        var value = safeDescribeValue(retval);
                        console.log("[objectForKey] " + key + " => " + value);
                    } catch (e) {}
                }
            });
        }
        
        if (NSUserDefaults && NSUserDefaults[sel2]) {
            Interceptor.attach(NSUserDefaults[sel2].implementation, {
                onEnter: function(args) {
                    // 快速检查 key，不匹配则跳过
                    this._shouldLog = quickCheckKey(args[3]);
                    if (this._shouldLog) {
                        this._keyPtr = args[3];
                        this._valuePtr = args[2];
                    }
                },
                onLeave: function(retval) {
                    if (!this._shouldLog) return;
                    try {
                        var key = ObjC.Object(this._keyPtr).toString();
                        var value = safeDescribeValue(this._valuePtr);
                        console.log("[setObject:forKey:] " + key + " = " + value);
                    } catch (e) {}
                }
            });
        }
        
        console.log("[OK] NSUserDefaults hooks installed (watch only)");
    } catch (err) {
        console.log("hook error:", err);
    }
}

// --- 监控 NSDictionary 的 initWithContentsOfFile: / writeToFile:atomically: (直接读写 plist 的情况) ---
// if (ObjC.available) {
//     try {
//         const NSDictionaryClass = ObjC.classes.NSDictionary;

//         if (NSDictionaryClass["- initWithContentsOfFile:"]) {
//             Interceptor.attach(NSDictionaryClass["- initWithContentsOfFile:"].implementation, {
//                 onEnter: function(args) {
//                     try {
//                         this._path = args[2] ? ObjC.Object(args[2]).toString() : null;
//                     } catch (e) { this._path = null; }
//                 },
//                 onLeave: function(retval) {
//                     try {
//                         if (this._path && this._path.indexOf("/Library/Preferences/" + TARGET_BUNDLE + ".plist") !== -1) {
//                             console.log("\n[NSDictionary initWithContentsOfFile:] path=", this._path);
//                             // 结果对象(retval) 是 NSDictionary*
//                             try {
//                                 let dict = ObjC.Object(retval);
//                                 console.log("  contents =>", dict.toString());
//                             } catch (e) {
//                                 console.log("  could not convert retval to NSDictionary:", e);
//                             }
//                             console.log("  backtrace:\n", getBacktrace(this.context));
//                         }
//                     } catch (e) {}
//                 }
//             });
//         }

//         if (NSDictionaryClass["- writeToFile:atomically:"]) {
//             Interceptor.attach(NSDictionaryClass["- writeToFile:atomically:"].implementation, {
//                 onEnter: function(args) {
//                     try {
//                         this._path = args[2] ? ObjC.Object(args[2]).toString() : null;
//                         this._dict = ObjC.Object(args[0]); // self
//                     } catch (e) { this._path = null; this._dict = null; }
//                     if (this._path && this._path.indexOf("/Library/Preferences/" + TARGET_BUNDLE + ".plist") !== -1) {
//                         try {
//                             console.log("\n[NSDictionary writeToFile:atomically:] path=", this._path);
//                             console.log("  writing =>", this._dict.toString());
//                             console.log("  backtrace:\n", getBacktrace(this.context));
//                         } catch (e) {}
//                     }
//                 }
//             });
//         }
//     } catch (e) {
//         console.log("[WARN] NSDictionary hooks failed:", e);
//     }
// }
