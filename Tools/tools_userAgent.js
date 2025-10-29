// 监控 NSUserDefaults 指定字段的读写（仅观察，不替换）
// 运行：frida -U -f com.kugou.kugou1002 -l tools_userAgent.js

const WATCH_KEYS = ["UserAgent", "SystemUserAgent", "kTencentStatic_Qimei"];

function safeToString(ptr) {
    if (!ptr || ptr.isNull()) return null;
    try {
        return ObjC.Object(ptr).toString();
    } catch (e) {
        return null;
    }
}

function isWatchedKey(key) {
    return key && WATCH_KEYS.some(k => key.indexOf(k) !== -1);
}

if (!ObjC.available) {
    console.log("[WARN] ObjC not available");
    throw new Error("ObjC not available");
}

try {
    const NSUserDefaults = ObjC.classes.NSUserDefaults;

    // Hook objectForKey: - 只观察，不修改
    Interceptor.attach(NSUserDefaults["- objectForKey:"].implementation, {
        onEnter: function(args) {
            this._keyPtr = args[2];
        },
        onLeave: function(retval) {
            if (!this._keyPtr || this._keyPtr.isNull()) return;
            
            let key = null;
            try {
                key = safeToString(this._keyPtr);
            } catch (e) {
                return;
            }
            
            if (!isWatchedKey(key)) return;
            
            try {
                let value = "<nil>";
                if (retval && !retval.isNull()) {
                    const retObj = safeToString(retval);
                    value = retObj || "<non-string>";
                }
                console.log(`[objectForKey] ${key} => ${value}`);
            } catch (e) {}
        }
    });

    // Hook setObject:forKey: - 只观察
    Interceptor.attach(NSUserDefaults["- setObject:forKey:"].implementation, {
        onEnter: function(args) {
            this._keyPtr = args[3];
            this._valuePtr = args[2];
        },
        onLeave: function(retval) {
            if (!this._keyPtr || this._keyPtr.isNull()) return;
            
            let key = null;
            try {
                key = safeToString(this._keyPtr);
            } catch (e) {
                return;
            }
            
            if (!isWatchedKey(key)) return;
            
            try {
                const value = safeToString(this._valuePtr) || "<nil>";
                console.log(`[setObject:forKey:] ${key} = ${value}`);
            } catch (e) {}
        }
    });

    console.log("[OK] NSUserDefaults hooks installed (watch only)");
} catch (e) {
    console.log("[ERR] Hook failed:", e);
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
