// watch_ua_plist.js
// 监控并可替换 com.kugou.kugou1002.plist 中 UserAgent / SystemUserAgent 的读写

const TARGET_BUNDLE = "com.kugou.kugou1002";
const WATCH_KEYS = ["UserAgent", "SystemUserAgent"];

// 若要在读取时替换值，在这里写入你想替换成的字符串；否则置为 null
const OVERRIDE = {
    "UserAgent": null,            // e.g. "MyFakeUA/1.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"
    "SystemUserAgent": null
};

// helpers
function tryCFToString(ptr) {
    if (!ptr || ptr.isNull && ptr.isNull()) return null;
    try {
        // If it's a CFStringRef/NSString it can be wrapped by ObjC.Object
        return new ObjC.Object(ptr).toString();
    } catch (e) {
        try {
            return Memory.readUtf8String(ptr);
        } catch (e2) {
            return String(ptr);
        }
    }
}

function getBacktrace(context) {
    try {
        return Thread.backtrace(context, Backtracer.FUZZY)
            .map(DebugSymbol.fromAddress).join("\n");
    } catch (e) {
        return "<backtrace error>";
    }
}

function isTargetApp(appId) {
    if (!appId) return false;
    return (appId.indexOf(TARGET_BUNDLE) !== -1);
}

function checkKeyInterest(k) {
    if (!k) return false;
    for (let i=0;i<WATCH_KEYS.length;i++){
        if (k.indexOf(WATCH_KEYS[i]) !== -1) return true;
    }
    return false;
}

console.log("[Frida] Watch UA plist script loaded. Target:", TARGET_BUNDLE);

// --- Hook CFPreferencesCopyAppValue / CFPreferencesSetAppValue / CFPreferencesAppSynchronize ---
// signatures:
// CFPropertyListRef CFPreferencesCopyAppValue(CFStringRef key, CFStringRef applicationID)
// void CFPreferencesSetAppValue(CFStringRef key, CFPropertyListRef value, CFStringRef applicationID)
// Boolean CFPreferencesAppSynchronize(CFStringRef applicationID)

const cfCopy = Module.findExportByName(null, "CFPreferencesCopyAppValue");
const cfSet  = Module.findExportByName(null, "CFPreferencesSetAppValue");
const cfSync = Module.findExportByName(null, "CFPreferencesAppSynchronize");

if (cfCopy) {
    Interceptor.attach(cfCopy, {
        onEnter: function(args) {
            this._key = tryCFToString(args[0]);
            this._app = tryCFToString(args[1]);
        },
        onLeave: function(retval) {
            try {
                if (isTargetApp(this._app) && checkKeyInterest(this._key)) {
                    const oldVal = tryCFToString(retval) || "<non-string or null>";
                    console.log("\n[CFPreferencesCopyAppValue] app=", this._app, " key=", this._key);
                    console.log("  original value =>", oldVal);
                    console.log("  backtrace:\n", getBacktrace(this.context));
                    // 如果有 OVERRIDE，则替换返回值（构造一个 CFString 并返回）
                    const want = OVERRIDE[this._key];
                    if (want && want.length) {
                        // create an NSString in ObjC and return its pointer
                        const ns = ObjC.classes.NSString.stringWithUTF8String_(want);
                        // CFRetain to avoid immediate release
                        const cf = ns.handle;
                        retval.replace(cf);
                        console.log("  >>> overridden to:", want);
                    }
                }
            } catch (e) {
                console.log("[ERR] CFPreferencesCopyAppValue onLeave:", e);
            }
        }
    });
} else {
    console.log("[WARN] CFPreferencesCopyAppValue not found");
}

if (cfSet) {
    Interceptor.attach(cfSet, {
        onEnter: function(args) {
            this._key = tryCFToString(args[0]);
            this._val = tryCFToString(args[1]);
            this._app = tryCFToString(args[2]);
            if (isTargetApp(this._app) && checkKeyInterest(this._key)) {
                console.log("\n[CFPreferencesSetAppValue] app=", this._app, " key=", this._key, " newVal=", this._val);
                console.log("  backtrace:\n", getBacktrace(this.context));
            }
        }
    });
} else {
    console.log("[WARN] CFPreferencesSetAppValue not found");
}

if (cfSync) {
    Interceptor.attach(cfSync, {
        onEnter: function(args) {
            this._app = tryCFToString(args[0]);
            if (isTargetApp(this._app)) {
                console.log("\n[CFPreferencesAppSynchronize] app=", this._app);
                console.log("  backtrace:\n", getBacktrace(this.context));
            }
        }
    });
} else {
    console.log("[WARN] CFPreferencesAppSynchronize not found");
}


// --- Hook NSUserDefaults -objectForKey: / -setObject:forKey: (ObjC 层) ---
if (ObjC.available) {
    try {
        const NSUserDefaults = ObjC.classes.NSUserDefaults;

        if (NSUserDefaults["- objectForKey:"]) {
            Interceptor.attach(NSUserDefaults["- objectForKey:"].implementation, {
                onEnter: function(args) {
                    try {
                        this._key = args[2] ? ObjC.Object(args[2]).toString() : null;
                        // get bundle id from [NSBundle mainBundle].bundleIdentifier cheaply
                        try {
                            this._app = ObjC.classes.NSBundle.mainBundle().bundleIdentifier().toString();
                        } catch (e) {
                            this._app = null;
                        }
                    } catch (e) { this._key = null; this._app = null; }
                },
                onLeave: function(retval) {
                    try {
                        if (isTargetApp(this._app) && checkKeyInterest(this._key)) {
                            let rv = "<non-string or nil>";
                            try { rv = retval && !retval.isNull() ? ObjC.Object(retval).toString() : "<nil>"; } catch(e){}
                            console.log("\n[NSUserDefaults objectForKey:] app=", this._app, " key=", this._key, " => ", rv);
                            console.log("  backtrace:\n", getBacktrace(this.context));
                            const want = OVERRIDE[this._key];
                            if (want && want.length) {
                                // return a new NSString object
                                const ns = ObjC.classes.NSString.stringWithUTF8String_(want);
                                retval.replace(ns.handle);
                                console.log("  >>> overridden to:", want);
                            }
                        }
                    } catch (e) { console.log("[ERR] objectForKey onLeave:", e); }
                }
            });
        }

        if (NSUserDefaults["- setObject:forKey:"]) {
            Interceptor.attach(NSUserDefaults["- setObject:forKey:"].implementation, {
                onEnter: function(args) {
                    try {
                        const v = args[2] ? ObjC.Object(args[2]).toString() : "<nil>";
                        const k = args[3] ? ObjC.Object(args[3]).toString() : "<nil>";
                        let app = null;
                        try { app = ObjC.classes.NSBundle.mainBundle().bundleIdentifier().toString(); } catch(e){}
                        if (isTargetApp(app) && checkKeyInterest(k)) {
                            console.log("\n[NSUserDefaults setObject:forKey:] app=", app, " key=", k, " value=", v);
                            console.log("  backtrace:\n", getBacktrace(this.context));
                        }
                    } catch (e) {}
                }
            });
        }
    } catch (e) {
        console.log("[WARN] NSUserDefaults hook failed:", e);
    }
} else {
    console.log("[WARN] ObjC not available");
}


// --- 监控 NSDictionary 的 initWithContentsOfFile: / writeToFile:atomically: (直接读写 plist 的情况) ---
if (ObjC.available) {
    try {
        const NSDictionaryClass = ObjC.classes.NSDictionary;

        if (NSDictionaryClass["- initWithContentsOfFile:"]) {
            Interceptor.attach(NSDictionaryClass["- initWithContentsOfFile:"].implementation, {
                onEnter: function(args) {
                    try {
                        this._path = args[2] ? ObjC.Object(args[2]).toString() : null;
                    } catch (e) { this._path = null; }
                },
                onLeave: function(retval) {
                    try {
                        if (this._path && this._path.indexOf("/Library/Preferences/" + TARGET_BUNDLE + ".plist") !== -1) {
                            console.log("\n[NSDictionary initWithContentsOfFile:] path=", this._path);
                            // 结果对象(retval) 是 NSDictionary*
                            try {
                                let dict = ObjC.Object(retval);
                                console.log("  contents =>", dict.toString());
                            } catch (e) {
                                console.log("  could not convert retval to NSDictionary:", e);
                            }
                            console.log("  backtrace:\n", getBacktrace(this.context));
                        }
                    } catch (e) {}
                }
            });
        }

        if (NSDictionaryClass["- writeToFile:atomically:"]) {
            Interceptor.attach(NSDictionaryClass["- writeToFile:atomically:"].implementation, {
                onEnter: function(args) {
                    try {
                        this._path = args[2] ? ObjC.Object(args[2]).toString() : null;
                        this._dict = ObjC.Object(args[0]); // self
                    } catch (e) { this._path = null; this._dict = null; }
                    if (this._path && this._path.indexOf("/Library/Preferences/" + TARGET_BUNDLE + ".plist") !== -1) {
                        try {
                            console.log("\n[NSDictionary writeToFile:atomically:] path=", this._path);
                            console.log("  writing =>", this._dict.toString());
                            console.log("  backtrace:\n", getBacktrace(this.context));
                        } catch (e) {}
                    }
                }
            });
        }
    } catch (e) {
        console.log("[WARN] NSDictionary hooks failed:", e);
    }
}

// end
console.log("[Frida] Hooks installed for plist UA monitoring.");
