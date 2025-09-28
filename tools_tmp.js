// if (ObjC.available) {
//     const cls = ObjC.classes.NSProcessInfo;
//     const sel = "+ propConfig_source";

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

if (!ObjC.available) {
    console.log("Objective-C runtime is not available");
} else {
    // helper: safe call obj method if exists, return null on error
    function safeCall(obj, selName) {
        try {
            if (!obj || obj.isNull()) return null;
            var sel = ObjC.selector(selName);
            if (obj.respondsToSelector_(sel)) {
                return obj[selName](); // Frida auto-maps simple selectors
            }
            // fallback: try alternate call style
            if (typeof obj[selName] === "function") {
                return obj[selName]();
            }
        } catch (e) {
            // fallthrough
        }
        return null;
    }

    // safer conversion for returned values
    function toStringSafe(val) {
        try {
            if (val === null || val === undefined) return "<nil>";
            if (typeof val === "string") return val;
            // If ObjC object
            if (val.__proto__ && val.$className) {
                // ObjC.Object-like
                try {
                    return new ObjC.Object(val).toString();
                } catch (e) {
                    try { return ObjC.Object(val).toString(); } catch(e2) {}
                }
            }
            // If Frida wrapped ObjC.Object
            try {
                if (val.toString) return val.toString();
            } catch(e){}
            return String(val);
        } catch (e) {
            return "<unprintable>";
        }
    }

    // Try to pretty-print NSDictionary (limited)
    function dictToPairs(dictObj, maxItems) {
        try {
            if (!dictObj || dictObj.isNull()) return "<nil>";
            var o = new ObjC.Object(dictObj);
            if (!o.allKeys) return "<not-a-dict>";
            var keys = o.allKeys();
            var out = [];
            var count = Math.min(keys.count().toInt32(), maxItems || 10);
            for (var i = 0; i < count; i++) {
                try {
                    var k = keys.objectAtIndex_(i);
                    var v = o.objectForKey_(k);
                    out.push(toStringSafe(k) + "=" + toStringSafe(v));
                } catch (e) {}
            }
            if (keys.count().toInt32() > count) out.push("...(" + keys.count().toString() + " items)");
            return "{" + out.join(", ") + "}";
        } catch (e) {
            return "<dict-unreadable>";
        }
    }

    // Hook +[NSProcessInfo processInfo]
    try {
        var NSProcessInfo = ObjC.classes.NSProcessInfo;
        if (NSProcessInfo && NSProcessInfo["+ processInfo"]) {
            Interceptor.attach(NSProcessInfo["+ processInfo"].implementation, {
                onLeave: function (retval) {
                    try {
                        console.log("\n[+] Hook +[NSProcessInfo processInfo] returned ptr:", retval);
                        if (retval.isNull()) {
                            console.log("    -> <null>");
                            return;
                        }

                        var pi = new ObjC.Object(retval);
                        console.log("    -> NSProcessInfo object:", "<" + pi.$className + " " + retval + ">");

                        // processName
                        var pName = null;
                        try { pName = pi.processName ? pi.processName() : null; } catch(e){}
                        if (!pName) {
                            try { pName = pi.valueForKey_("processName"); } catch(e){}
                        }
                        console.log("      processName: ", toStringSafe(pName));

                        // processIdentifier (integer)
                        try {
                            var pid = null;
                            if (pi.respondsToSelector_("processIdentifier")) {
                                pid = pi.processIdentifier();
                                // pid might be a number wrapper; try conversions
                                if (typeof pid === "object" && pid.toInt32) {
                                    console.log("      processIdentifier: ", pid.toInt32());
                                } else {
                                    console.log("      processIdentifier: ", pid);
                                }
                            } else {
                                console.log("      processIdentifier: <not-available>");
                            }
                        } catch (e) {
                            // fallback: retval pointer? don't do that
                            console.log("      processIdentifier: <error reading pid>", e);
                        }

                        // globallyUniqueString
                        var gus = null;
                        try { gus = pi.globallyUniqueString ? pi.globallyUniqueString() : null; } catch(e){}
                        if (!gus) {
                            try { gus = pi.valueForKey_("globallyUniqueString"); } catch(e){}
                        }
                        console.log("      globallyUniqueString: ", toStringSafe(gus));

                        // hostName
                        var hname = null;
                        try { hname = pi.hostName ? pi.hostName() : null; } catch(e){}
                        console.log("      hostName: ", toStringSafe(hname));

                        // environment (NSDictionary) - print a few items
                        var env = null;
                        try { env = pi.environment ? pi.environment() : null; } catch(e){}
                        if (!env) {
                            try { env = pi.valueForKey_("environment"); } catch(e){}
                        }
                        console.log("      environment: ", dictToPairs(env, 12));

                        // operatingSystemVersion (struct) - attempt to call and read fields
                        var osv = null;
                        try {
                            if (pi.respondsToSelector_("operatingSystemVersion")) {
                                // try calling; may return an object-like wrapper or plain JS object
                                osv = pi.operatingSystemVersion ? pi.operatingSystemVersion() : null;
                                // If Frida returns a JS object with fields, print them
                                if (osv && (typeof osv === "object") && ("majorVersion" in osv || "major" in osv)) {
                                    var mj = osv.majorVersion || osv.major || 0;
                                    var mn = osv.minorVersion || osv.minor || 0;
                                    var pt = osv.patchVersion || osv.patch || 0;
                                    console.log("      operatingSystemVersion: " + mj + "." + mn + "." + pt);
                                } else {
                                    var osvStr = null;
                                    try {
                                        if (pi.respondsToSelector_("operatingSystemVersionString")) {
                                            osvStr = pi.operatingSystemVersionString();
                                        }
                                    } catch (e) { }
                                    console.log("      operatingSystemVersionString: " + (osvStr || "<nil>"));
                                }
                            } else {
                                console.log("      operatingSystemVersion: <not-supported>");
                            }
                        } catch (e) {
                            console.log("      operatingSystemVersion: <error>", e);
                        }

                        // Also attempt UIDevice.systemVersion via UIDevice.currentDevice
                        try {
                            var UIDevice = ObjC.classes.UIDevice;
                            if (UIDevice && UIDevice.currentDevice) {
                                var dev = UIDevice.currentDevice();
                                var sv = null;
                                try { sv = dev.systemVersion(); } catch(e){}
                                if (!sv) {
                                    try { sv = dev.valueForKey_("systemVersion"); } catch(e){}
                                }
                                console.log("      UIDevice.systemVersion: " + toStringSafe(sv));
                            }
                        } catch (e) {}

                    } catch (e) {
                        console.log("onLeave +processInfo error:", e);
                    }
                }
            });
            console.log("[*] Hooked +[NSProcessInfo processInfo]");
        } else {
            console.log("[-] +[NSProcessInfo processInfo] not found");
        }
    } catch (e) {
        console.log("hook +processInfo exception:", e);
    }

    // Also hook -processIdentifier to print clean integer values
    try {
        if (NSProcessInfo && NSProcessInfo["- processIdentifier"]) {
            Interceptor.attach(NSProcessInfo["- processIdentifier"].implementation, {
                onLeave: function (retval) {
                    try {
                        // pid_t typically fits 32-bit
                        var pid = null;
                        try { pid = retval.toInt32(); } catch(e){ pid = retval.toInt64(); }
                        console.log("[-] Hook -processIdentifier => PID:", pid);
                    } catch (e) {
                        console.log("onLeave -processIdentifier error:", e);
                    }
                }
            });
            console.log("[*] Hooked -[NSProcessInfo processIdentifier]");
        }
    } catch (e) {
        console.log("hook -processIdentifier error:", e);
    }

    // Also hook -globallyUniqueString to print the real string
    try {
        if (NSProcessInfo && NSProcessInfo["- globallyUniqueString"]) {
            Interceptor.attach(NSProcessInfo["- globallyUniqueString"].implementation, {
                onLeave: function (retval) {
                    try {
                        if (retval.isNull()) {
                            console.log("[-] Hook -globallyUniqueString => <null>");
                            return;
                        }
                        var s = new ObjC.Object(retval).toString();
                        console.log("[-] Hook -globallyUniqueString =>", s);
                    } catch (e) {
                        console.log("onLeave -globallyUniqueString error:", e);
                    }
                }
            });
            console.log("[*] Hooked -[NSProcessInfo globallyUniqueString]");
        }
    } catch (e) {
        console.log("hook -globallyUniqueString error:", e);
    }
}
