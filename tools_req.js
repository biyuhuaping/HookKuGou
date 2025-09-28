/*
 查看 请求头内容
 运行：frida -U -f com.kugou.kugou1002 -l tools_req.js
 frida -U -f kugou -l tools_req.js
*/


// hook_set_header_fixed.js
if (!ObjC.available) {
    console.log("Objective-C runtime is not available!");
} else {
    try {
        var NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;
        var sel = "- setValue:forHTTPHeaderField:";
        if (NSMutableURLRequest && NSMutableURLRequest[sel]) {
            Interceptor.attach(NSMutableURLRequest[sel].implementation, {
                onEnter: function (args) {
                    try {
                        var selfObj = new ObjC.Object(args[0]);
                        var val = args[2] ? ObjC.Object(args[2]).toString() : "<nil>";
                        var key = args[3] ? ObjC.Object(args[3]).toString() : "<nil>";

                        // 只关注感兴趣的 header key，减少噪音
                        if (key && (key.indexOf("Device-Model") >= 0 || key.indexOf("Os-Version") >= 0 || key.indexOf("Version") >= 0 || key.indexOf("Device-Brand") >= 0)) {
                            console.log("\n[setHeader] " + key + " = " + val);
                            console.log("[setHeader] self class:", selfObj.$className);

                            // 打印调用栈（可读）
                            try {
                                var bt = Thread.backtrace(this.context, Backtracer.FUZZY)
                                    .map(DebugSymbol.fromAddress)
                                    .join("\n");
                                console.log("Backtrace:\n" + bt);
                            } catch (e) {
                                console.log("Backtrace error:", e);
                            }
                        }
                    } catch (e) {
                        // 防止单次异常中断 hook
                        console.log("onEnter error:", e);
                    }
                }
            });
            console.log("[*] Hook installed: NSMutableURLRequest setValue:forHTTPHeaderField:");
        } else {
            console.log("[-] NSMutableURLRequest or selector not found");
        }
    } catch (err) {
        console.log("hook error:", err);
    }
}


// hook_device_model.js
// if (!ObjC.available) {
//     console.log("Objective-C runtime is not available!");
// } else {
//     try {
//         var TARGET_NAME = "DeviceModel"; // 主匹配词（也会检测小写开头 deviceModel）
//         var foundCount = 0;

//         function safeToString(obj) {
//             try {
//                 if (!obj) return "<nil>";
//                 // 如果是 primitive pointer that can be wrapped as ObjC.Object 会抛异常
//                 var o = ObjC.Object(obj);
//                 return o.toString();
//             } catch (e) {
//                 try {
//                     // fallback: try reading as native pointer / int
//                     return obj.toString();
//                 } catch (e2) {
//                     return "<unprintable>";
//                 }
//             }
//         }

//         function printBacktrace(context) {
//             try {
//                 var bt = Thread.backtrace(context, Backtracer.FUZZY)
//                     .map(DebugSymbol.fromAddress)
//                     .join("\n");
//                 console.log(bt);
//             } catch (e) {
//                 console.log("  <backtrace error>", e);
//             }
//         }

//         ObjC.enumerateLoadedClasses({
//             onMatch: function(className) {
//                 try {
//                     var cls = ObjC.classes[className];
//                     if (!cls) return;

//                     // $ownMethods 包含类的所有 + / - 方法字符串，如 "- foo:" 或 "+ bar"
//                     var methodList = [];
//                     if (cls.$ownMethods && cls.$ownMethods.length) {
//                         methodList = cls.$ownMethods;
//                     } else if (cls.$methods && cls.$methods.length) {
//                         // 有的 Frida 版本可能使用 $methods
//                         methodList = cls.$methods;
//                     } else {
//                         return;
//                     }

//                     methodList.forEach(function(mstr) {
//                         try {
//                             // mstr 形如 "- deviceModel" 或 "+ DeviceModel:" 等
//                             if (!mstr) return;
//                             // 标准化空格并拆分
//                             var s = mstr.trim();
//                             // 取出符号（+ 或 -）和 selector
//                             var kind = s.charAt(0); // '+' 或 '-'
//                             var sel = s.slice(1).trim(); // selector （可能带冒号）
//                             if (!sel) return;

//                             // 匹配规则：包含 TARGET_NAME（忽略大小写）
//                             if (sel.toLowerCase().indexOf(TARGET_NAME.toLowerCase()) === -1) return;

//                             // 找到后准备 hook
//                             foundCount++;

//                             // 获取实现地址：实例方法在类对象上，类方法在 metaclass (cls.class) 上
//                             var impl = null;
//                             if (kind === '-') {
//                                 // instance method
//                                 if (cls[sel]) {
//                                     impl = cls[sel].implementation;
//                                 } else {
//                                     // 备用尝试：通过 methodForSelector
//                                     try { impl = ObjC.classes[className].instanceMethodForSelector_(sel); } catch(e){}
//                                 }
//                             } else if (kind === '+') {
//                                 // class method -> 在 metaclass 上
//                                 try {
//                                     var meta = cls.class; // metaclass
//                                     if (meta && meta[sel]) {
//                                         impl = meta[sel].implementation;
//                                     } else {
//                                         // 备用尝试：直接从 cls[sel]（某些 frida 版本可能映射）
//                                         if (cls[sel]) impl = cls[sel].implementation;
//                                     }
//                                 } catch (e) {
//                                     // ignore
//                                 }
//                             }

//                             if (!impl) {
//                                 console.log("[WARN] Could not find implementation for " + mstr + " in " + className);
//                                 return;
//                             }

//                             // attach
//                             try {
//                                 Interceptor.attach(impl, {
//                                     onEnter: function(args) {
//                                         // args[0] = id self, args[1] = SEL, args[2...] = params
//                                         try {
//                                             var isClassMethod = (kind === '+');
//                                             var selfObjStr = "<unavailable>";
//                                             try {
//                                                 selfObjStr = ObjC.Object(args[0]).$className + " instance";
//                                             } catch (e) {
//                                                 try {
//                                                     selfObjStr = args[0].toString();
//                                                 } catch(e2) { selfObjStr = "<self unreadable>"; }
//                                             }

//                                             console.log("\n==== DeviceModel HOOK ====");
//                                             console.log((isClassMethod ? "[+] " : "[-] ") + className + " -> " + sel);
//                                             console.log("self:", selfObjStr);
//                                             // print selector from args[1]
//                                             try {
//                                                 var selFromArg = new ObjC.Selector(args[1]).toString();
//                                                 console.log("selector:", selFromArg);
//                                             } catch (e) {}

//                                             // print up to first 6 arguments for safety
//                                             for (var i = 2; i < 8; i++) {
//                                                 try {
//                                                     if (!args[i]) break;
//                                                     var aStr = safeToString(args[i]);
//                                                     console.log("arg[" + (i-2) + "]:", aStr);
//                                                 } catch (e) {
//                                                     console.log("arg[" + (i-2) + "]: <err>", e);
//                                                 }
//                                             }

//                                             // print backtrace
//                                             console.log("Backtrace:");
//                                             printBacktrace(this.context);

//                                             // 保存一个标识以在 onLeave 中使用（如果需要）
//                                             this._hook_meta = {
//                                                 className: className,
//                                                 sel: sel,
//                                                 kind: kind
//                                             };
//                                         } catch (e) {
//                                             console.log("onEnter exception:", e);
//                                         }
//                                     },
//                                     onLeave: function(retval) {
//                                         try {
//                                             // 尝试把返回值打印为 ObjC 对象（若可）
//                                             var meta = this._hook_meta || {};
//                                             try {
//                                                 if (retval && !retval.isNull && retval.toString) {
//                                                     // 有时直接用 ObjC.Object(retval) 会抛异常，先尝试包装
//                                                     var rvStr;
//                                                     try {
//                                                         rvStr = ObjC.Object(retval).toString();
//                                                         console.log("Return (ObjC):", rvStr);
//                                                     } catch (e) {
//                                                         // fallback to pointer string
//                                                         try { console.log("Return (ptr):", retval.toString()); } catch(e2){}
//                                                     }
//                                                 } else {
//                                                     // primitive or null
//                                                     try { console.log("Return (raw):", retval); } catch(e){}
//                                                 }
//                                             } catch (e) {
//                                                 console.log("onLeave: print retval error:", e);
//                                             }
//                                             console.log("==== end ====\n");
//                                         } catch (e) {
//                                             console.log("onLeave exception:", e);
//                                         }
//                                     }
//                                 });
//                                 console.log("[HOOKED] " + mstr + " in class " + className);
//                             } catch (e) {
//                                 console.log("[ERROR attach] " + mstr + " in " + className + " ->", e);
//                             }
//                         } catch (e) {
//                             // method loop individual error
//                         }
//                     });
//                 } catch (e) {
//                     // per-class error
//                 }
//             },
//             onComplete: function() {
//                 console.log("== DeviceModel hook scan complete. Total candidates hooked: " + foundCount + " ==");
//             }
//         });

//     } catch (err) {
//         console.log("Script load error:", err);
//     }
// }

if (!ObjC.available) {
    console.log("Objective-C runtime is not available!");
} else {
    try {
        // 需要 hook 的类和方法列表
        var hooks = [
            {cls: "NeeSystemInfo", sel: "+deviceModel"},
            {cls: "UIDevice", sel: "+deviceModel"},
            {cls: "UIDevice", sel: "-deviceModel"},
            {cls: "UIDevice", sel: "+udidWithWifiMacAddressAndDeviceModelMD5"},
            {cls: "XHSSDKUtils", sel: "+deviceModel"},
            {cls: "FAFXDeviceInfo", sel: "+deviceModel"},
            {cls: "StatisticInfo", sel: "-setDeviceModelToCahce"},
            {cls: "StatisticInfo", sel: "-deviceModelName"},

        ];

        hooks.forEach(function(item) {
            var cls = ObjC.classes[item.cls];
            if (!cls) {
                console.log("[-] Class not found:", item.cls);
                return;
            }

            var sel = item.sel;
            var isClassMethod = sel.charAt(0) === "+"; // 用于日志显示
            var selName = sel.slice(1); // 去掉 + 或 -

            // 获取实现
            var impl = null;
            if (isClassMethod) {
                var meta = cls.class; // 元类
                if (meta && meta[selName]) impl = meta[selName].implementation;
            } else {
                if (cls[selName]) impl = cls[selName].implementation;
            }

            if (!impl) {
                console.log("[-] Implementation not found for", sel, "in", item.cls);
                return;
            }

            Interceptor.attach(impl, {
                onEnter: function(args) {
                    this.startTime = Date.now();
                },
                onLeave: function(retval) {
                    try {
                        // 尝试转换返回值为 ObjC 对象
                        var retStr = "<non-ObjC>";
                        if (retval && !retval.isNull) {
                            try {
                                var retObj = new ObjC.Object(retval);
                                retStr = retObj.toString();
                            } catch (e) {
                                retStr = retval.toString();
                            }
                        } else {
                            retStr = "<null>";
                        }
                        console.log("[HOOK] " + sel + " returned:", retStr);
                    } catch (e) {
                        console.log("[HOOK] error printing return value:", e);
                    }
                }
            });
            console.log("[*] Hook installed:", sel, "in", item.cls);
        });
    } catch (err) {
        console.log("hook script error:", err);
    }
}


// hook_uid_dev.js
// if (ObjC.available) {
//     var UIDevice = ObjC.classes.UIDevice;
//     if (UIDevice) {
//         var selName = "- model";
//         if (UIDevice[selName]) {
//             Interceptor.attach(UIDevice[selName].implementation, {
//                 onEnter: function (args) {
//                     // nothing
//                 },
//                 onLeave: function (ret) {
//                     try {
//                         var s = new ObjC.Object(ret).toString();
//                         console.log("[UIDevice model] ->", s);
//                         console.log("Backtrace:\n" + Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join("\n"));
//                     } catch (e) {}
//                 }
//             });
//             console.log("[*] hooked UIDevice model");
//         }
//         if (UIDevice["- name"]) {
//             Interceptor.attach(UIDevice["- name"].implementation, {
//                 onLeave: function (ret) {
//                     try {
//                         console.log("[UIDevice name] ->", new ObjC.Object(ret).toString());
//                     } catch (e) {}
//                 }
//             });
//         }
//     }
// }