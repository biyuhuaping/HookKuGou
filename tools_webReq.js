/*
捕获 evaluateJavaScript / loadRequest / addUserScript / postMessage / NSURLSession
运行：frida -U -f com.kugou.kugou1002 -l tools_webReq.js
*/ 
if (!ObjC.available) {
    console.log("ObjC runtime not available");
} else {
    try {
        // 1. 捕获 native -> page 的 JS 执行（evaluateJavaScript:completionHandler:）
        (function hookEvaluate() {
            var WKWebView = ObjC.classes.WKWebView;
            if (WKWebView && WKWebView['- evaluateJavaScript:completionHandler:']) {
                Interceptor.attach(WKWebView['- evaluateJavaScript:completionHandler:'].implementation, {
                    onEnter: function (args) {
                        try {
                            var js = ObjC.Object(args[2]).toString();
                            console.log("[WKWebView evaluateJavaScript] =>\n", js);
                            // 可选：把 JS 发回 host
                            send({evt: "evaluateJS", js: js});
                        } catch (e) {}
                    }
                });
            }
        })();

        // 2. 捕获页面加载 URL / loadHTMLString
        (function hookLoad() {
            var WKWebView = ObjC.classes.WKWebView;
            if (WKWebView && WKWebView['- loadRequest:']) {
                Interceptor.attach(WKWebView['- loadRequest:'].implementation, {
                    onEnter: function (args) {
                        try {
                            var req = new ObjC.Object(args[2]);
                            var url = req.URL() ? req.URL().absoluteString().toString() : "<nil>";
                            console.log("[WKWebView loadRequest] URL =", url);
                            send({evt: "loadRequest", url: url});
                        } catch (e) {}
                    }
                });
            }
            if (WKWebView && WKWebView['- loadHTMLString:baseURL:']) {
                Interceptor.attach(WKWebView['- loadHTMLString:baseURL:'].implementation, {
                    onEnter: function (args) {
                        try {
                            var html = ObjC.Object(args[2]).toString();
                            console.log("[WKWebView loadHTMLString] length =", html.length);
                            send({evt: "loadHTMLString", len: html.length});
                        } catch (e) {}
                    }
                });
            }
        })();

        // 3. 捕获 WKUserContentController 的 addUserScript/addScriptMessageHandler（谁注入了脚本或注册了 handler）
        (function hookUserContentController() {
            var WKUserContentController = ObjC.classes.WKUserContentController;
            if (WKUserContentController) {
                if (WKUserContentController['- addUserScript:']) {
                    Interceptor.attach(WKUserContentController['- addUserScript:'].implementation, {
                        onEnter: function (args) {
                            try {
                                var script = new ObjC.Object(args[2]); // WKUserScript
                                var src = script.javascriptSource ? script.javascriptSource().toString() : "<no source>";
                                console.log("[WKUserScript added] length=", src ? src.length : 0);
                                send({evt: "addUserScript", srcLen: src ? src.length : 0, src: src});
                            } catch (e) {}
                        }
                    });
                }
                if (WKUserContentController['- addScriptMessageHandler:name:']) {
                    Interceptor.attach(WKUserContentController['- addScriptMessageHandler:name:'].implementation, {
                        onEnter: function (args) {
                            try {
                                var name = ObjC.Object(args[3]).toString();
                                var handler = new ObjC.Object(args[2]);
                                console.log("[addScriptMessageHandler] name=", name, " handlerClass=", handler.$className);
                                send({evt: "addScriptMessageHandler", name: name, handlerClass: handler.$className});
                            } catch (e) {}
                        }
                    });
                }
            }
        })();

        // 4. 捕获 JS -> native: userContentController:didReceiveScriptMessage:
        (function hookScriptMessageHandler() {
            // hook NSObject implementation of selector to capture app handlers
            var selName = "- userContentController:didReceiveScriptMessage:";
            try {
                var classes = ObjC.enumerateLoadedClassesSync();
                classes.forEach(function (className) {
                    try {
                        var cls = ObjC.classes[className];
                        if (!cls) return;
                        if (cls[selName]) {
                            Interceptor.attach(cls[selName].implementation, {
                                onEnter: function (args) {
                                    try {
                                        var handler = ObjC.Object(args[0]);
                                        var controller = ObjC.Object(args[2]);
                                        var message = ObjC.Object(args[3]);
                                        var name = message.name ? message.name().toString() : "<noname>";
                                        var body = "<non-string>";
                                        try { body = message.body() ? message.body().toString() : "<nil>"; } catch (e) {}
                                        console.log("[WKScriptMessage] handler=" + handler.$className + " name=" + name + " body=", body);
                                        send({evt: "scriptMessage", handler: handler.$className, name: name, body: body});
                                    } catch (e) {}
                                }
                            });
                        }
                    } catch (e) {}
                });
            } catch (e) {}
        })();

        // 5. 捕获 WebView 发起的网络请求（NSURLSession dataTaskWithRequest:completionHandler:）
        (function hookNSURLSession() {
            try {
                var NSURLSession = ObjC.classes.NSURLSession;
                if (NSURLSession && NSURLSession['- dataTaskWithRequest:completionHandler:']) {
                    Interceptor.attach(NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
                        onEnter: function (args) {
                            try {
                                var req = new ObjC.Object(args[2]);
                                var url = req.URL() ? req.URL().absoluteString().toString() : "<nil>";
                                var method = req.HTTPMethod ? req.HTTPMethod().toString() : "GET";
                                var headers = req.allHTTPHeaderFields ? req.allHTTPHeaderFields().toString() : "{}";
                                var body = "<nil>";
                                try {
                                    if (req.HTTPBody()) {
                                        body = ObjC.Object(req.HTTPBody()).toString();
                                    } else if (req.HTTPBodyStream()) {
                                        body = "<HTTPBodyStream>";
                                    }
                                } catch (e) {}
                                console.log("[NSURLSession] " + method + " " + url + "\nheaders=" + headers + "\nbody=" + (body || "<nil>"));
                                // 打印调用栈
                                var backtrace = Thread.backtrace(this.context, Backtracer.FUZZY)
                                    .map(DebugSymbol.fromAddress)
                                    .join("\n");
                                    console.log("[*] Call stack:\n" + backtrace);
                                send({evt: "nsurlsession", method: method, url: url, headers: headers, body: body});
                            } catch (e) {}
                        }
                    });
                }
            } catch (e) {}
        })();

        // 6. 辅助：当找不到 webcontent 里 fetch/XHR 时，通过拦截 addUserScript 把注入脚本内容 dump 出来（上面已 hook）
        // 7. 提示
        console.log("[wk_capture] hooks installed");
    } catch (err) {
        console.log("error installing hooks: " + err);
    }
}
