/*
 查看 WKWebView加载的js页面内容
 运行：frida -U -f com.kugou.kugou1002 -l tools_web.js
*/

if (ObjC.available) {
    try {
        var WKWebView = ObjC.classes.WKWebView;
        if (WKWebView && WKWebView['- loadRequest:']) {
            Interceptor.attach(WKWebView['- loadRequest:'].implementation, {
                onEnter: function (args) {
                    try {
                        var req = new ObjC.Object(args[2]);
                        console.log("[WKWebView] loadRequest URL: " + req.URL().absoluteString());
                    } catch (e) {}
                }
            });
        }
        if (WKWebView && WKWebView['- loadHTMLString:baseURL:']) {
            Interceptor.attach(WKWebView['- loadHTMLString:baseURL:'].implementation, {
                onEnter: function (args) {
                    try {
                        var html = ObjC.Object(args[2]).toString();
                        console.log("[WKWebView] loadHTMLString length: " + html.length);
                    } catch (e) {}
                }
            });
        }
    } catch (e) {}
}

// evaluateJavaScript: 是 native 向页面注入/执行 JS 的入口，下面能打印出 native 要执行的 JS 字符串。
if (ObjC.available) {
    try {
        var WKWebView = ObjC.classes.WKWebView;
        if (WKWebView && WKWebView['- evaluateJavaScript:completionHandler:']) {
            Interceptor.attach(WKWebView['- evaluateJavaScript:completionHandler:'].implementation, {
                onEnter: function (args) {
                    try {
                        var js = ObjC.Object(args[2]).toString();
                        console.log("[WKWebView] evaluateJavaScript => " + js);
                    } catch (e) {}
                },
                onLeave: function (retval) { /* nothing */ }
            });
        }
    } catch (e) {}
}

