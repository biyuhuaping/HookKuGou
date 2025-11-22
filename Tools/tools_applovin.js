/**
 * AppLovin SDK Hook 工具
 * 基于 AppLovinSDK.h 分析的关键Hook点
 */

if (!ObjC.available) {
    console.log("❌ ObjC runtime not available");
    throw new Error("ObjC not available");
}

// ==================== 1. 网络层Hook ====================

/**
 * Hook ALConnectionManager 的网络请求
 * 可以拦截所有SDK的网络请求，包括广告请求、验证请求等
 */
function hookALConnectionManager() {
    try {
        var ALConnectionManager = ObjC.classes.ALConnectionManager;
        if (!ALConnectionManager) {
            console.log("[-] ALConnectionManager not found");
            return;
        }

        // Hook 主要的请求方法（需要根据实际方法名调整）
        var methods = [
            "- makeRequest:andNotify:",
            "- makeRequestWithBuilder:andNotify:",
            "- executeRequest:andNotify:"
        ];

        methods.forEach(function(methodName) {
            if (ALConnectionManager[methodName]) {
                Interceptor.attach(ALConnectionManager[methodName].implementation, {
                    onEnter: function(args) {
                        try {
                            var request = args[2] ? new ObjC.Object(args[2]) : null;
                            if (request) {
                                var url = request.endpoint ? request.endpoint().toString() : "<nil>";
                                var method = request.HTTPMethod ? request.HTTPMethod().toString() : "GET";
                                var body = request.body ? request.body().toString() : "<nil>";
                                var headers = request.HTTPHeaders ? request.HTTPHeaders().toString() : "<nil>";
                                
                                console.log("\n[ALConnectionManager] " + methodName);
                                console.log("  URL: " + url);
                                console.log("  Method: " + method);
                                console.log("  Headers: " + headers);
                                console.log("  Body: " + body);
                                
                                // 可以在这里修改请求参数
                                // 例如：修改URL、添加/修改headers、修改body等
                            }
                        } catch (e) {
                            console.log("[error] " + methodName + " onEnter: " + e);
                        }
                    },
                    onLeave: function(retval) {
                        // 可以在这里修改返回值
                    }
                });
                console.log("[+] Hooked: ALConnectionManager " + methodName);
            }
        });
    } catch (e) {
        console.log("[error] hookALConnectionManager: " + e);
    }
}

/**
 * Hook ALHTTPRequest 的构建和属性设置
 * 可以拦截和修改HTTP请求的构建过程
 */
function hookALHTTPRequest() {
    try {
        var ALHTTPRequest = ObjC.classes.ALHTTPRequest;
        if (!ALHTTPRequest) {
            console.log("[-] ALHTTPRequest not found");
            return;
        }

        // Hook body 设置
        if (ALHTTPRequest["- setBody:"]) {
            Interceptor.attach(ALHTTPRequest["- setBody:"].implementation, {
                onEnter: function(args) {
                    try {
                        var body = args[2] ? new ObjC.Object(args[2]).toString() : "<nil>";
                        console.log("\n[ALHTTPRequest] setBody:");
                        console.log("  Body: " + body);
                        // 可以在这里修改body
                    } catch (e) {
                        console.log("[error] setBody: " + e);
                    }
                }
            });
            console.log("[+] Hooked: ALHTTPRequest setBody:");
        }

        // Hook headers 设置
        if (ALHTTPRequest["- setHTTPHeaders:"]) {
            Interceptor.attach(ALHTTPRequest["- setHTTPHeaders:"].implementation, {
                onEnter: function(args) {
                    try {
                        var headers = args[2] ? new ObjC.Object(args[2]).toString() : "<nil>";
                        console.log("\n[ALHTTPRequest] setHTTPHeaders:");
                        console.log("  Headers: " + headers);
                        // 可以在这里修改headers
                    } catch (e) {
                        console.log("[error] setHTTPHeaders: " + e);
                    }
                }
            });
            console.log("[+] Hooked: ALHTTPRequest setHTTPHeaders:");
        }
    } catch (e) {
        console.log("[error] hookALHTTPRequest: " + e);
    }
}

// ==================== 2. 用户标识Hook ====================

/**
 * Hook ALUserTokenManager 的Token获取
 * 可以伪造用户标识和Token
 */
function hookALUserTokenManager() {
    try {
        var ALUserTokenManager = ObjC.classes.ALUserTokenManager;
        if (!ALUserTokenManager) {
            console.log("[-] ALUserTokenManager not found");
            return;
        }

        // Hook userIdentifier 获取
        if (ALUserTokenManager["- userIdentifier"]) {
            Interceptor.attach(ALUserTokenManager["- userIdentifier"].implementation, {
                onLeave: function(retval) {
                    try {
                        var original = retval ? new ObjC.Object(retval).toString() : "<nil>";
                        console.log("\n[ALUserTokenManager] userIdentifier: " + original);
                        
                        // 可以在这里伪造用户标识
                        // var fakeIdentifier = ObjC.classes.NSString.stringWithString_("fake_user_id");
                        // retval.replace(fakeIdentifier);
                    } catch (e) {
                        console.log("[error] userIdentifier: " + e);
                    }
                }
            });
            console.log("[+] Hooked: ALUserTokenManager userIdentifier");
        }

        // Hook compassRandomToken 获取
        if (ALUserTokenManager["- compassRandomToken"]) {
            Interceptor.attach(ALUserTokenManager["- compassRandomToken"].implementation, {
                onLeave: function(retval) {
                    try {
                        var original = retval ? new ObjC.Object(retval).toString() : "<nil>";
                        console.log("\n[ALUserTokenManager] compassRandomToken: " + original);
                    } catch (e) {
                        console.log("[error] compassRandomToken: " + e);
                    }
                }
            });
            console.log("[+] Hooked: ALUserTokenManager compassRandomToken");
        }

        // Hook retrieveUserIdentifier
        if (ALUserTokenManager["- retrieveUserIdentifier"]) {
            Interceptor.attach(ALUserTokenManager["- retrieveUserIdentifier"].implementation, {
                onLeave: function(retval) {
                    try {
                        var original = retval ? new ObjC.Object(retval).toString() : "<nil>";
                        console.log("\n[ALUserTokenManager] retrieveUserIdentifier: " + original);
                    } catch (e) {
                        console.log("[error] retrieveUserIdentifier: " + e);
                    }
                }
            });
            console.log("[+] Hooked: ALUserTokenManager retrieveUserIdentifier");
        }
    } catch (e) {
        console.log("[error] hookALUserTokenManager: " + e);
    }
}

// ==================== 3. 奖励验证Hook ====================

/**
 * Hook ALTaskValidateReward 的奖励验证
 * 可以绕过奖励验证或伪造验证结果
 */
function hookALTaskValidateReward() {
    try {
        var ALTaskValidateReward = ObjC.classes.ALTaskValidateReward;
        if (!ALTaskValidateReward) {
            console.log("[-] ALTaskValidateReward not found");
            return;
        }

        // Hook 验证请求的成功回调
        if (ALTaskValidateReward["- connectionManager:didSucceedForUrl:withCode:response:"]) {
            Interceptor.attach(ALTaskValidateReward["- connectionManager:didSucceedForUrl:withCode:response:"].implementation, {
                onEnter: function(args) {
                    try {
                        var url = args[3] ? new ObjC.Object(args[3]).toString() : "<nil>";
                        var code = args[4].toInt32();
                        var response = args[5] ? new ObjC.Object(args[5]).toString() : "<nil>";
                        
                        console.log("\n[ALTaskValidateReward] Validation Success");
                        console.log("  URL: " + url);
                        console.log("  Code: " + code);
                        console.log("  Response: " + response);
                        
                        // 可以在这里修改验证响应
                    } catch (e) {
                        console.log("[error] Validation Success: " + e);
                    }
                }
            });
            console.log("[+] Hooked: ALTaskValidateReward validation success");
        }

        // Hook 验证请求的失败回调
        if (ALTaskValidateReward["- connectionManager:didFailForUrl:withCode:response:error:"]) {
            Interceptor.attach(ALTaskValidateReward["- connectionManager:didFailForUrl:withCode:response:error:"].implementation, {
                onEnter: function(args) {
                    try {
                        var url = args[3] ? new ObjC.Object(args[3]).toString() : "<nil>";
                        var code = args[4].toInt32();
                        var error = args[6] ? new ObjC.Object(args[6]).toString() : "<nil>";
                        
                        console.log("\n[ALTaskValidateReward] Validation Failed");
                        console.log("  URL: " + url);
                        console.log("  Code: " + code);
                        console.log("  Error: " + error);
                    } catch (e) {
                        console.log("[error] Validation Failed: " + e);
                    }
                }
            });
            console.log("[+] Hooked: ALTaskValidateReward validation failed");
        }

        // Hook handlePendingReward
        if (ALTaskValidateReward["- handlePendingReward:"]) {
            Interceptor.attach(ALTaskValidateReward["- handlePendingReward:"].implementation, {
                onEnter: function(args) {
                    try {
                        var reward = args[2] ? new ObjC.Object(args[2]).toString() : "<nil>";
                        console.log("\n[ALTaskValidateReward] handlePendingReward: " + reward);
                    } catch (e) {
                        console.log("[error] handlePendingReward: " + e);
                    }
                }
            });
            console.log("[+] Hooked: ALTaskValidateReward handlePendingReward");
        }
    } catch (e) {
        console.log("[error] hookALTaskValidateReward: " + e);
    }
}

// ==================== 4. 广告服务Hook ====================

/**
 * Hook ALAdService 的广告加载和追踪
 * 可以拦截广告加载请求和追踪事件
 */
function hookALAdService() {
    try {
        var ALAdService = ObjC.classes.ALAdService;
        if (!ALAdService) {
            console.log("[-] ALAdService not found");
            return;
        }

        // Hook 加载广告
        if (ALAdService["- loadNextAd:andNotify:"]) {
            Interceptor.attach(ALAdService["- loadNextAd:andNotify:"].implementation, {
                onEnter: function(args) {
                    try {
                        var zone = args[2] ? new ObjC.Object(args[2]).toString() : "<nil>";
                        console.log("\n[ALAdService] loadNextAd: " + zone);
                    } catch (e) {
                        console.log("[error] loadNextAd: " + e);
                    }
                }
            });
            console.log("[+] Hooked: ALAdService loadNextAd");
        }

        // Hook 追踪展示
        if (ALAdService["- trackImpressionForAd:"]) {
            Interceptor.attach(ALAdService["- trackImpressionForAd:"].implementation, {
                onEnter: function(args) {
                    try {
                        var ad = args[2] ? new ObjC.Object(args[2]).toString() : "<nil>";
                        console.log("\n[ALAdService] trackImpressionForAd: " + ad);
                        // 可以在这里阻止追踪上报
                    } catch (e) {
                        console.log("[error] trackImpressionForAd: " + e);
                    }
                }
            });
            console.log("[+] Hooked: ALAdService trackImpressionForAd");
        }

        // Hook 追踪点击
        if (ALAdService["- trackClickForAd:inAdView:forClickLocation:"]) {
            Interceptor.attach(ALAdService["- trackClickForAd:inAdView:forClickLocation:"].implementation, {
                onEnter: function(args) {
                    try {
                        var ad = args[2] ? new ObjC.Object(args[2]).toString() : "<nil>";
                        console.log("\n[ALAdService] trackClickForAd: " + ad);
                        // 可以在这里阻止追踪上报
                    } catch (e) {
                        console.log("[error] trackClickForAd: " + e);
                    }
                }
            });
            console.log("[+] Hooked: ALAdService trackClickForAd");
        }

        // Hook 收集竞价Token
        if (ALAdService["- collectBidTokenWithCompletion:"]) {
            Interceptor.attach(ALAdService["- collectBidTokenWithCompletion:"].implementation, {
                onEnter: function(args) {
                    try {
                        console.log("\n[ALAdService] collectBidTokenWithCompletion");
                    } catch (e) {
                        console.log("[error] collectBidTokenWithCompletion: " + e);
                    }
                }
            });
            console.log("[+] Hooked: ALAdService collectBidTokenWithCompletion");
        }
    } catch (e) {
        console.log("[error] hookALAdService: " + e);
    }
}

// ==================== 5. 隐私设置Hook ====================

/**
 * Hook ALPrivacySettings 的隐私设置
 * 可以绕过隐私合规检查
 */
function hookALPrivacySettings() {
    try {
        var ALPrivacySettings = ObjC.classes.ALPrivacySettings;
        if (!ALPrivacySettings) {
            console.log("[-] ALPrivacySettings not found");
            return;
        }

        // Hook hasUserConsent
        if (ALPrivacySettings["+ hasUserConsent"]) {
            Interceptor.attach(ALPrivacySettings["+ hasUserConsent"].implementation, {
                onLeave: function(retval) {
                    try {
                        var original = retval.toInt32() !== 0;
                        console.log("\n[ALPrivacySettings] hasUserConsent: " + original);
                        // 可以强制返回true
                        // retval.replace(ptr("0x1"));
                    } catch (e) {
                        console.log("[error] hasUserConsent: " + e);
                    }
                }
            });
            console.log("[+] Hooked: ALPrivacySettings hasUserConsent");
        }

        // Hook isDoNotSell
        if (ALPrivacySettings["+ isDoNotSell"]) {
            Interceptor.attach(ALPrivacySettings["+ isDoNotSell"].implementation, {
                onLeave: function(retval) {
                    try {
                        var original = retval.toInt32() !== 0;
                        console.log("\n[ALPrivacySettings] isDoNotSell: " + original);
                        // 可以强制返回false
                        // retval.replace(ptr("0x0"));
                    } catch (e) {
                        console.log("[error] isDoNotSell: " + e);
                    }
                }
            });
            console.log("[+] Hooked: ALPrivacySettings isDoNotSell");
        }
    } catch (e) {
        console.log("[error] hookALPrivacySettings: " + e);
    }
}

// ==================== 6. Postback回调Hook ====================

/**
 * Hook ALPostbackService 的回调发送
 * 可以拦截和修改回调请求
 */
function hookALPostbackService() {
    try {
        var ALPostbackService = ObjC.classes.ALPostbackService;
        if (!ALPostbackService) {
            console.log("[-] ALPostbackService not found");
            return;
        }

        // Hook 异步发送回调
        if (ALPostbackService["- dispatchPostbackAsync:andNotify:"]) {
            Interceptor.attach(ALPostbackService["- dispatchPostbackAsync:andNotify:"].implementation, {
                onEnter: function(args) {
                    try {
                        var postback = args[2] ? new ObjC.Object(args[2]).toString() : "<nil>";
                        console.log("\n[ALPostbackService] dispatchPostbackAsync: " + postback);
                        // 可以在这里修改或阻止回调
                    } catch (e) {
                        console.log("[error] dispatchPostbackAsync: " + e);
                    }
                }
            });
            console.log("[+] Hooked: ALPostbackService dispatchPostbackAsync");
        }
    } catch (e) {
        console.log("[error] hookALPostbackService: " + e);
    }
}

// ==================== 7. 测试模式Hook ====================

/**
 * Hook ALTestModeService 的测试模式检测
 * 可以绕过测试模式限制
 */
function hookALTestModeService() {
    try {
        var ALTestModeService = ObjC.classes.ALTestModeService;
        if (!ALTestModeService) {
            console.log("[-] ALTestModeService not found");
            return;
        }

        // Hook isEnabled
        if (ALTestModeService["- isEnabled"]) {
            Interceptor.attach(ALTestModeService["- isEnabled"].implementation, {
                onLeave: function(retval) {
                    try {
                        var original = retval.toInt32() !== 0;
                        console.log("\n[ALTestModeService] isEnabled: " + original);
                        // 可以强制返回false以绕过测试模式
                        // retval.replace(ptr("0x0"));
                    } catch (e) {
                        console.log("[error] isEnabled: " + e);
                    }
                }
            });
            console.log("[+] Hooked: ALTestModeService isEnabled");
        }
    } catch (e) {
        console.log("[error] hookALTestModeService: " + e);
    }
}

// ==================== 主函数 ====================

function main() {
    console.log("\n[+] Starting AppLovin SDK Hooks...\n");

    // 等待类加载
    setTimeout(function() {
        hookALConnectionManager();
        hookALHTTPRequest();
        hookALUserTokenManager();
        hookALTaskValidateReward();
        hookALAdService();
        hookALPrivacySettings();
        hookALPostbackService();
        hookALTestModeService();
        
        console.log("\n[+] All hooks installed!\n");
    }, 1000);
}

// 执行
main();

