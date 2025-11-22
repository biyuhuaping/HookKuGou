# 绕过防 Frida 注入的方法

## 当前方案：使用 Tweak（推荐）

你的项目主要使用 **Tweak（dylib 注入）**，这比 Frida 更隐蔽：

### 优势：
1. ✅ **更隐蔽**：Tweak 是静态注入，不会留下 Frida 的痕迹
2. ✅ **性能更好**：直接 hook，没有 Frida 的中间层
3. ✅ **更难检测**：应用通常检测 Frida，而不是检测 dylib 注入

### 已实现的反检测：
- Hook `_dyld_image_count` 和 `_dyld_get_image_name`（隐藏 dylib 列表）
- Hook `dlopen`（隐藏动态库加载）
- Hook `sysctl`（隐藏进程信息）

## 如果必须使用 Frida

### 1. 修改 Frida Server 名称和端口

```bash
# 重命名 frida-server
mv /data/local/tmp/frida-server /data/local/tmp/fs

# 使用自定义端口
frida -H 192.168.1.100:9999 -f com.example.app -l script.js
```

### 2. 使用 Frida Gadget（静态注入）

将 `frida-gadget.dylib` 注入到应用中，而不是使用 frida-server：

```bash
# 1. 下载 frida-gadget
# 2. 重命名为普通库名，如 libhelper.dylib
# 3. 通过 Tweak 注入
```

### 3. Hook 检测函数

在 Tweak 中已经添加了以下 hook：

```objc
// Hook dyld 函数
hook_dyld_image_count()
hook_dyld_get_image_name()

// Hook 系统调用
hook_dlopen()
hook_sysctl()
```

### 4. 常见检测点及绕过

#### 检测 frida-server 进程
```objc
// 应用可能通过 sysctl 或进程列表检测
// 已在 Tweak 中 hook sysctl
```

#### 检测端口 27042
```bash
# 使用自定义端口
frida -H 192.168.1.100:9999 ...
```

#### 检测 /proc/self/maps 中的 frida 字符串
```objc
// iOS 不适用，这是 Android 的检测方法
```

#### 检测环境变量
```objc
// 应用可能检查环境变量
// 可以在 hook 中清除相关环境变量
```

#### 检测 dylib 注入
```objc
// 已在 Tweak 中 hook _dyld_get_image_name
// 可以返回 NULL 来隐藏我们的 dylib
```

## 建议

1. **优先使用 Tweak**：你的项目已经用 Tweak 实现了大部分功能
2. **只在必要时使用 Frida**：用于动态分析和调试
3. **使用自定义端口**：避免使用默认端口 27042
4. **重命名 frida-server**：避免进程名检测
5. **延迟 hook**：在应用启动后再 hook，避免早期检测

## 测试是否被检测

1. 运行应用，查看是否有崩溃或退出
2. 检查日志，看是否有检测相关的输出
3. 如果应用正常启动，说明反检测生效

## 如果仍然被检测

1. 检查应用的具体检测方法（通过逆向分析）
2. 在 Tweak 中添加对应的 hook
3. 考虑使用更底层的 hook（如 Substrate 或直接修改二进制）

