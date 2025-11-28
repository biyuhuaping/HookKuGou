#!/bin/bash
#
# frida-trace 包装脚本，自动加载 formatObjCObject 工具
# 使用方法：./Tools/frida-trace-with-format.sh -U -f com.kugou.kugou1002 -m "*[Qmeiegtm qmei_*]"
#

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FORMAT_TOOL="$PROJECT_ROOT/Tools/format_objc.js"

# 检查工具文件是否存在
if [ ! -f "$FORMAT_TOOL" ]; then
    echo "❌ 错误: 未找到 format_objc.js: $FORMAT_TOOL"
    exit 1
fi

# 构建 frida-trace 命令，自动添加 -I 参数
# 如果参数中已经包含 -I，则不重复添加
if [[ "$*" == *"-I"* ]]; then
    # 用户已经指定了 -I，直接执行
    frida-trace "$@"
else
    # 自动添加 -I 参数
    frida-trace -I "$FORMAT_TOOL" "$@"
fi

