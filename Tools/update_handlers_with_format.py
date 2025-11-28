#!/usr/bin/env python3
"""
批量更新所有 handler 文件，添加 formatObjCObject 工具函数
"""

import os
import re
from pathlib import Path

# 工具函数代码（从 format_objc.js 提取）
FORMAT_FUNCTION = '''// 根据类型格式化输出 Objective-C 对象
function formatObjCObject(objcObj) {
  if (!objcObj || objcObj.isNull()) {
    return 'nil';
  }
  
  const className = objcObj.$className;
  let output = '';
  
  try {
    // NSString 类型
    if (className === 'NSString' || className === '__NSCFString' || className === '__NSCFConstantString' || className === 'NSMutableString') {
      output = objcObj.toString();
    }
    // NSData 类型
    else if (className === 'NSData' || className === '__NSCFData' || className === 'NSMutableData') {
      const dataLength = objcObj.length();
      const dataBytes = objcObj.bytes();
      
      // 尝试 UTF-8 字符串
      try {
        const utf8String = Memory.readUtf8(dataBytes, Math.min(dataLength, 256));
        const isPrintable = /^[\\x20-\\x7E\\s]*$/.test(utf8String);
        if (isPrintable && utf8String.length > 0 && dataLength <= 256) {
          output = `UTF-8: ${utf8String}`;
        } else {
          // 显示十六进制
          const hexString = Memory.readByteArray(dataBytes, Math.min(dataLength, 64))
            .map(b => ('0' + (b & 0xFF).toString(16)).slice(-2))
            .join(' ');
          output = dataLength <= 64 ? `Hex: ${hexString}` : `Hex (first 64 bytes): ${hexString}... (total: ${dataLength})`;
        }
      } catch (e) {
        // UTF-8 失败，显示十六进制
        const hexString = Memory.readByteArray(dataBytes, Math.min(dataLength, 64))
          .map(b => ('0' + (b & 0xFF).toString(16)).slice(-2))
          .join(' ');
        output = dataLength <= 64 ? `Hex: ${hexString}` : `Hex (first 64 bytes): ${hexString}... (total: ${dataLength})`;
      }
    }
    // NSNumber 类型
    else if (className === 'NSNumber' || className === '__NSCFNumber') {
      output = objcObj.toString();
    }
    // NSDictionary 类型
    else if (className === 'NSDictionary' || className === '__NSCFDictionary' || className === 'NSMutableDictionary') {
      output = objcObj.toString();
    }
    // NSArray 类型
    else if (className === 'NSArray' || className === '__NSCFArray' || className === 'NSMutableArray') {
      const count = objcObj.count();
      output = `Array[${count}]: ${objcObj.toString()}`;
    }
    // Block 类型
    else if (className === '__NSStackBlock__' || className === '__NSMallocBlock__' || className === '__NSGlobalBlock__') {
      output = objcObj.toString();
    }
    // 其他类型，使用 toString()
    else {
      output = objcObj.toString();
    }
  } catch (e) {
    output = `[Error: ${e}] ${objcObj.toString()}`;
  }
  
  return `${output} (${className})`;
}

'''


def update_handler_file(file_path):
    """更新单个 handler 文件"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 检查是否已经包含 formatObjCObject 函数
        if 'function formatObjCObject' in content:
            print(f"  ⏭️  已包含 formatObjCObject: {file_path}")
            return False
        
        # 查找 defineHandler 的位置
        define_handler_match = re.search(r'(defineHandler\s*\{)', content)
        if not define_handler_match:
            print(f"  ⚠️  未找到 defineHandler: {file_path}")
            return False
        
        # 在 defineHandler 之前插入函数定义
        insert_pos = define_handler_match.start()
        
        # 检查注释结束位置
        comment_end = content.rfind('*/', 0, insert_pos)
        if comment_end != -1:
            insert_pos = comment_end + 2  # 在 */ 之后插入
            # 确保有换行
            if content[insert_pos:insert_pos+1] != '\n':
                FORMAT_FUNCTION = '\n' + FORMAT_FUNCTION
        else:
            # 如果没有注释，在 defineHandler 之前插入
            pass
        
        new_content = content[:insert_pos] + '\n' + FORMAT_FUNCTION + content[insert_pos:]
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        print(f"  ✅ 已更新: {file_path}")
        return True
    except Exception as e:
        print(f"  ❌ 错误: {file_path} - {e}")
        return False


def main():
    """主函数"""
    handlers_dir = Path(__file__).parent.parent / '__handlers__'
    
    if not handlers_dir.exists():
        print(f"❌ 未找到 __handlers__ 目录: {handlers_dir}")
        return
    
    print(f"📁 扫描目录: {handlers_dir}")
    
    updated_count = 0
    skipped_count = 0
    error_count = 0
    
    # 递归查找所有 .js 文件
    for js_file in handlers_dir.rglob('*.js'):
        if update_handler_file(js_file):
            updated_count += 1
        else:
            if 'formatObjCObject' in open(js_file, 'r', encoding='utf-8').read():
                skipped_count += 1
            else:
                error_count += 1
    
    print(f"\n📊 统计:")
    print(f"  ✅ 已更新: {updated_count}")
    print(f"  ⏭️  已跳过: {skipped_count}")
    print(f"  ❌ 错误: {error_count}")


if __name__ == '__main__':
    main()

