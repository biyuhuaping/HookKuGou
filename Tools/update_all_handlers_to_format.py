#!/usr/bin/env python3
"""
批量更新所有 handler 文件，统一使用 formatObjCObject 输出日志
"""

import os
import re
from pathlib import Path

def fix_objc_object_creation(content):
    """修复 ObjC.Object 为 new ObjC.Object"""
    # 将 ObjC.Object(args[X]) 替换为 new ObjC.Object(args[X])
    # 但不要替换已经是 new ObjC.Object 的
    pattern = r'(?<!new\s)ObjC\.Object\('
    return re.sub(pattern, 'new ObjC.Object(', content)

def update_handler_file(file_path):
    """更新单个 handler 文件"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        modified = False
        
        # 检查是否已经全部使用 formatObjCObject
        has_old_format = (
            re.search(r'\.toString\(\)\s*\+\s*[\'"]（[\'"]\s*\+\s*\w+\.\$className', content) or
            re.search(r'\$className\s*\+\s*[\'"]\s*[\'"]\s*\+\s*\w+\.toString\(\)', content) or
            re.search(r'log\([\'"]👈:\s*[\'"]\s*\+\s*\w+\.\$className', content)
        )
        
        if not has_old_format and 'formatObjCObject' in content:
            return {'updated': False, 'reason': 'already using formatObjCObject'}
        
        # 替换模式1: log('👉'+ objcObj.toString() + '（' + objcObj.$className + '）')
        # 匹配各种变体，包括有空格和无空格的
        pattern1 = r"log\(['\"]👉['\"]?\s*\+\s*(\w+)\.toString\(\)\s*\+\s*['\"]（['\"]\s*\+\s*\1\.\$className\s*\+\s*['\"]）['\"]\)"
        replacement1 = r"log('👉 ' + formatObjCObject(\1))"
        new_content = re.sub(pattern1, replacement1, content)
        if new_content != content:
            content = new_content
            modified = True
        
        # 替换模式2: log('👈: '+ objcObj.$className +" "+ objcObj.toString() + '\n')
        pattern2 = r"log\(['\"]👈:\s*['\"]\s*\+\s*(\w+)\.\$className\s*\+\s*['\"][\s]*['\"]\s*\+\s*\1\.toString\(\)\s*\+\s*['\"]\\n['\"]\)"
        replacement2 = r"log('👈 ' + formatObjCObject(\1) + '\\n')"
        new_content = re.sub(pattern2, replacement2, content)
        if new_content != content:
            content = new_content
            modified = True
        
        # 替换模式3: log('👈: '+ objcObj.$className +" "+ objcObj.toString())
        pattern3 = r"log\(['\"]👈:\s*['\"]\s*\+\s*(\w+)\.\$className\s*\+\s*['\"][\s]*['\"]\s*\+\s*\1\.toString\(\)\)"
        replacement3 = r"log('👈 ' + formatObjCObject(\1))"
        new_content = re.sub(pattern3, replacement3, content)
        if new_content != content:
            content = new_content
            modified = True
        
        # 替换模式4: log('👈: '+ formatObjCObject(objcObj) + '\n') 但格式是旧的
        # 这个主要是确保格式一致性，如果已经是 formatObjCObject 但格式不对
        
        # 替换模式5: log('👈: '+ formatObjCObject(objcObj) + '\n') 中的格式（如果已经是 formatObjCObject 但格式不对）
        # 这个主要是修复格式一致性
        
        # 修复 ObjC.Object 创建
        fixed_content = fix_objc_object_creation(content)
        if fixed_content != content:
            content = fixed_content
            modified = True
        
        # 确保所有 ObjC.Object 都是 new ObjC.Object
        # 但不要替换已经是 new 的
        content = re.sub(r'(?<!new\s)(?<!new)ObjC\.Object\(', 'new ObjC.Object(', content)
        
        if modified:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return {'updated': True, 'reason': 'updated'}
        
        return {'updated': False, 'reason': 'no changes needed'}
        
    except Exception as e:
        return {'updated': False, 'reason': f'error: {str(e)}'}

def find_js_files(directory):
    """递归查找所有 .js 文件"""
    js_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.js'):
                js_files.append(os.path.join(root, file))
    return js_files

def main():
    script_dir = Path(__file__).parent
    handlers_dir = script_dir.parent / '__handlers__'
    
    if not handlers_dir.exists():
        print(f"❌ 目录不存在: {handlers_dir}")
        return
    
    print(f"📁 扫描目录: {handlers_dir}\n")
    
    js_files = find_js_files(handlers_dir)
    print(f"找到 {len(js_files)} 个 JS 文件\n")
    
    updated_count = 0
    skipped_count = 0
    error_count = 0
    
    for js_file in js_files:
        relative_path = os.path.relpath(js_file, script_dir.parent)
        result = update_handler_file(js_file)
        
        if result['updated']:
            print(f"✅ {relative_path}")
            updated_count += 1
        elif result['reason'] == 'already using formatObjCObject':
            print(f"⏭️  {relative_path} (已使用 formatObjCObject)")
            skipped_count += 1
        elif result['reason'].startswith('error'):
            print(f"❌ {relative_path} ({result['reason']})")
            error_count += 1
        else:
            print(f"➖ {relative_path} (无需更新)")
            skipped_count += 1
    
    print(f"\n📊 统计:")
    print(f"  ✅ 已更新: {updated_count}")
    print(f"  ⏭️  已跳过: {skipped_count}")
    print(f"  ❌ 错误: {error_count}")

if __name__ == '__main__':
    main()

