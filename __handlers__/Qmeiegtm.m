// Objective-C++ pseudo implementation (ARC)
// Method name inferred: - (void)qmei_e948ze8:(std::string)str code:(long)code
// Many helpers (sub_XXXXX) are mapped to meaningfully named functions.
// Comments include assembly clues (loc offsets / behaviors).

#import <Foundation/Foundation.h>
#import <mach/mach_time.h>

@interface Qmeiegtm : NSObject

@end

@implementation Qmeiegtm (Reconstructed)

// key ：@"q16"、"q36"，的value是怎么来的
// 汇编中，调用 sub_10009F6CC 函数，填充 QMStruct 结构体
// 「解码服务器下发的某种自定义二进制消息」的 OC 封装层。
- (NSDictionary *)qmei_e948ze8:(NSString *)arg1 code:(NSString *)arg2 {

    // --- 1.　本地结构体 ---
    QMStruct p = {0};

    // --- 2.　初始化结构体：sub_10009F6CC(&p) ---
    // 这个函数通常是：解析字符串，做 hash，填充随机数或生成 token
    sub_10009F6CC(&p);

    // --- 3.　创建一个可变字典（从空字典复制）---
    NSMutableDictionary *dict = [@{} mutableCopy];

    // ============ 第一部分：key = @"q16" ============
    NSString *keyQ16 = [NSString stringWithUTF8String:"q16"];

    // 注意：汇编里判断的是 p.bytes[7] 是否 < 0
    BOOL negative = ((int8_t)p.bytes[7] < 0);

    // 选择 value：负数则取结构体 A，不是负数则取结构体 B
    NSString *valueQ16 = nil;

    if (negative) {
        // X24 —> 指向 struct_A 的字符串地址
        valueQ16 = (NSString *)struct_A_string;    // 实际是一个指针，后面可补全
    } else {
        // X9 —> 指向 struct_B 的字符串地址
        valueQ16 = (NSString *)struct_B_string;
    }

    // 放入字典
    sub_107C0A718(dict, keyQ16, valueQ16);
    // 或等价于：dict[keyQ16] = valueQ16;


    // ============ 第二部分：key = @"q36" ============
    NSString *keyQ36 = [NSString stringWithUTF8String:"q36"];

    // 再次检查结构体 p。注意：第二次不是 p.bytes[7]，
    // 而是汇编中从 p 里另一个位置（偏移 0x36 附近）提取字段
    BOOL condition2 = (extract_from_p(p) < 0);
    // 上面 extract_from_p(p) 是占位，我需要你发 sub_10009F6CC 就能确认具体字段

    NSString *valueQ36 = condition2 ? (NSString *)struct_C_string
                                    : (NSString *)struct_D_string;

    sub_107C0A718(dict, keyQ36, valueQ36);
    // 或：dict[keyQ36] = valueQ36;


    // ============ 函数返回 ============
    // 汇编里是 autoreleaseReturnValue
    return [dict copy];
}

void sub_107C0A718(NSMutableDictionary *dict, id key, id value) {
    sub_10CD14758(dict, key, value);
}
// 假设函数签名如下（根据寄存器 X0/X1/X2 的使用推测）
void sub_10CD14758(NSMutableDictionary *dict, id key, id value) {
    id localDict = dict;   // X19
    id localKey  = key;    // X20
    id localValue = value; // X21

    // -------- 参数保留与空判断 --------
    if (!localValue || !localKey) {
        return;
    }

    // -------- 判断 value 是否是 NSString 且 length > 0 --------
    if ([localValue isKindOfClass:[NSString class]]) {
        if ([(NSString *)localValue length] == 0) {
            // 字符串为空 -> 不写入
            return;
        }
    }

    // -------- 执行 setObject:forKey: --------
    [localDict setObject:localValue forKey:localKey];

    // ARC 下无需手动释放，反汇编里是编译器生成的 retain/release
}

// 参数：arg (std::string-like) , code (int)
- (NSInteger)sub_10009F6CC:(std_string *)arg code:(int)code {

    // 根据前面的寄存器推导，X0 是 self，X1 是参数结构体指针
    std_string *input = arg;

    // 取 input->byte[0x17] 作为符号判断
    int8_t sign = (int8_t)input->bytes[0x17];

    // 取 input->ptr（string buffer 指针）
    uintptr_t stringPtr = *(uintptr_t *)((uint8_t*)input + 8);

    // CSEL：如果 sign < 0 就取 stringPtr，否则取 sign 本身
    uintptr_t selector = (sign < 0) ? stringPtr : sign;

    // 在栈上构造一个 std::string
    std_string tempStr = std_string(selector);  // 调用 C1(复制构造)

    // 读取 tempStr 的结构，判断是否为空（W8==W9）
    if (tempStr.start >= tempStr.finish) {
        return 0x100; // 直接返回
    }

    // 预计算的一些指针
    uint8_t *ptrForCase1 = (uint8_t *)self + 8;
    uint8_t *ptrForCase2 = (uint8_t *)self + 0x20;

    const int defaultValue = 0xF;

    while (true) {
        uint64_t tmpValue = 0;

        // ⭐核心：解析字符串，返回一个状态码
        int state = sub_10007B5E4(&tempStr, &tmpValue);

        if (state != 0x100) {
            // 错误直接返回 state
            return state;
        }

        // 解析 tmpValue 的低三位
        uint64_t low3 = tmpValue & 7;

        // 如果低 3 位 <= 6 则选 defaultValue，否则保持之前的值
        int picked = (low3 <= 6) ? low3 : defaultValue;

        uint64_t highBits = tmpValue >> 3;

        if (highBits == 1) {
            // case 1
            int ret = sub_10007B4A0(&tempStr, ptrForCase1);
            if (ret == 0x100) continue;
            else return 0x203;
        } else if (highBits >= 2) {
            // case >=2
            int ret = sub_10007B4A0(&tempStr, ptrForCase2);
            if (ret == 0x100) continue;
            else return 0x204;
        } else {
            // fallback
            sub_10007B530(&tempStr, NULL);
        }
        // 最后检查是否需要继续循环
        if (tempStr.start >= tempStr.finish) break;
    }
    return 0x100;
}


// 返回值：0x100 = OK, 0x101 = Error
// 「从一个结构体中读取一段字符串 → append 到 std::string → 更新游标」
int sub_10007B4A0(std::string* thisStr, SomeStruct* pStruct)
{
    uint64_t outValue = 0;
    
    // 调用 sub_10007B5E4 填充 outValue
    int status = sub_10007B5E4(&outValue);

    if (status != 0x100) {
        return status;   // 错误直接返回
    }

    // outValue 现在是某个长度 len
    uint32_t len = (uint32_t)outValue;

    // thisStr->assign("")
    thisStr->assign("");     // 先清空字符串

    uint32_t pos  = pStruct->pos;     // pStruct->[0]
    uint32_t size = pStruct->size;    // pStruct->[4]

    // 检查 pos + len 是否越界
    if (pos + len > size) {
        return 0x101;        // 越界 → 错误
    }

    // thisStr->append( anotherString, pos, len )
    thisStr->append(
        pStruct->innerString,   // offset +8
        pos, len
    );

    pStruct->pos = pos + len;

    return 0x100;            // OK
}

//「从一个结构体中读取一段字符串 → append 到 std::string → 更新游标」
int sub_10007B530(MyClass* thisObj, InputStruct* in)
{
    uint32_t flag = in->flag;
    int result = 0;

    // flag == 2 的分支
    if (flag == 2)
    {
        SomeStruct temp = {0};
        int status = sub_10007B4A0(thisObj, &temp);
        result = status;

        // 如果 temp 内部有指针，需要 delete
        if (temp.shouldFree)
        {
            operator delete(temp.ptr);
        }

        if (status != 0x100)
            return status;

        // 继续从 in->flag 取
        flag = in->flag;
    }

    // flag == 0 的分支
    if (flag == 0)
    {
        SomeStruct temp = {0};
        int status = sub_10007B5E4(&temp);
        result = status;

        if (status != 0x100)
            return status;

        return 0x103;
    }

    // 其它 flag → 固定返回 0x103
    return 0x103;
}

// 返回值：0x100 OK，0x101 EOF，0x102 超长错误
uint32_t sub_10007B5E4(BufferStruct* buf, uint64_t* outValue)
{
    uint32_t pos = buf->pos;
    uint32_t size = buf->size;

    // 如果 pos >= size → 没有更多字节可以读
    if (pos >= size) {
        return 0x101;   // EOF
    }

    uint64_t result = 0;
    int shift = 0;        // 每次移位 7 bit
    uint32_t index = 0;    // 已消费字节数，最多 9

    uint8_t* base = (uint8_t*)buf + 8; // 指向 dataPtr 的位置

    while (true)
    {
        if (pos + index >= size || index > 8) {
            // 超界 or 超过 9 字节
            buf->pos = pos + index;
            return 0x102;
        }

        // 读取一个字节，可以是直接数据或间接寻址
        uint8_t* realPtr = base;
        int8_t tag = *(int8_t*)(base + 0x17);

        // 如果最高位为1，则 dataPtr 在 base[0]
        if (tag < 0) {
            realPtr = *(uint8_t**)base;
        }

        uint8_t byte = *(realPtr + pos + index);

        // 低7位加入结果
        result |= ((uint64_t)(byte & 0x7F)) << shift;

        *outValue = result;

        index++;
        shift += 7;

        // 如果最高位为0（byte & 0x80 == 0）→结束
        if ((byte & 0x80) == 0) {
            break;
        }
    }

    buf->pos = pos + index;
    return 0x100;
}

@end
