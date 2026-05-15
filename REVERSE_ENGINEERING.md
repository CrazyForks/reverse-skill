# LinYuDriverLoader4.9.sh 逆向分析报告

## 概述

`LinYuDriverLoader4.9.sh` 是一个伪装成 shell 脚本的 **ARM64 (AArch64) ELF 可执行文件**。该文件使用静态链接、无符号表、无 section header，并包含一个损坏的程序头作为反分析措施。实际文件是一个自解压的驱动加载器（driver loader），运行于 Android/Linux ARM64 环境。

| 属性 | 值 |
|------|-----|
| 文件大小 | 685,451 字节 |
| ELF 类型 | 可执行文件 |
| 架构 | ARM aarch64 |
| 入口点 | `0x3d66bc` |
| 工具链 | AOSP LLVM/Clang 21.0 (PGO 优化) |
| 链接器 | LLD |

---

## 文件结构

```
┌─────────────────────────────────────┐
│ ELF 头 + 程序头 (3 个)               │
│  - PHDR[0]: LOAD RW (数据/BSS)       │
│  - PHDR[1]: LOAD XR (代码段)         │
│  - PHDR[2]: 0x0a 填充 (反分析)       │
├─────────────────────────────────────┤
│ 未压缩的 ARM64 代码                   │
│  - 解压器 (LZSS)                     │
│  - loader 函数                       │
│  - mmap wrapper                     │
│  - setup 函数                        │
├─────────────────────────────────────┤
│ 数据表 (16 字节)                     │
├─────────────────────────────────────┤
│ LZSS 压缩数据 (1,981 字节)           │
├─────────────────────────────────────┤
│ 构建元数据 (938 字节)                 │
│  - Android (138152, +pgo, ...)       │
│  - clang version 21.0                │
│  - LLVM 项目 commit hash             │
└─────────────────────────────────────┘
```

### ELF 程序头

| 索引 | 类型 | 标志 | 偏移 | 虚拟地址 | 文件大小 |
|------|------|------|------|----------|----------|
| 0 | LOAD | RW | 0x0 | 0x0 | 0x1000 |
| 1 | LOAD | XR | 0x0 | 0x330000 | 0xa71e1 |
| 2 | 0x0a0a0a0a | 0x0a0a | 0x0a0a... | 0x0a0a... | 损坏 |

PHDR[2] 被故意填充 `0x0a` 字节以干扰分析工具。

> **计算关系**：文件偏移 = 虚拟地址 - `0x330000`

---

## 解压器算法 (LZSS)

### 位读取函数 (`pop_bit`)

位于 `0x3d676c`。维护一个 32 位移位寄存器 `w4`，每次提取最高位。

```python
def pop_bit(w4, input_buf, input_pos):
    carry = (w4 >> 31) & 1          # 提取 bit 31 → C flag
    w4 = (w4 << 1) & 0xFFFFFFFF     # w4 = w4 + w4 (左移 1 位)
    if w4 == 0:                     # cbz: 缓冲区耗尽，重新加载
        loaded = read_u32(input_buf, input_pos)
        input_pos += 4
        adcs_carry = 1 if (loaded >= 0x80000000) else 0
        w4 = (loaded * 2 + carry) & 0xFFFFFFFF
        return (adcs_carry, w4, input_pos)  # 返回 adcs 的进位
    return (carry, w4, input_pos)   # 返回 adds 的进位（旧 bit 31）
```

**关键细节**：
- 初始值 `w4 = 0x80000000`
- 当 `w4` 移空（变成 0）时，从输入加载 4 字节并更新移位寄存器
- refill 路径的返回值来自 `adcs`（与 `adds` 不同）

### 主循环

```
pop_bit → 如果 bit == 1: LITERAL（直接拷贝一个字节）
         如果 bit == 0: MATCH（读取长度 + 偏移量 + 回拷）
```

#### Literal 路径
```python
*output_ptr++ = *input_ptr++    # 直接拷贝一个字节
```

#### Match 路径

**长度解码**：可变长度编码，读取 bit 对 `(bit1, bit2)`：

```python
w1 = 1
while True:
    bit1 = pop_bit()
    w1 = w1 * 2 + bit1
    bit2 = pop_bit()
    if bit2 == 1:          # 结束标记
        break
    w1 -= 1
    bit_extra = pop_bit()
    w1 = w1 * 2 + bit_extra
```

编码示例：
- bits=`0,1` → w1=2
- bits=`1,1` → w1=3
- bits=`0,0,0,1` → w1=4
- bits=`1,0,0,1` → w1=9

**偏移量解码**（当 w1 >= 3 时）：

```python
w3 = w1 - 3
byte_offset = *input_ptr++          # 从输入读取 1 字节
w5 = byte_offset | (w3 << 8)        # 组合成 16 位值
w5 = ~w5                            # 按位取反（得到负数，指向后方）
if w5 == 0:                         # 结束标记
    break
odd = w5 & 1
w5 = w5 >> 1 (arithmetic)           # 算术右移，保留符号
```

`w5` 取反后为负数，用作相对于当前输出位置的回拷偏移量。

**结束标记**：当编码产生 `w1 = 0x1000002` 且读入的字节为 `0xFF` 时：
```
w5 = 0xFF | (0x00FFFFFF << 8) = 0xFFFFFFFF
~w5 = 0                           # → 触发结束
```

**额外长度解码**（根据 offset 奇偶性选择路径 A 或 B）：

路径 A（偶数 offset）：
```python
w1 = 1
bit = pop_bit()
if bit == 1: goto path_B
while True:
    bit = pop_bit()
    w1 = w1 * 2 + bit
    bit = pop_bit()
    if bit == 1: break
w1 += 4
```

路径 B（奇数 offset 或路径 A 提前退出）：
```python
bit = pop_bit()
w1 = w1 * 2 + bit
w1 += 2
```

**长度调整**：
```python
if unsigned(w5) + 0x500 < 2^32:   # cmn w5, #0x500; cinc w1, w1, lo
    w1 += 1                        # offst magnitude > 0x500 时加 1
```

**回拷循环**：
```python
for i in range(w1):
    output[out_pos] = output[out_pos + w5_signed]   # w5 为负值
    out_pos++
```

---

## 执行流程

### 阶段 1：ELF 入口

```
入口 (0x3d66bc)
  ├── ldr w19, [literal_pool]     # 从字面池加载 w19 = 0x22
  ├── bl setup_func (0x3d69cc)    # 解析 auxv，获取页面大小
  │     ├── 扫描栈寻找 auxv 向量
  │     ├── 查找 AT_PAGESZ (type=6)
  │     └── 设置 x24 = 返回地址
  └── 进入解压器 (0x3d66c4)
        ├── 保存寄存器
        ├── 设置 x7 = input + comp_size
        ├── w5 = -1, w4 = 0x80000000
        └── 跳转到主循环

解压完成 → cache 维护 (dc cvau / ic ivau)
         → 返回到调用者
```

### 阶段 2：Loader 函数

Loader 函数 (`0x3d6930`) 被 `bl 0x3d6930` 调用（位于 `0x3d6a10`）：

```
Loader 入口
  ├── 保存返回地址到 x20
  ├── 读取数据表：entry_offset, decomp_size, flags
  ├── mmap(NULL, 0xa68, PROT_RW, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0)
  ├── 保存 mmap 结果到 x27, 设 x2 = mmap_base (输出指针)
  ├── 设 x0 = compressed_data_addr (0x3d6a24)
  ├── 设 x1 = comp_size (0x7bd)
  ├── blr x24 → 调用解压器 (在 0x3d66c4)
  ├── 存储 x26 到 mmap_base[0]
  ├── 存储 w19 到 mmap_base[0x10]
  ├── mprotect(mmap_base, size, PROT_READ|PROT_EXEC)
  └── br mmap_base + 0x14 → 跳转到解压后的 payload
```

### 阶段 3：解压后的 Payload

解压后的 2664 字节结构：

| 偏移 | 大小 | 内容 |
|------|------|------|
| 0x00 | 8 | x26 值（取反的页对齐值 = `0xFFFFFFFFFFFFF000`） |
| 0x08 | 8 | ARM64 代码（`ldr` / `ret`） |
| 0x10 | 4 | w19 = `0x22` (34) |
| 0x14 | 剩余 | 入口代码 |

Payload 代码分析：

```
0x00: 00 f0 ff ff ff ff ff ff   # x26 = 取反的页大小 (-0x1000)
0x08: c0 ff ff 58 c0 03 5f d6   # ldr x0, [PC-4]; ret
0x10: 22 00 00 00               # w19 = 0x22
0x14: 13 00 00 14               # b #0x60 (跳转到入口)
...
0x60: 开始实际执行代码
      包含对 /proc/self/exe 的引用
      (路径字符串位于 payload 偏移 0x1b8)
```

---

## 关键数据结构

### 数据表 (vaddr `0x3d6a14`)

| 字段 | 偏移 | 值 | 说明 |
|------|------|-----|------|
| entry_offset | +0 | 0x00000100 | Payload 入口偏移量（未使用？） |
| decomp_size | +4 | 0x00000a68 | 解压后大小 (2664 字节) |
| comp_size | +8 | 0x000007bd | 压缩数据大小 (1981 字节) |
| flags | +12 | 0x00000008 | 标志位 |

### 压缩数据 (vaddr `0x3d6a24`)

- 文件偏移：`0xa6a24`
- 大小：1,981 字节
- 压缩比：1981 / 2664 ≈ 74.4%

---

## 解压器实现

完整 Python 解压器代码见 `decompress.py`。关键正确性要点：

1. `pop_bit` 在 refill 路径必须返回 **`adcs` 的进位值**（不是 `adds` 的进位值），即加载的 32 位字的 bit 31
2. 可变长度编码的解码需要正确处理 `(bit1, bit2)` 对的循环
3. 偏移量的 `MVN + ASR #1` 产生的是有符号负数

---

## 反分析技术

1. **损坏的程序头**：第 3 个程序头 (PHDR[2]) 被填充 `0x0a` 字节，使 readelf/Ghidra 解析出错
2. **无 section header**：`e_shoff = 0`，无法使用 section 信息分析
3. **去符号表**：所有符号被剥离
4. **静态链接**：无外部共享库依赖
5. **伪装 .sh 扩展名**：文件名为 `.sh` 但不是脚本

---

## 构建环境

从文件末尾的构建元数据提取：

```
Android (138152, +pgo, ...
clang version 21.0
https://android.googlesource.com/.../chain/llvm-project...
commit 5e969f06077099aa41290cdb4c66fa0f59349...
LLD /mnt/disks/build-...
```

工具链：AOSP 预置 LLVM/Clang 21.0，带 PGO 优化和 LLD 链接。
