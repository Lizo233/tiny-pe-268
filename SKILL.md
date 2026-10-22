# SKILL.md — 268 字节 Windows PE 实战手册

> 把一个能用的 Windows 控制台程序压到 **268 字节**（Windows 加载器允许的最小文件），
> 并把它继续塞进 echo 这种需要两个 API 调用的功能。
> 这份文档是"下次再做同类事"的速查手册：每个结论都标了是实测还是推算，
> 每个坑都写了症状、原因、修法。

**所有数据来自一台机器：Windows 10 19045 x64（WOW64 跑 32 位映像）。
换系统版本、换架构前，结论必须重新实测。**

---

## 0. 结果

| 程序 | 文件 | 代码 | 能力 |
|---|---:|---:|---|
| `hello-268.exe` | **268 B** | 132 B | 打印 `hello world` |
| `hello-echo-arg.exe` | **268 B** | 143 B | `echo` 语义：打印命令行参数 |
| `hello-echo-fold.exe` | **268 B** | 178 B | 过滤器：stdin → stdout |
| `hello-echo-stdin.exe` | 295 B | 171 B | 同上，连续布局（超预算，作对照） |

对照：MSVC 最小 C 版约 3~10 KB，FASM 原生 PE 2 KB，Crinkler 压缩 345 B。

三个 268 字节版本的区别只在**代码怎么摆**：
`hello-268` 全部连续；`echo-arg` 把 6 字节折进空洞；
`echo-fold` 把 28 字节折进 5 个空洞——**代码 178 字节，比连续区还大 34 字节，仍然塞进了 268**。

---

## 1. 为什么地板是 268

### 1.1 结论

```
file_size >= e_lfanew + 264
```

264 = 4（`PE\0\0`）+ 20（COFF）+ 240（`IMAGE_OPTIONAL_HEADER64`）
= **`sizeof(IMAGE_NT_HEADERS64)`**。

而 `e_lfanew` 最小只能是 4，所以 `4 + 264 = 268`。

### 1.2 实测表（二分搜索，每次只改 `e_lfanew`）

| `e_lfanew` | 0x04 | 0x10 | 0x20 | 0x40 | 0x80 | 0x100 | 0x200 | 0x400 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 最小文件 | 268 | 280 | 296 | 328 | 392 | 520 | 776 | 1288 |
| 减去 `e_lfanew` | **264** | 264 | 264 | 264 | 264 | 264 | 264 | 264 |

八个点全部精确等于 264，没有漂移。

### 1.3 为什么是 64 位的结构大小

这个 32 位映像是由 **64 位 ntdll** 校验的（WOW64），它按自己那套 64 位头部结构
的大小去读文件；文件没覆盖到 264 字节，探测读就越过 EOF，映射失败。

*（推论，未反汇编验证）* 若在真正的 32 位 Windows 上，校验方是 32 位 ntdll，
用 `IMAGE_NT_HEADERS32` = 248，地板应为 `4 + 248 = 252`。本机无法验证。

### 1.4 为什么 `e_lfanew` 不能小于 4

- 它必须 4 字节对齐（实测 `2`、`3` 被拒）。
- 更关键：**0x3C 处那个 DWORD 被读两次**——一次当 `e_lfanew`，一次当某个头部字段。
  只有 `e_lfanew = 4` 时它落在 `SectionAlignment` 上，而我们要的正好是 4 字节对齐。
  `e_lfanew = 8` 时它落在 `ImageBase` 上，`ImageBase` 变成 8，直接废掉。

### 1.5 踩坑：267 字节报的错会误导你

267 字节 → `ERROR_EXE_MACHINE_TYPE_MISMATCH`(216)，Windows 提示
"该版本与您运行的 Windows 版本不兼容"。

**这句提示和真实原因毫无关系**——真实原因是"探测读越过文件末尾"。
我在这上面绕了很久，去怀疑 Machine 字段和 Subsystem 版本。
**遇到 216 先数文件字节数，别信文案。**

---

## 2. 268 字节的完整分账

| 类别 | 字节 | 明细 |
|---|---:|---|
| ① 加载器强制（值必须精确） | **54** | MZ(2) PE签名(4) Machine(2) nsec=0(2) Magic(2) ImageBase(4) SecAlign(4) FileAlign(4) SizeOfImage(4) SizeOfHeaders(4) DllChars=0(2) 栈堆+LoaderFlags(20) |
| ② 只能填合法值 | **20** | e_cblp(2) optsize(2) Characteristics(2) 入口点(4) 子系统版本(4) Subsystem(2) NumDirs(4) |
| ③ 连续代码区 0x7C–0x10B | **144** | 代码与数据共用，1:1 互斥 |
| ④ 散落空洞 | **50** | 0x00C(12) 0x01E(2) 0x020(12) 0x030(8) 0x044(8) 0x050(4) 0x05C(4) |

54 + 20 + 144 + 50 = 268 ✓

**代码最早只能从 0x7C 开始**：`NumberOfRvaAndSizes` 在 0x78–0x7B，
实测填 `0xCCCCCCCC` 直接 193，必须写 0，所以那 4 字节被占死。

---

## 3. 无节区三连击

### 3.1 坑：有节区时 `SectionAlignment` 必须是 0x1000

在一个已验证可跑的 638 字节样本上做单变量测试：

| 改动 | 结果 |
|---|---|
| `SectionAlignment = 4` | **193** ERROR_BAD_EXE_FORMAT |
| `SectionAlignment = 0x100` | **193** |
| `SectionAlignment = 0x200` | **193** |
| `SectionAlignment = 0x1000` | 正常 |

而 `SectionAlignment < 0x1000` 时又要求 `FileAlignment == SectionAlignment`，
于是 `PointerToRawData` 被顶到 ≥ 0x200。

**这就是 345 字节以下走不通的根因**：有节区就有 0x200 的头部地板。

### 3.2 修法：`NumberOfSections = 0`

无节区时加载器把**整个文件**映射到 `ImageBase`，于是：

```
虚拟地址 VA = ImageBase + 文件偏移        （RVA == 文件偏移）
```

`SectionAlignment = FileAlignment = 4` 也被接受，0x200 地板消失。

### 3.3 坑：无节区时导入表完全不生效

实测：把 `dir[1]` 指向一张合法导入表，程序能加载、入口能执行，
但 **IAT 里仍是原来的 RVA**（读出 `0xDF`，不是 `0x76xxxxxx`）。

症状：程序正常启动，一调 API 就 `0xC0000005`。

这与 KeyJ 文章里"Windows 10 1703 起忽略不在节里的导入表"一致。
**修法：自己解析，见第 5 节。**

### 3.4 坑：`SizeOfImage` 必须 > 0x1000

恰好一页（`0x1000`）时，约 **1/25** 概率以 `0xC0000005` 随机死掉。
`0x2000` 及以上实测 600 次无失败。

**这个偶发崩溃极容易被误判成代码 bug。** 我为此重写了三遍哈希循环。
排查顺序：先固定 `SizeOfImage = 0x2000`，再怀疑代码。

### 3.5 坑：`SizeOfHeaders` 调大反而崩

`0x30` 正常；改成 `0x100` 以上会 `0xC000007B`。
入口在 0x7C（远大于 `SizeOfHeaders = 0x30`）却仍然被接受——
**"入口必须落在 headers 内"这条规则在这里不成立**。

---

## 4. 加载器必读字段清单（0xCC 填槽实测）

方法：把候选区域整体填 `0xCC`，跑 3 次看是否仍输出正确、退出码 0。

### 4.1 绝对不能动

| 偏移 | 字段 | 填 0xCC 的结果 |
|---|---|---|
| 0x000 | `'MZ'` | 不是 PE |
| 0x004 | `'PE\0\0'` | 不是 PE |
| 0x008 | `Machine` | 改 0x8664 → **193** |
| 0x00A | `NumberOfSections` | 改 1 → **193** |
| 0x01A | `Characteristics` | `0xFFFF` → **193**（不能置 NO_SEH 等位） |
| 0x01C | `Magic` | 改 0x20B → **193** |
| 0x02C | `AddressOfEntryPoint` | 改了就跑到别处 |
| 0x038 | `ImageBase` | 改 → 崩（代码里硬编码了绝对地址） |
| 0x03C | `SectionAlignment`（= `e_lfanew`） | 改 0x1000 → **216** |
| 0x040 | `FileAlignment` | 必须等于 SecAlign |
| 0x054 | `SizeOfImage` | 必须 > 0x1000 |
| 0x058 | `SizeOfHeaders` | 0x200 → **0xC000007B** |
| 0x062 | `DllCharacteristics` | `0xCCCC` → **193** |
| 0x064–0x077 | 栈/堆大小 + `LoaderFlags` | **87** ERROR_INVALID_PARAMETER |
| 0x078 | `NumberOfRvaAndSizes` | `0xCCCCCCCC` → **193** |

**注意 0x064 那 20 字节**：看着像"一堆 0"，其实是"0 = 用系统默认"。
填垃圾就 87。**"是 0"不等于"没用"。**

### 4.2 真的可以随便改

| 偏移 | 大小 | 原字段 |
|---|---:|---|
| 0x00C–0x017 | 12 | TimeDateStamp + 符号表指针 + 符号数 |
| 0x01E–0x01F | 2 | LinkerVersion |
| 0x030–0x037 | 8 | BaseOfCode + BaseOfData |
| 0x044–0x04B | 8 | OS / Image 版本号 |
| 0x050–0x053 | 4 | Win32VersionValue |
| 0x05C–0x05F | 4 | CheckSum |

共 **38 字节**，加上 0x020 那 12 字节（我们的字符串位）和尾部填充，
就是第 7 节折叠时可用的空间。

### 4.3 边界情况

`0x002–0x003` 填 0xCC 时 3 次里崩 1 次 → **保持 0**。
教训：**边缘通过不算通过**，要压测。

---

## 5. API 定位：PEB → 导出表

### 5.1 走链

```
fs:[0x30] → TEB
  +0x30 → PEB
  +0x0C → PEB_LDR_DATA
  +0x0C → InLoadOrderModuleList.Flink
          ├─ 第1项 本 exe
          ├─ 第2项 ntdll
          └─ 第3项 kernel32 ── +0x18 → DllBase (esi)
esi + 0x3C → e_lfanew
    + 0x78 → 导出目录（0x18 COFF + 0x60 数据目录起点）
       +0x18 NumberOfNames
       +0x1C AddressOfFunctions   (EAT)
       +0x20 AddressOfNames
       +0x24 AddressOfNameOrdinals
```

### 5.2 为什么用哈希而不是比字符串

比字符串要逐字节比 + 处理长度，多几十字节。
哈希把任意长度名字压成 32 位，**一条 `cmp` 就够**。

```
h = 0;  for each char c:  h = h*33 + c
```

### 5.3 坑：`\0` 多乘了一次 33（最阴的坑）

循环写成"先乘再判空"：

```asm
hash: imul eax, eax, 33
      movzx ecx, byte [ebx]
      add eax, ecx
      inc ebx
      test ecx, ecx
      jnz hash
```

结尾的 `\0` 也会走一次 `imul`，所以运行时算出的是 `h33(name) * 33`。

症状：**所有查找全部落空**，`[esp]` 保持 0，
然后 `call dword [esp]` 跳到地址 0 → 必然 `0xC0000005`。

诊断方法：让程序把算出的哈希当退出码返回，和 Python 端对比。
我实测得到 `0x86E81C5C`，而预期是 `0x49E800DC`，正好差 33 倍。

**修法（零成本）**：比较的常量预乘 33。

```python
H_WRITEFILE = (h33(b'WriteFile') * 33) & 0xFFFFFFFF
```

比"多写一条指令避免多乘"更省。

### 5.4 坑：`movzx ecx, byte [ebx]` vs `[ebp]` 的编码差

`[ebx]` 是 3 字节（`0F B6 0B`），`[ebp]` 要 4 字节（`0F B6 4D 00`，因为 ebp 基址需要 disp8）。
**寄存器选择会影响指令长度**，在 144 字节预算下值得计较。

---

## 6. 每次 API 调用的成本

| 版本 | 代码 | 说明 |
|---|---:|---|
| 1 次调用（`WriteFile`） | **132 B** | 基准 |
| 2 次调用（`ReadFile` + `WriteFile`） | **178 B** | **+46** |
| 2 次调用（`GetCommandLineA` + `WriteFile`） | **143 B** | **+11** |

+46 的拆解：多一次哈希比较 +7、多一个取值分支 +14、多一段调用序列 +25。

### 6.1 关键取舍：选"无参数"的 API

`GetCommandLineA` 比 `ReadFile` 便宜 35 字节，因为：

- 无参数 → `call dword [esp]` 只要 3 字节，不用压栈
- 不需要缓冲区指针、长度上限、输出长度变量

**做 `echo` 这种"打印参数"的功能，用 `GetCommandLineA` 比读 stdin 便宜得多。**

### 6.2 坑：别把 `echo` 做成过滤器

`echo content` 的语义是**打印参数**，数据来自命令行；
`cat` 式过滤器读 stdin。两者不是一回事。

我先做成了过滤器（`echo x | prog.exe`），名字叫 echo 但行为是 cat。
**实现与 shell 内置命令同名的工具前，先对齐语义**，否则要返工。

### 6.3 坑：含空格的程序路径会被引号包裹

Windows 在程序路径含空格时把命令行写成 `"C:\Program Files\x\echo.exe" arg`。
"找第一个空格"会停在 `Program` 后面，输出变成路径的残段。

处理办法是：若首字符是 `"`，先扫到配对的 `"` 再找空格。**实测代价 +10 字节**，
而 `main` 已用到 142/144，要腾出这 10 字节必须重构整个栈帧
（把计数器从栈槽改成 `push`、交换 ebp/ebx 角色等）。

**本仓库选择了不修**，改为在 README 里声明"路径不能含空格"。
这是一个诚实的取舍：10 字节的代价在这个预算下不是"顺手"能付的。
教训：**预算紧张时，先把限制写清楚，再决定要不要付这笔钱。**

---

## 7. 代码折叠：把 178 字节塞进 144

### 7.1 成本模型

空洞里放代码碎片，每段末尾要一条 `jmp short`（2 字节）跳到下一段。

```
可用代码碎片 = 空洞总容量 − 2 × 碎片数
```

`echo-fold` 用 5 个空洞（12+12+8+8+4 = 44），5 条跳转（10 字节），净得 34 字节。
`main` 里还要一条 `jmp rel32`（5 字节）跳进第一个空洞。

**净收益 ≈ 29 字节，正好补上 178 − 144 = 34 的缺口（配合下面的优化）。**

### 7.2 三个布局技巧

**① 把尾部前移**

`jmp` 的距离决定用 `rel8`（2 字节）还是 `rel32`（5 字节）。
空洞在 0x00C–0x05C，main 在 0x7C+，**从 main 末尾往回跳必然超过 127 字节 → rel32**。

解法：把"调用+收尾"那段放在 `main` 的**开头**，入口点后移到它后面：

```
main: 0x07C  tail（call WriteFile / add esp / xor / ret）   10 B
      0x086  start（序言…）← AddressOfEntryPoint 指这里
```

这样最后一个空洞跳回 tail 只有 40 字节，`rel8` 够用。

**② 合并重复的匹配块**

两个函数各自一个"取值+存储"块要 27 字节。改成用寄存器选槽位：

```asm
found: movzx eax, word [edi]
       mov eax, [edx+eax*4]
       add eax, esi
       mov [esp+ebx], eax      ; ebx = 0 或 4
       jmp adv
```

`f1` 只负责 `xor ebx,ebx`，`f2` 只负责 `push 4 / pop ebx`。**省 5 字节。**

**③ 删掉多余的跳转**

`adv` 里的 `jnz next` 不跳时要落到 `done`。
把 `done` 紧跟在 `adv` 后面、匹配块挪到最后，就不用 `jmp done` 了。**省 2 字节。**

### 7.3 坑：`adv` 后面不能紧跟匹配块

`scan_adv` 的 `jnz next` 落空时会**顺序执行下一条**。
如果匹配块紧跟在 `adv` 后面，就会拿一个垃圾 `eax` 去查 EAT → 崩。

**正确顺序**：`scan_head → scan_adv → done → f1/f2/found`。

### 7.4 坑：碎片边界必须落在指令边界上

切分点是"语义边界"还是"字节边界"必须分清。
`call [esp+0x18]` 是 4 字节，塞不进"4 字节空洞减 2 字节跳转 = 2 字节"的位置。

我的分配（`echo-fold`）：

| 区域 | 地址 | 容量 | 放什么 |
|---|---|---:|---|
| h1 | 0x00C | 12 | ReadFile 前 4 个参数 |
| h2 | 0x020 | 12 | ReadFile 剩余 + call |
| h3 | 0x030 | 8 | WriteFile 前 2 个参数 |
| h4 | 0x044 | 8 | WriteFile 中间参数 |
| h5 | 0x050 | 4 | 最后一个 push + 跳回 tail |

**布局由生成器产出并 `assert` 校验**（超限、rel8 越界都会报错），
不要手改二进制。

---

## 8. 未文档化行为与风险

| 依赖 | 说明 | 风险 |
|---|---|---|
| `WriteFile` 直吃 `-11` | 省掉整次 `GetStdHandle` 查找（约 14 B） | **未文档化**，非契约。不信任时用显式解析版（+14 B） |
| `ReadFile` 直吃 `-10` | 同上 | 同上 |
| kernel32 是第 3 个模块 | 只对当前加载顺序成立 | 加载顺序变化即失效 |
| 代码折叠进头部字段 | 可读性彻底崩坏 | 改任何布局都影响跳转距离 |
| 无重定位表 | 省空间 | `ImageBase` 被锁死 0x400000 |
| 极小 PE | 常被杀软误报 | KeyJ 文中也有 Avira 误报记录 |

**268 是本机 Win10 19045 实测下限，不能外推到 Win7/XP/未来版本。**

---

## 9. 调试方法论

### 9.1 坑：`objdump -d` 对无节区文件无效

```
$ objdump -d hello-268.exe
hello-268.exe:     file format pei-i386
（空白）
```

因为 `NumberOfSections = 0`，objdump 按节表找代码，找不到就什么都不输出。
`dumpbin /disasm` 同样空白（但 `dumpbin /headers` 正常）。

### 9.2 正确姿势：`ndisasm`

```powershell
ndisasm -b 32 -e 0x7c -o 0x40007c hello-268.exe
```

| 参数 | 作用 |
|---|---|
| `-b 32` | 32 位指令 |
| `-e 0x7c` | 跳过前 0x7C 字节头部 |
| `-o 0x40007c` | 起始地址，让左边显示真实 VA |

等价做法（objdump 裸二进制模式）：

```powershell
objdump -D -b binary -m i386 -M intel --adjust-vma=0x400000 `
        --start-address=0x40007c --stop-address=0x400100 hello-268.exe
```

### 9.3 显示怪癖

- `6A F5` 显示成 `push dword 0xfffffffffffffff5` —— 那是 `push -11`，ndisasm 按 64 位补了符号位。
- 尾部连串的 `add [eax],al` 是 `00 00` 零填充被当指令解了，**说明代码到此结束**。

### 9.4 退出码探针

把中间值当退出码返回，是唯一可靠的"无调试器"观测手段：

```asm
mov eax, [esi+0x3C]     ; 想看什么就把什么塞进 eax
ret                     ; 退出码 = eax
```

我用它确认了：kernel32 基址、导出目录 RVA、NumberOfNames（1610）、
首名哈希、IAT 未被填充（读出 0xDF）。

### 9.5 区分"必崩"和"偶发"

同一个文件跑 3 次崩 1 次 ≠ 代码有 bug。
**先压测 30~300 次统计分布**，再决定是否怀疑代码。

实测遇到过的偶发源：`SizeOfImage = 0x1000`（1/25）、
`0x002` 填 0xCC（1/3）、高负载下随机 1/50~1/300。

---

## 10. 可复用检查清单

写下一个极小 PE 前过一遍：

- [ ] `e_lfanew = 4`，文件 ≥ `e_lfanew + 264`
- [ ] `NumberOfSections = 0`，`SizeOfOptionalHeader = 8`
- [ ] `SectionAlignment = FileAlignment = 4`
- [ ] `SizeOfImage > 0x1000`（用 0x2000）
- [ ] `SizeOfHeaders = 0x30`（别调大）
- [ ] `NumberOfRvaAndSizes = 0`
- [ ] 栈/堆大小全 0（= 用默认），别填垃圾
- [ ] `DllCharacteristics = 0`
- [ ] 入口 RVA < `SizeOfImage`（**严格小于**，等于会崩）
- [ ] 代码最早从 0x7C 开始（0x78 的 NumDirs 被占）
- [ ] 哈希常量**预乘 33**
- [ ] 用 `ndisasm` 反汇编验证，别用 `objdump -d`
- [ ] 压测 ≥ 200 次再称"稳定"
- [ ] 折叠布局由生成器 assert 校验，禁止手改二进制

---

## 11. 参考

- [kajott / runcalc.asm — 268 字节，sectionless，import by hash](https://gist.github.com/kajott/063dfce6a94da03a379553b3db6be334)
  独立撞到同一个 268 下限，源码里写着 `FILL equ 48 ; fill with NOPs to get to
  the minimum allowed .exe size`，并把代码折叠进头部空洞。
- [KeyJ: Writing ultra-small Windows executables](https://keyj.emphy.de/win32-pe/)
  从 76800 字节压到 316 字节的完整推演；说明了"无节区时导入表失效"；
  评论区（Tinker, 2025-08）给出 `WriteFile` 直吃 `STD_OUTPUT_HANDLE` 的技巧。
- [tiny-hello](https://github.com/Lizo233/tiny-hello) —— 345 字节 Crinkler 版，本项目的起点。

---

## 12. 证据等级

| 结论 | 等级 |
|---|---|
| 268 地板、`e_lfanew + 264`、字段必读清单、代码字节数、折叠后 268 | **本机实测** |
| 264 = `sizeof(IMAGE_NT_HEADERS64)`、64 位 ntdll 探测 32 位映像 | 机制推论（数值精确吻合，未反汇编 ntdll） |
| 32 位 Windows 上地板为 252 | **未验证推测** |
| `WriteFile`/`ReadFile` 直吃伪句柄 | 本机实测，但属未文档化行为 |
| 折叠布局的通用性 | 仅在本机、本版本验证 |
