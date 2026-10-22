# tiny-pe-268

把能用的 Windows 控制台程序压到 **268 字节** —— Windows 加载器允许的最小 PE 文件。

```cmd
> hello-268.exe
hello world

> hello-echo-arg.exe content
content
```

| 程序 | 文件 | 代码 | 能力 |
|---|---:|---:|---|
| `hello-268.exe` | **268 B** | 132 B | 打印 `hello world` |
| `hello-echo-arg.exe` | **268 B** | 143 B | `echo` 语义：打印命令行参数 |
| `hello-echo-fold.exe` | **268 B** | 178 B | 过滤器：stdin → stdout |
| `hello-echo-stdin.exe` | 295 B | 171 B | 同上，连续布局（作对照） |

参考：MSVC 最小 C 版约 3~10 KB，FASM 原生 PE 2 KB，Crinkler 压缩 345 B。

**最值得看的是 [SKILL.md](SKILL.md)** —— 完整的踩坑手册，写了为什么地板是 268、
加载器到底读哪些字段、怎么把 178 字节代码塞进 144 字节空间。

## 怎么做的

不依赖任何汇编器或链接器，用 Python 逐字节生成 PE：

```
gen/mini_asm.py   区域感知的迷你汇编器（可以往任意地址区间发指令）
gen/build.py      四个目标，一条命令全部构建
```

`mini_asm.py` 的存在理由：代码要**折叠进 PE 头部字段**，
没有任何正常汇编器能表达"这段指令放在 0x020，那段放在 0x044"。
每个区域都有容量断言，跳转按绝对地址解析并检查 `rel8` 范围——
布局写错会直接报错，不会生成一个跑不起来的 exe。

## 构建

```powershell
python gen/build.py
```

无第三方依赖，Python 3.8+。输出到 `build/`。

## 验收

```powershell
python tools/verify.py
```

跑 200 次 hello、50 次 echo-arg、边界用例（空输入、127/2047 字节、
3000 字节截断、含 NUL 二进制、CRLF）、重定向、管道，全部 PASS 才退出 0。

## 已知限制

- **`hello-echo-arg.exe` 要求程序路径不含空格。** 路径含空格时 Windows 会用引号包裹
  程序名（`"C:\Program Files\x\echo.exe" arg`），而本程序只扫"第一个空格"，
  会从路径中间开始输出。处理引号要多约 10 字节，而 `main` 已用到 142/144，
  需要重构整个栈帧才能腾出空间——留作 TODO。
  把 exe 放到 `C:\bin\echo.exe` 这类路径下即可正常工作。
- **`hello-echo-fold.exe` 单次最多读 127 字节**（`push 0x7F`，为省 3 字节）。
  `hello-echo-stdin.exe` 能读 2047 字节（`push 0x7FF`），代价是文件 295 字节。
- 所有版本都**依赖未文档化行为**，见下方"风险"。

## 技术要点（详见 SKILL.md）

- **地板**：`file_size >= e_lfanew + 264`，264 = `sizeof(IMAGE_NT_HEADERS64)`，
  `e_lfanew` 最小为 4 → **268**
- **无节区**：`NumberOfSections = 0` → 整文件映射，RVA == 文件偏移，0x200 地板消失
- **无导入表**：加载器不填 IAT，代码自己走 `PEB → Ldr → kernel32 → 导出表`，
  按名字哈希（`h = h*33 + c`）定位函数
- **折叠**：连续区只有 144 字节，178 字节代码按指令边界切碎塞进头部 5 个空洞，
  用 `jmp short` 串联

## 风险

- 依赖若干**未文档化行为**（`WriteFile` 直吃 `STD_OUTPUT_HANDLE`、
  kernel32 是第 3 个加载模块）
- 无重定位表，`ImageBase` 锁死 `0x400000`
- 极小 PE 常被杀软误报
- **268 仅在本机 Win10 22H2 x64 实测**，不外推到其他系统版本

## 许可

MIT
