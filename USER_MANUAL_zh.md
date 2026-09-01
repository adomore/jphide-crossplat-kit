# jphide-crossplat-kit —— 用户手册

作者：匿名者
版本：2.3

本文档的英文镜像是 `USER_MANUAL.md`。两份文件逐节对齐、同步维护。若你是新手，请先看
`GETTING_STARTED_zh.md`；工具包背后的跨平台实证，见 `README.md`。

---

## 1. 概览与范围

jphide 把载荷嵌入 JPEG 的量化 DCT 系数，用一条由口令驱动的 Blowfish 密钥流来挑选系数。
存在两个互不兼容的容器版本：

- **v3** —— `h3xx/jphs` 一脉，`HS_MINOR_VERSION 3`，Linux 上常见。
- **v5** —— `JPHSWIN` / `jphs05` 包，JPHS 0.5，Windows 上常见。

两者在密钥派生、头部布局和载荷封装上都不同（见第 3 节），所以一个版本的读取器连另一个的
长度字段都恢复不出来。本工具包提供原生的 Linux 工具来识别、破解并提取二者，外加两个用于
诊断「Windows 做的容器在 Linux 上显示为空」两种失效模式的工具：text-mode 字节破坏，以及
字典编码问题。

**工具包不做什么。** 它是弱口令攻击，和 `stegbreak` 完全一样：能恢复字典口令和短口令，
对强随机口令无能为力。jphide 的 Blowfish 没有可利用的缺陷，口令强度是唯一的攻击面。它也
不把 `h3xx/jphs` 本身移植去读 v5——`jpseek5` 是一个独立的原生读取器来做这件事。

---

## 2. 安装与编译

### 2.1 依赖

```
sudo apt install build-essential libjpeg-dev
```

三个 `.py` 工具需要 Python 3（Kali 已自带）。编译 `stegdetect`/`stegbreak` 还额外需要 32
位工具链（见 2.3）。

### 2.2 编译 C 工具

```
./build.sh
```

在工作目录生成四个二进制：

| 二进制 | 作用 |
|---|---|
| `jphoracle` | 判别容器：v3/v5 与大端/小端 |
| `jpseek5` | 提取 v3/v5 载荷（Blowfish + LZO1X） |
| `jpcrack` | 多线程 v3/v5 字典攻击；`-o` 命中后提取 |
| `v5diff` | 以每种解读导出 v5 载荷的原始比特 |

`build.sh` 先把 `bf.c` 和 `minilzo.c` 编成目标文件，再编各工具。`bf_config.h` 刻意什么都不
定义，好让大端（`B_Blowfish_*`）与小端（`L_Blowfish_*`）两组入口同时可用；`jphoracle` 借此
逐个测试两种字节序。

### 2.3 编译 stegdetect / stegbreak

Kali 与现行 Debian 都不打包 `stegdetect`/`stegbreak`，唯一的路是从源码编译。工具包对此做了
封装：

```
sudo apt install gcc-multilib libc6-dev-i386 git
sh build-stegdetect-kali.sh [target-dir]
```

源码出自 1996–2001 年，在现代工具链上编不干净。脚本不硬编码标志——它探测本机编译器、只保
留能用的，因为所需标志随 GCC 版本而变：

- **必须 32 位构建。** x86-64 构建能链接能跑，但其卡方值会漂移、`stegbreak` 会破坏内存；
  脚本会预检一个可用的 `gcc -m32`，找不到就带指引中止。
- **GCC 14+** 把若干传统 C 警告提升为错误，破坏了自带 `jpeg-6b` 的 autoconf 探测；脚本用
  探测到的 `-Wno-error=` 标志把它们降回警告。
- **GCC 15** 默认 `gnu23`，其中 `true`/`false`/`bool` 是关键字、`stegdetect.c` 不再是合法
  C；脚本仅在默认标准无法编译 `float false;` 探测时才加 `-std=gnu17`。
- **`rules.ini`** 是 `stegbreak` 必需、且上游已删除；脚本在缺失时提供一个最小回退版本。

两个运行时注意点，都已记录、处理得当就无害：

- `stegbreak` **直接喂 `.jpg` 会段错误。** 用 `-c` 转换路径，它会写出一个有效的 `.jph`、
  然后在退出清理阶段以 139 退出——忽略退出码、用那个文件（脚本里追加 `|| true`）。
- `stegdetect` **从不提取**，只做检测与识别。它的 jphide 判决是带固定阈值的卡方检验：在
  干净图上可能误报、在默认灵敏度下可能漏检真样——用 `-s` 提高灵敏度。

---

## 3. jphide 格式

### 3.1 v3（JPHS 0.3 / `h3xx/jphs`）

- **密钥：** 口令本身。
- **头部：** 单个 8 字节 Blowfish 块。解密后，字节 0–2 是载荷长度；字节 3–7 必须等于
  （加密、旋转后的）IV 的字节 3–7。
- **载荷：** 直接嵌入所选 DCT 系数的比特流；每个数据位与一个密钥流位异或。不压缩存储。

### 3.2 v5（JPHS 0.5 / `JPHSWIN`）

- **密钥：** `iv[0..5] || 口令`，其中 `iv` 由载体的头几个 DCT 系数派生。
- **头部：** 两个 8 字节块。第 0 块携带压缩长度和第一次 IV 校验；第 1 块携带未压缩长度和
  第二次 IV 校验，外加一个交叉校验——第 1 块字节 1–2 须等于第 0 块字节 1–2。`hdr[3]` 须
  ≤ 3。正是这份冗余，使 v5 的匹配达到约 2⁻⁶⁴ 的误报率。
- **载荷：** 与 v3 相同的按位嵌入内循环，但受一个 v5 独有的尾部标志 `hdr[3] & 1` 控制：
  置位时，每接受一个系数就多消耗一个密钥流 2 的位，这正是 v5 在载荷中途与 v3 失同步的
  原因。若未压缩长度非零，则载荷是 **LZO1X 压缩**的（LZO 1.01 / minilzo；格式跨版本稳定，
  现行 minilzo 即可读取），需解压；若为零，则原样存储。

### 3.3 字节序

这里的 Blowfish 有两种数据字节序。`h3xx/jphs` 默认大端，这是错的：参考 `stegbreak` 只接受
小端容器、对大端直接拒绝（见 `README.md` §2）。本工具包所有工具在实际校验时都走小端
（`L_Blowfish_*`）；`jphoracle` 是例外，它两种都测，好报出文件用的是哪一种。

---

## 4. 工具参考

### 4.1 jphoracle

```
./jphoracle file.jpg passphrase
```

解码 JPEG 一次，拿口令对完整的 v3 与 v5 头部逻辑、在两种字节序下逐一测试。匹配行给出版本
与字节序、并打印恢复出的载荷长度；没有匹配行说明没有任何组合通过校验——口令不对、文件为空、
或容器已损坏。要求 3 通道（彩色）JPEG。这是诊断前端：当你已知或怀疑某口令、想给容器归类
时用它。

### 4.2 jpcrack

```
jpcrack [-t N] [-o out.bin] [-n] [-p SEC] stego.jpg wordlist
```

字典攻击。它解码载体一次、缓存系数遍历，然后把每个字典词——经规则引擎展开（见第 5 节）——
喂给和 `jphoracle` 相同的 v3 与 v5 头部校验，跨 `N` 个线程。命中第一个即打印版本与口令并停止。

**选项**

- `-t N` —— 线程数；默认全部在线核心。
- `-o FILE` —— 命中时委托 `jpseek5` 把载荷提取到 `FILE`，给出「未知口令直达明文」的一条命令。
- `-n` —— 关闭变形；逐字测试每个词（只有基础词，无规则）。
- `-p SEC` —— 每 `SEC` 秒自动打印一行进度（0 = 只在 SIGINT 时）。

**校验。** v3：密钥 = 口令、单块、长度须容于图像、外加 `hdr[3..7] == iv[3..7]` 的尾部校验。
v5：完整的五层 `break_jphide_v5` 校验——`hdr[3] ≤ 3`、长度容于图像、`iv[5..7]` 对解密后第 0
块、第 1 块交叉校验、冗余长度范围、以及 `iv2[4..7]` 对解密后第 1 块。v5 综合误报率约 2⁻⁶⁴，
所以哪怕跨数千万候选，错误口令也不会产生虚假命中。

**进度与分母（v2.3）。** 在工作线程启动前，`jpcrack` 会对词表做一遍不含任何密码学的扫描，
逐个基础词累加规则将为它产出的候选精确数量（`count_variants`）。该和就是打印为
`N candidates to test` 的分母，也用于百分比和 ETA。这遍扫描很快（rockyou 约一秒），因为它不
做任何 Blowfish。由此得到一个有用的不变量：穷尽一次时，已测候选计数会精确等于该分母，因为
生成器产出的每个候选都被计数一次——于是 `count_variants` 与规则引擎在运行时被证明一致，一旦
不相等就说明二者失同步了。

**进度行格式**

```
Status: 42.087%  437408912/1039482318  180431.5 c/s  ETA 0:53:41: sunshine23
```

百分比 · 已测/总数 · 速率 · ETA（由当前速率推算）· 当前候选。每次 Ctrl+C 打印，`-p` 下每
`SEC` 秒自动打印。

**吞吐。** 每个候选的开销由 Blowfish 密钥调度主导，每核约 30k 候选/秒；工具跨核并行来抬高
天花板。见第 9 节。

### 4.3 jpseek5

```
./jpseek5 stego.jpg passphrase outfile
```

原生提取器。给对口令，它为两个版本恢复载荷：v3 不压缩写出；v5 在头部未压缩长度非零时做
LZO1X 解压，否则原样写出。它是 `jpcrack -o` 调用的「单一真值」提取路径。v5 变换是从
`jpseek.exe` 反编译中还原、并对八个已知明文样本做了逐字节验证；推导过程见 `v5-findings.md`。

### 4.4 v5diff

```
./v5diff stego.jpg passphrase [plaintext_file]
```

v5 载荷分析器：以每种候选解读导出原始嵌入比特，可选地对照一个已知明文文件做 diff。这是
调查与格式验证工具，不在常规「识别 → 破解 → 提取」路径上。

### 4.5 stegdetect / stegbreak（单独编译）

编好之后（见 2.3）：

- `stegdetect [-s SENS] -t p file.jpg` —— 检测并识别嵌入系统。若默认灵敏度漏检真嵌入，就
  提高 `-s`。
- `stegbreak -r rules.ini -f wordlist -t p file.jph` —— 恢复口令（先用 `-c` 把 `.jpg` 转成
  `.jph`；忽略退出清理阶段的 139）。

**对照：stegbreak 的进度百分比。** `stegbreak` 是 *rule-major*：外层循环是规则集，每换一条
规则就把整个词表从头回卷再流一遍。它的状态百分比（出自 `stegbreak.c`）是
`(rule_number * 100 + part_file) / rule_count`，其中 `rule_count` 是展开后的词表规则总条数、
`part_file` 是*当前这一遍*扫到词表的字节偏移百分比。所以分母是规则条数、不是总候选数，一个
变形候选出现在很高的百分比处，只是因为它属于靠后的一遍规则。`jpcrack` 恰好相反——*word-major*，
对词表只过一遍、每个词施加所有规则——所以它用不了那个公式；它的百分比是基于候选计数的
（见 4.2）。

### 4.6 dict_hygiene.py

```
python3 dict_hygiene.py FILE [FILE ...]
python3 dict_hygiene.py --fix FILE           # 写出 FILE.clean
python3 dict_hygiene.py --quiet FILE ...     # 只打印有问题的文件
python3 dict_hygiene.py --fix --strip-trailing FILE
```

逐字节筛查词表中会静默破坏字节型破解器的编码问题。发现按严重度分级：

- **FAIL**（会破坏候选）：UTF-8/16/32 **BOM**（开头的 BOM 污染第一个候选）；**UTF-16/32**
  编码，靠「每字符一个 NUL」的模式判定（带不带 BOM 都认）（`fgets`/`strlen` 遇第一个 NUL
  截断，整表不可读）；**混合** CRLF+LF（Unix 文件被 Windows 编辑器追加了几行，只有追加行带
  隐藏的 `\r`）。
- **WARN**（可疑）：整表 **CRLF**（jpcrack 会剥尾随 `\r`，但 hashcat/john 未必）；**孤立
  CR**；行尾 **空格/Tab**（`pw ` ≠ `pw`，但尾随空格可能是有意的，所以只报不删）；行内控制
  字节。
- **INFO**：末行无换行。

退出码仅在所有文件都干净时为 0，可拿去 gate 流水线。`--fix` 写出归一化副本（UTF-16 →
UTF-8、剥 BOM、CRLF/CR → LF）；除非给 `--strip-trailing`，否则**不**动尾随空格，因为尾随
空格可能是真口令的一部分。

### 4.7 rule_expand.py

```
python3 rule_expand.py WORD [TARGET_VARIANT]
python3 rule_expand.py --selftest
```

`jpcrack` 的 `rules_apply` 的精确复刻，用来推演规则引擎。它报出一个基础词展开成多少个候选，
并可选地报出某个变形候选在生成顺序里的位置。它带两条互相交叉验证的独立代码路径——生成器与
闭式计数器——所以它的数字与 `jpcrack` 自己的 `count_variants` 一致。用它来预判规则能否到达某
口令形态，或理解某个总候选数（见第 5 节）。

### 4.8 crlf_check.py

```
python3 crlf_check.py suspect.jpg [original_cover.jpg]
python3 crlf_check.py --repair suspect.jpg
```

判断一张 JPEG 是否被 Windows text-mode I/O 破坏——CRT 会在每个 `0x0A` 前插 `0x0D`、读取时
把 `0x0D 0x0A` 折叠、并把 `0x1A` 当 EOF。这样的文件仍能作为图像解码，但其 DCT 系数被移位，
于是在 Linux 上什么都找不到。`--repair` 把 `0x0D 0x0A` 改回 `0x0A`；由 `0x1A` 字节造成的
截断，这条路救不回来。注意这针对的是**容器**（JPEG）；`dict_hygiene.py` 是**词表**的对应
工具。

---

## 5. 规则引擎与候选计数

测试前，`jpcrack` 用 John-the-Ripper 风格的规则对每个基础词做变形，顺序固定如下（每条产出
一个候选；括号内为条件）：

1. 词原样；
2. 首字母大写（仅当首字母小写）；
3. 全大写；4. 全小写；
5. 追加每个数字 0–9，对词本身和它的大写形式（后者仅当首字母小写）——至多 20 个；
6. 追加 19 个常见后缀（`23 1 12 123 1234 12345 ! @ # 01 007 69 111 2020 2021 2022 2023
   2024 00`），同样翻倍——至多 38 个；
7. 前置每个数字 0–9——10 个；
8. 反转；9. 重复（对任何短到能放进缓冲区的词）；
10. leetspeak 单字符替换 `a→@ a→4 e→3 i→1 o→0 s→$ s→5 t→7`，每条仅当该字母存在才产出。

因此每个词的数量是**可变的**，因为大多数规则有条件：

- 小写字母开头的词：**74 + leet(0–8)** 个候选；
- 数字或大写开头的词：**44 + leet**（首字母大写、以及大写形式追加那批变体都被跳过）；
- 实例：`smalvilesoker`（小写，含 a/e/i/o/s，不含 t）展开为正好 **81** 个候选，而
  `6smalvilesoker`——即前置 `6` 的变体——在生成顺序里排**第 69**。

没有固定倍数。在 rockyou 的一次真实跑批里，平均约为**每个基础词 71.5 个候选**：小写词
（74–82）是主体，一大批数字打头的口令（≈44）把均值拉低。`-n` 关闭以上全部——每个词一个
候选。`rule_expand.py` 可算出这里任何一个数字；`python3 rule_expand.py smalvilesoker` 复现
81 / #69 这个例子。

---

## 6. 词表卫生与跨平台问题

在 Windows 上编写的字典可能静默挫败破解。各种机制，以及 `jpcrack` 本身是否受影响：

- **尾随 CR（CRLF）。** `jpcrack` 的读取器会剥掉尾随的 `\r` 和 `\n`，所以 CRLF 词表在
  `jpcrack` 上**不会**漏掉口令。别的工具（hashcat、john）未必剥，那样每个候选都会静默带上
  一个隐藏的 `\r`。
- **BOM。** 开头的 UTF-8 BOM（`EF BB BF`）会成为第一个候选的一部分而使其失败；`jpcrack`
  不剥开头 BOM。它只影响第一行，所以追加到末尾是安全的，但把整个文件带 BOM 重存一遍会破坏
  它原来的第一个词条。
- **存成 UTF-16 /「Unicode」。** 每字符两字节、夹 NUL；`fgets`/`strlen` 遇第一个 NUL 截断、
  整表基本报废——这对 `jpcrack` 也会咬。词表永远别存 UTF-16。
- **行尾空格/Tab。** `jpcrack` 不剥；`pw ` ≠ `pw`。手工编辑很容易引入。
- **非 ASCII 口令的编码不一致。** `jpcrack` 逐字节比对，所以带重音或中文字符的口令，其在
  词表里的编码必须与当年嵌入时完全一致。纯 ASCII 不受影响。

**最佳实践。** 从 Linux 侧追加候选——`printf '%s\n' 'candidate' >> list.txt`——而不是让文件在
Windows 编辑器里过一手；非要在 Windows 编就存成 UTF-8（无 BOM）+ LF 行尾。任何传过来的表都
用 `dict_hygiene.py`（见 4.6）筛一遍；用它的 `--fix` 修复，或对 CRLF 用 `dos2unix` 再显式剥
一次 BOM。

---

## 7. 门禁自检套件

```
./selftest.sh
```

29 道门禁，出厂全绿；每道断言一个事实。它们覆盖：`jphoracle` 的 v3 大端/小端判别与载荷长度、
阴性对照（干净原图与错误口令）、真实 JPHSWIN v5 样本（判别与 105 字节长度，及其阴性对照）、
对受控样本的原生 v5 提取、`jpcrack` 找到 v3 与 v5 两种口令、规则引擎到达变形口令（`jeremy` →
`jeremy23`）、抗误报（5 万个错误候选在完整五层 v5 校验下无匹配）、以及 `crlf_check.py` 的
检测-修复路径（破坏被标出、健康文件不被误标、被破坏文件对 `jphoracle` 不可见、修复逐字节一致、
修复后可读）。运行以 `ALL 29 GATES GREEN` 结束。

---

## 8. 故障排查

- 编译 stegdetect 时 **`./configure failed for jpeg-6b` / `C compiler cannot create
  executables`** —— GCC 14/15 或 multilib 不匹配问题；跑 `build-stegdetect-kali.sh`，它会探测
  并降级出问题的标志、并预检 32 位编译器。见 2.3。
- **`stegbreak` 以 139 退出** —— `-c` 转换路径上的预期现象；`.jph` 在退出崩溃前已正确写出，
  忽略即可。
- **`JPEG parameter struct mismatch: library thinks size is 656, caller expects 712`** ——
  `h3xx/jphs` 构建把它自带的 `jpeg-8a` 头文件与系统 `libjpeg` 混用；移植性补丁与本包自己的
  `build.sh` 都避开了它。
- **`not 3-component` / `not a 3-component JPEG`** —— 工具要求彩色（3 通道）JPEG；灰度图不
  支持。
- **`jpcrack` 报 `no match`** —— 见 `GETTING_STARTED_zh.md` §8：口令不在表里、强口令、或
  被破坏/非 v3-v5 容器。
- **一个「本应」含口令的词表仍然失败** —— 用 `dict_hygiene.py` 筛它；BOM、UTF-16 存盘或尾随
  空格是常见原因。

---

## 9. 性能与局限

吞吐受 Blowfish 密钥调度限制，每核约 30k 候选/秒；`jpcrack` 跨核扩展，所以墙钟时间约为
`总候选数 / (30k × 核数)`。规则引擎每基础词加约 71.5×（见第 5 节），一个 1400 万行的词表就是
十亿量级的候选——在典型多核机器上要数小时，这正是百分比与 ETA（v2.3）存在的理由。当你已经
有精确口令时，`-n` 把它砍到每词一个候选。

硬性上限是口令强度。这是弱口令攻击：能恢复字典口令和短口令，恢复不了强随机口令。jphide 的
Blowfish 没有可利用的缺陷，所以绕不开密钥调度、除口令本身外没有别的攻击面。

---

## 10. 来源与许可

`bf.c` 与 `bf.h` 是 Olaf Titz 的公共领域 Blowfish。`ltable.h` 标注为公共领域，且与
`stegdetect` 的 `jphide_table.c` 逐字节相同。`jphoracle`、`jpcrack`、`jpseek5` 与 `v5diff`
中的头部验证逻辑，是对 Niels Provos 的 `break_jphide.c`（BSD 许可）的独立重实现，算法归功于他。
`minilzo` 是 Markus Oberhumer 的 LZO，GPL 许可。`jphs-portability.patch` 针对 GPL 许可的
`h3xx/jphs`。Python 工具（`dict_hygiene.py`、`rule_expand.py`、`crlf_check.py`）与全部
fixtures 均由匿名者本地生成，不含任何第三方图像素材。
