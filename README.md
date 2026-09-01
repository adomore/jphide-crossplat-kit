# jphide-crossplat-kit

**中文** · [English](README_en.md)

针对 **Windows 版 JPHS** 与 **Kali / Debian 12 上的 `h3xx/jphs` + `stegdetect`**
之间跨平台失效问题的诊断工具包。

作者：匿名者
版本：2.3

本文档的英文镜像是 `README_en.md`。两份文件逐节对齐、同步维护。

**文档导航。** 新手请先看 `GETTING_STARTED_zh.md`（`GETTING_STARTED.md`）；完整参考是
`USER_MANUAL_zh.md`（`USER_MANUAL.md`）。本 README 记录的是工具包为之而生、并已验证的
跨平台实证发现。

---

## 1. 这是什么

常见的报告是：在 Windows 上做好的 jphide 载体图，在 Windows 上 hide/seek 一切正常，
拿到 Kali 上 `stegdetect` 不报、`jpseek` 也取不出来。第一反应通常是怀疑 Windows
的换行符转换。

本工具包的目的就是把这个猜测换成实测。它针对一个具体文件回答三个问题：

- 这是哪个 jphide 容器版本，**v3** 还是 **v5**？
- 用的是哪种 Blowfish 数据字节序，**大端**还是**小端**？
- 文件是否被 Windows text-mode 流破坏过，能否修复？

---

## 2. 实证发现

以下每一条都在容器里复现过，不是从文档推断的。

**`h3xx/jphs` 与 Windows 版 JPHS 是两种互不兼容的容器格式。**
`h3xx/jphs` 写着 `HS_MINOR_VERSION 3`；Windows 包（`JPHSWIN.EXE`、`jphs05.zip`）
是 JPHS 0.5。`stegdetect` 的 `break_jphide.c` 把两者实现为两条独立的验证路径。
v3 的 Blowfish 密钥就是口令本身，头部是单个 8 字节块；v5 的密钥是 DCT 派生 IV 的
前 6 字节拼接口令，头部是两个块，多一个冗余长度字段和第二次 IV 校验。密钥派生不同
加上头部布局不同，意味着 v3 的读取器连 v5 容器的长度字段都恢复不出来。

**`h3xx/jphs` 默认的 Blowfish 字节序是错的。这一条已被证明，不是推断。**
`bf_config.h` 默认走 `B_Blowfish_Encrypt`（大端），仓库自己的 `TODO` 也承认这个问题
从未定论。用参考源码编出的 32 位 `stegbreak`，喂入含正确口令的词表，结果是：

    stego_v3_le.jph : jphide[v3](TestPass123)     破解成功
    stego_v3_be.jph : negative                    根本不被识别
    cover_clean.jph : negative                    阴性对照正确

参考实现接受小端容器，对大端容器直接拒绝。它还自行标出了版本号，独立印证了 v3 判定。
编译 `h3xx/jphs` 必须加 `-DBF_LE`，否则它的产物对其它任何 jphide 工具都是不可读的。

**`jpseek.c` 在 Debian 12 / Kali 上编译不过。**
`open(seekfilename, O_WRONLY|O_TRUNC|O_CREAT)` 少了 mode 参数；`-O2` 下
`_FORTIFY_SOURCE` 生效时，glibc 会抛出 `__open_missing_mode` 硬错误。

**仓库自带的 Makefile 链接不了，链接修好后二进制运行时还会中止。**
`LDFLAGS` 放在目标文件之前，GNU ld 不认。把顺序改对之后，`-I./jpeg-8a` 配 `-ljpeg`
（Debian 上是 libjpeg-turbo）会报
`JPEG parameter struct mismatch: library thinks size is 656, caller expects 712`。

**`stegdetect` 在 x86-64 上需要 `-fcommon`，而且它的 jphide 判决不稳定。**
不加会因 `multiple definition of 'progname'` 链接失败。编出来之后，`fixtures/` 里
那张干净原图被报成 `f5[1.69](***)` —— 误报。`stego_v3_be.jpg` 报 `jphide(*)`，而
`stego_v3_le.jpg`（同工具、同载荷、同原图）在默认灵敏度下漏检，要 `-s 3` 才出来。
该检测器是带固定阈值的卡方检验，图像过小时会静默返回。

**jphide v5 识别已用真实 JPHSWIN 0.5 样本做逐位验证。** 包内附带
`fixtures/stego_v5_real.jpg`，由 Windows 上的 JPHS 0.5 用口令 `jeremy23` 制作。
`jphoracle` 将其判为 `jphide v5 / little-endian`，读出载荷长度 105 字节；Windows 版
`stegbreak.exe` 对同一文件独立报出 `jphide[v5](jeremy23)`。v5 的头部逻辑——密钥 =
`iv[0..5]||口令`、双块头、冗余长度字段与两次 IV 交叉校验——与参考实现逐位吻合。
`selftest.sh` 里的四道 v5 门禁就是针对这个真实样本断言的。

**v5 载荷提取已彻底攻克，且在 Linux 上原生可用（无需 Wine）。** 该变换是从
`jpseek.exe` 的反编译中还原的，并对八个已知明文样本做了逐字节验证（`fixtures/v5_samples/`
里七个受控样本，加上真实的 `jeremy23` 样本）。v5 载荷是：

1. 一个按位嵌入的字节流，内循环与 v3 完全相同（Blowfish 密钥流选择 DCT 系数，每个数据位
   与密钥流 1 异或）；
2. 一个 16 字节的头，携带**两个**长度——压缩长度（第 0 块）与未压缩长度（第 1 块）。若
   未压缩长度非零，则载荷是 LZO1X 压缩的，需解压；若为零，则直接原样存储。压缩器是
   LZO 1.01 / minilzo（由二进制里的版本字符串确认）；LZO1X 格式跨版本稳定，现行 minilzo
   即可读取。
3. 受一个 v5 独有的尾部标志 `hdr[3] & 1` 控制：置位时，每接受一个系数就多消耗一个密钥流 2
   的位。正是这一个位让 v5 在载荷中途与 v3 失同步，也正是它导致该格式无法仅凭输入/输出对
   还原——它在头部密文之外不可见。

`jpseek5` 实现了完整流程，在 Kali 上无需 Wine 即可提取 v5 载荷。推导过程见 `v5-findings.md`。

**字典攻击已内置：`jpcrack`。** 它先解码载体一次，然后拿字典里每个候选口令同时对
v3 和 v5 的头部校验做测试——与 `stegbreak` 用的是同一套校验——命中时报出版本号与口令。
加 `-o` 会直接接上 `jpseek5` 写出提取的载荷，于是一条命令即可从「未知口令的容器」走到
「明文」：

    ./jpcrack -o out.bin stego.jpg wordlist.txt

`-t N` 设置线程数（默认：全部核心）。和 `stegbreak` 一样，`jpcrack` 在测试前会用
JtR 风格的规则对每个字典词做变形——首字母大写、追加/前置数字、常见后缀、leetspeak、
反转、重复——所以基础词 `jeremy` 也会尝试 `Jeremy`、`jeremy1`、`jeremy23`、`j3r3my`
等等。这正是 stegbreak 把 `kaosmon` 破成 `Kaosmon0` 的机制。加 `-n` 关闭变形、逐字
测试。发送一次 SIGINT（Ctrl+C）会打印一行进度——已测候选数、速率、当前候选——与
stegbreak 完全一致。

每个候选的开销由 Blowfish 密钥调度主导（每核约 30k/秒），这就是吞吐天花板；`jpcrack`
通过多核并行来抬高它。这是弱口令攻击，和 `stegbreak` 完全一样：能破字典词和短口令，
对强随机口令无能为力——jphide 的 Blowfish 没有可利用的缺陷，所以口令强度是唯一的
攻击面。与只验证口令的 `stegbreak` 不同，`jpcrack -o` 还会写出载荷。

**Kali 不提供 `stegdetect` 与 `stegbreak`。** Kali bug tracker 的 #1688 请求提交于
2014-08-23，于 2020-02-11 以 `won't fix` 关闭，管理员给出的理由是该 fork 已无人维护、
上游站点已死。Debian 曾收录该包直到 2008 年的 0.6-5 QA 上传（`Architecture: source
i386`，从未为 amd64 构建过），此后移除。两边 `apt install stegdetect` 都会失败。唯一
的路是从源码编译，见 `build-stegdetect-kali.sh`。

**`stegbreak` 直接喂 JPEG 会段错误。** 32 位与 64 位构建下均可复现，`-t p`、`-t o`、
`-t j` 三种模式都崩。文档里的 `-c` 转换路径可用，但它同样以 139 退出：它会先写出一个
完整有效的 `.jph`，然后在退出清理阶段崩溃，所以退出码必须忽略。2007 年的一个 Debian
bug 报告过同类崩溃，从未被修复。

**GCC 14 及以后会直接编不过，而且修复方案不是一份固定的标志清单。**
`jpeg-6b` 自带的是 autoconf 2.12 的 configure，它的编译器探测程序就是一句
`main(){return(0);}`。GCC 14 把 `implicit-int`、`implicit-function-declaration`、
`int-conversion`、`incompatible-pointer-types` 与 `return-mismatch` 从警告提升为错误，
于是该探测失败，configure 报 `C compiler cannot create executables`，父级再报
`./configure failed for jpeg-6b`。用 `-Wno-error=` 把它们降回警告即可修好整条链，且
严格模式下编出的二进制仍能正确破解 fixtures。但标志名不可移植：GCC 13 会以
`no option '-Wreturn-mismatch'` 拒绝 `-Wno-error=return-mismatch`，而 GCC 14+ 恰恰需要
它。所以 `build-stegdetect-kali.sh` 会逐个做试编译探测，只保留本机编译器接受的标志。

**GCC 15 会以另一个原因再次编不过。** GCC 15 把默认标准从 `gnu17` 改成了 `gnu23`，而
C23 把 `true`、`false`、`bool` 变成了关键字。`stegdetect.c` 第 765 行声明的是
`float f, f2, sum, false;`，于是该文件不再是合法 C，构建以
`expected identifier or '(' before 'false'` 失败。`-std=gnu17` 可修。这是全树唯一的
冲突点：`rules.c` 里有个宏的形参就叫 `true` 和 `false`，但宏形参是预处理器标识符，
C23 仍然接受；`bf.c`、`jphide.c`、`jpseek.c` 与 `jphoracle.c` 在 C23 下也全部干净。
脚本对这一点同样做探测，用 `float false;` 试编译，仅在默认标准无法接受时才加 `-std`。
它同时会在 configure 之前预检 32 位编译器，因为当 `gcc-multilib` 与默认 `gcc` 版本不
匹配时，会由一个完全不同的原因产生同样误导的 "cannot create executables" 报错。

**`stegdetect` 从不提取任何东西。** 它做的是检测与嵌入系统识别。`stegbreak` 能恢复
口令但不写出载荷。提取只能靠 `jpseek`。

**Windows text-mode 破坏确有其事，但在本场景中多半不是主因。**
`jphide.c` 用 `fopen(...,"r")` / `fopen(...,"w")` 打开 JPEG，用 `open(..., O_RDONLY)`
打开载荷 —— 都没有要求二进制模式。在一个健康的 61,300 字节容器上模拟 Windows CRT
会插入 97 个 CR 字节；结果仍能作为合法的 640x480 图像打开，但 `stegdetect` 报
`negative`，头部也消失了。这与报告的症状完全吻合。然而同一容器在偏移 731 处有一个
`0x1A` 字节，text-mode 读取会把它当 EOF —— 所以如果 Windows 侧真对 JPEG 用了
text mode，Windows 自己的 `jpseek` 也会跟着坏。始终拿不到 `O_BINARY` 的载荷通道，
才是这个缺陷更可能发作的地方。

---

## 3. 目录内容

| 路径 | 用途 |
|---|---|
| `jphoracle.c` | 容器判别器：v3/v5 与大端/小端 |
| `crlf_check.py` | text-mode 破坏的检测与修复（容器） |
| `dict_hygiene.py` | 词表体检：BOM、UTF-16、CRLF、尾随空格 |
| `rule_expand.py` | 规则展开计算器（复刻 `jpcrack` 的规则） |
| `GETTING_STARTED.md` / `_zh.md` | 新手入门（EN/ZH lockstep） |
| `USER_MANUAL.md` / `_zh.md` | 完整参考（EN/ZH lockstep） |
| `jphs-portability.patch` | `h3xx/jphs` 在现代 Linux 上的修复补丁 |
| `build-stegdetect-kali.sh` | stegdetect/stegbreak 源码构建脚本，含工具链探测 |
| `jpseek5.c` | 原生 v3/v5 载荷提取器（Blowfish + LZO1X）——经反编译验证 |
| `jpcrack.c` | v3/v5 字典攻击，多线程；`-o` 命中后直接提取 |
| `v5diff.c` | v5 载荷分析器：以四种解读导出原始比特 |
| `v5-findings.md` | v5 格式的工作原理与还原过程 |
| `selftest.sh` | 10 道门禁的可复现验证套件 |
| `build.sh` | `jphoracle` 的一行式编译 |
| `bf.c`、`bf.h`、`bf_config.h`、`ltable.h` | 支撑文件（见第 9 节） |
| `fixtures/` | `selftest.sh` 使用的已验证测试语料 |

---

## 4. 编译

```
apt install build-essential libjpeg-dev
./build.sh
```

这里的 `bf_config.h` 刻意什么都不定义，好让 `B_Blowfish_*` 与 `L_Blowfish_*` 两组
入口同时可用，oracle 才能逐个试。

---

## 5. 用法

判别容器：

```
./jphoracle windows_stego.jpg '你的口令'
```

匹配行会给出版本号与字节序，并打印恢复出的载荷长度。没有匹配行说明没有任何组合通过
校验 —— 要么口令不对，要么文件里什么都没有，要么容器已被破坏。

检查 text-mode 破坏：

```
python3 crlf_check.py suspect.jpg [original_cover.jpg]
python3 crlf_check.py --repair suspect.jpg
```

修复会把 `0x0D 0x0A` 改回 `0x0A`。Windows 侧由 `0x1A` 字节造成的截断，这条路是救不
回来的。

---

## 6. 门禁自检

```
./selftest.sh
```

10 道门禁，出厂全绿：v3/大端与 v3/小端判别正确、载荷长度正确、干净原图无匹配、错误
口令无匹配、text-mode 破坏被标出、健康文件不被误标、被破坏文件对 oracle 不可见、
修复结果与破坏前逐字节相同、修复后容器重新可读。

---

## 7. 移植性补丁

```
git clone https://github.com/h3xx/jphs
cd jphs && patch -p1 -i ../jphs-portability.patch
```

补丁补上缺失的 `open()` mode 参数，通过一个在 Linux 上是空操作的 `O_BINARY` 垫片把
所有 JPEG 与载荷流切到二进制模式，把库移到链接行中目标文件之后，并把字节序选择提升
为默认 `-DBF_LE` 的 `BF_ENDIAN` 变量。

已验证：`-p1` 干净应用，打完的源码树可编译（含此前失败的 `jpseek.c`），打完的
`jpseek` 能逐字节取出 fixture 载荷。

---

## 8. 本工具包解决不了的问题

补丁不会让 `h3xx/jphs` 读懂 v5 容器。它是 0.3 的代码，打完还是 0.3。要在 Kali 上打开
Windows 做的容器只有两条路：用 Wine 跑 `jphs05` 的 `jpseek.exe`，或者自己写一个 v5
提取器。走第二条路的话，`jphoracle.c` 里的 `try_v5()` 已经完整复现了 v5 的全部头部
逻辑 —— 密钥派生、两个块、冗余长度字段与两次 IV 校验 —— 剩下的工作是载荷循环，不是
格式。

---

## 9. 来源与许可

`bf.c` 与 `bf.h` 是 Olaf Titz 的公共领域 Blowfish。`ltable.h` 标注为公共领域，且与
`stegdetect` 的 `jphide_table.c` 逐字节相同。`jphoracle.c` 是对 Niels Provos 的
`break_jphide.c` 中头部验证逻辑的独立重实现，该文件为 BSD 许可，算法归功于他。
`jphs-portability.patch` 针对 GPL 许可的 `h3xx/jphs`。fixtures 均为本地生成，不含任何
第三方图像素材。
