# jphide-crossplat-kit —— 新手入门

作者：匿名者
版本：2.3

本文档的英文镜像是 `GETTING_STARTED.md`。两份文件逐节对齐、同步维护。完整参考见
`USER_MANUAL_zh.md`；工具包背后的诊断实证见 `README.md`。

本指南带一个新手从「刚 clone 下来」到「第一次成功破解」，几分钟内完成，全程只用包内
自带的测试文件，不需要任何 jphide 的前置知识。

---

## 1. 这个工具包做什么

jphide 把载荷藏进 JPEG 的 DCT 系数里。野外存在两个互不兼容的版本：**v3**（Linux 上的
`h3xx/jphs` 一脉）与 **v5**（Windows 上的 `JPHSWIN` 包）。两者在密钥派生、头部布局和载荷
封装上都不同，所以读得懂其中一个的工具读不了另一个。

本工具包让你在 Linux 上、无需 Wine 即可：

- **识别** 一张 JPEG 装的是哪个版本、哪种字节序（`jphoracle`）；
- **破解** 弱口令/字典口令，同时覆盖 v3 和 v5（`jpcrack`）；
- **提取** 恢复出的载荷，含 LZO 压缩的 v5（`jpseek5`）；
- **检查** JPEG 是否被 Windows text-mode 破坏（`crlf_check.py`）；
- **检查** 字典是否有会静默破坏破解的编码问题（`dict_hygiene.py`）。

它是一套弱口令工具：能恢复字典口令和短口令。强随机口令无能为力——jphide 的 Blowfish
没有可利用的缺陷，所以口令强度是唯一的攻击面。

---

## 2. 前置要求

一台 Debian 12 / Kali（或类似）系统，装好 C 工具链和 libjpeg 头文件：

```
sudo apt install build-essential libjpeg-dev
```

`dict_hygiene.py`、`rule_expand.py`、`crlf_check.py` 需要 Python 3，Kali 已自带。编译
`stegdetect`/`stegbreak` 本身是可选的、且需要 32 位工具链——见 `USER_MANUAL_zh.md`，
下面的所有步骤都不需要它。

---

## 3. 编译

```
./build.sh
```

它把四个工具编译到当前目录：

```
built: ./jphoracle    (v3/v5 + endianness identifier)
built: ./jpseek5      (v3/v5 payload extractor, native)
built: ./jpcrack      (v3/v5 dictionary attack, multi-threaded)
built: ./v5diff       (v5 payload analysis tool)
```

要确认一切接线正确，跑门禁套件——29 项检查，出厂全绿：

```
./selftest.sh
```

---

## 4. 五分钟走一遍

包内附带一个真实的 JPHSWIN v5 样本 `fixtures/stego_v5_real.jpg`，由 Windows 上用口令
`jeremy23` 制作。下面我们假装不知道这个口令，把它恢复出来。

### 4.1 识别容器

如果你已经知道口令，`jphoracle` 会告诉你版本、字节序和载荷长度：

```
./jphoracle fixtures/stego_v5_real.jpg jeremy23
```

它会报出 `jphide v5 / little-endian`，载荷长度 105 字节。用错误口令跑则不打印任何匹配
行——这是预期的「没有任何组合通过校验」结果，不是报错。

### 4.2 破解口令

实战里你并没有口令，这正是 `jpcrack` 的用武之地。造一个小词表，把答案藏在里面某处：

```
printf 'letmein\nhunter2\njeremy23\npassword\n' > demo.txt
./jpcrack fixtures/stego_v5_real.jpg demo.txt
```

预期结果：

```
jpcrack: N threads, cached 300000 coefficients, 305 candidates to test
FOUND: jphide[v5](jeremy23)  [3 candidates, 0.10s, ... c/s]
```

`jpcrack` 拿每个词同时对 v3 和 v5 的头部校验做测试，命中第一个即停。这里哪怕基础词只写
`jeremy` 也能成：测试前 `jpcrack` 会对每个词施加 John-the-Ripper 风格的规则——首字母
大写、追加/前置数字、常见后缀、leetspeak、反转、重复——所以 `jeremy` 的变体之一就是
`jeremy23`。

### 4.3 一条命令破解并提取

加上 `-o`，命中时 `jpcrack` 会直接接上 `jpseek5`，写出解密后（v5 还会 LZO 解压）的载荷：

```
./jpcrack -o out.bin fixtures/stego_v5_real.jpg demo.txt
cat out.bin
```

至此你拿到了容器所藏的明文——在 Linux 上、从一个未知口令端到端恢复出来。

---

## 5. 读懂 jpcrack 的输出

启动行给出线程数，以及在对词表做一遍扫描后、它将测试的候选精确数量（基础词数量 × 施加
到每个词上的规则数）：

```
jpcrack: 8 threads, cached 300000 coefficients, 1039482318 candidates to test
```

随时按一次 Ctrl+C，或传 `-p SEC`，即可打印一行进度：

```
Status: 42.087%  437408912/1039482318  180431.5 c/s  ETA 0:53:41: sunshine23
```

依次是：完成百分比、已测候选 / 总数、当前速率、由速率推算的 ETA、以及正在测试的候选。
命中时得到上面的 `FOUND` 行；若词表耗尽仍无命中：

```
exhausted 1039482318 candidates in 5761.44s (180431 c/s), no match
```

---

## 6. 你真正会用到的几个开关

- `-t N` —— 线程数。默认为全部核心。吞吐受 Blowfish 密钥调度限制（每核约 30k 候选/秒），
  所以核越多越快。
- `-o FILE` —— 命中时把载荷提取到 `FILE`（接上 `jpseek5`）。
- `-n` —— 不做变形：逐字测试每个词、跳过规则。当你的词表里已经是精确口令、或要测某个特定
  字符串时用它。
- `-p SEC` —— 每 `SEC` 秒自动打印一行进度。不加则只在按 Ctrl+C 时打印。

完整用法：

```
jpcrack [-t N] [-o out.bin] [-n] [-p SEC] stego.jpg wordlist
```

---

## 7. 先给字典做个体检

在 Windows 上编辑或创建的字典可能静默破坏破解：开头的 BOM 会污染第一个候选、存成 UTF-16
会让整个文件对字节型工具不可读、一个多余的尾随空格会把 `pw` 变成 `pw ` 从而永远匹配不上。
在长跑之前先筛一遍：

```
python3 dict_hygiene.py rockyou.txt
```

它按严重度（FAIL / WARN / INFO）报出每个问题，有任何问题就以非零退出，可拿去 gate 脚本。
`--fix` 会写出一个归一化的 `rockyou.txt.clean`（UTF-16 → UTF-8、剥 BOM、CRLF → LF）。最稳
的习惯是从 Linux 侧追加候选，而不是让文件在 Windows 编辑器里过一手：

```
printf '%s\n' '你觉得对的某个候选' >> rockyou.txt
```

`jpcrack` 自己会剥掉尾随的 `\r`，所以纯 CRLF 词表不会漏掉你的口令——但别的工具（hashcat、
john）未必，而且 BOM/UTF-16/尾随空格照样会咬 `jpcrack`。`dict_hygiene.py` 把它们全查出来。

---

## 8. 当 jpcrack 什么都没找到

`no match` 常见有三种原因，按可能性排序：

1. **口令不在你的词表里（或其规则变体里）。** 换更大的表，或用
   `python3 rule_expand.py yourword` 确认规则能到达你预期的形态。
2. **口令是强口令。** 随机口令任何字典攻击都恢复不了；这是 jphide 的性质，不是工具的局限。
3. **容器被破坏，或根本不是 jphide v3/v5。** 如果这张 JPEG 来自 Windows、可能过过 text-mode
   流，检查它：

   ```
   python3 crlf_check.py suspect.jpg [original_cover.jpg]
   python3 crlf_check.py --repair suspect.jpg
   ```

   修复会把 `0x0D 0x0A` 改回 `0x0A`。Windows 侧由 `0x1A`（Ctrl-Z）字节造成的截断，这条路
   救不回来。

---

## 9. 下一步

- `USER_MANUAL_zh.md` —— 完整参考：每个工具与开关、jphide v3/v5 格式、规则引擎与候选数
  的算术、门禁自检套件、故障排查、性能与边界。
- `README.md` —— 工具包为之而生、并已验证的跨平台实证发现。
- `v5-findings.md` —— v5 载荷格式如何从反编译中还原出来。
