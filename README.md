# ibox_hook v3

**爱盒 (com.aihe.abc) 显示文本/数字修改器** — 截图录屏用。iOS 26 轻松签可用。

## 重要：iOS 26 为什么 v2 会崩

v2 用 Dobby **运行时改** `Flutter.__TEXT` → 页变成 `rw-` → 内核 `CODESIGNING / Invalid Page` 直接 `SIGKILL`。

**v3 方案**：

1. **离线**把 `Flutter.framework/Flutter` @ `0x481ca8` 的 `BLR X8` 打成 `BRK #0xCA8`
2. dylib **只**注册 `EXC_BREAKPOINT` 异常处理：改 `x1` 文本 + 模拟 `BLR X8`（`LR=PC+4, PC=X8`）
3. **运行时绝不写代码页**

## 安装（轻松签）

### 你需要两个文件

| 文件 | 作用 |
|------|------|
| `iboxhook.dylib` | 异常处理 + 悬浮球 UI |
| `Flutter`（patched） | 静态 BRK，替换原 `Flutter.framework/Flutter` |

### 步骤

1. 解压爱盒 IPA  
2. **替换**  
   `Payload/Runner.app/Frameworks/Flutter.framework/Flutter`  
   为仓库/本地打好的 `Flutter.patched`（或自己跑 patch 脚本）  
3. **注入** `iboxhook.dylib`（轻松签「注入 dylib」，或手动丢 Frameworks + `insert_dylib`）  
4. **删除** `Info.plist` 的 `UISupportedDevices`（原版锁 XR/11）  
5. 重打包 → 轻松签签名安装  

### 自己 patch Flutter

```bash
python tools/patch_flutter.py \
  Payload/Runner.app/Frameworks/Flutter.framework/Flutter \
  -o Flutter.patched
# 校验通过后覆盖回 Flutter.framework/Flutter
```

期望日志：

```
RVA  0x481ca8
was  0xd63f0100  BLR X8
now  0xd4219500  BRK #0xca8
```

若提示指令不匹配 = App 换引擎了，要重找偏移。

## 使用

启动约 4 秒后右上角蓝色 **「爱盒」** 悬浮球：

- 点一下 → 规则编辑器（精确/正则/钱包/总开关）
- 拖动换位；截图/录屏自动隐藏
- 配置：`Documents/ibox_hook_rules.json`（2 秒热加载）
- 静态数字需**重进页面**才会再走 `addText`

### 规则字段

| 字段 | 说明 |
|------|------|
| `enabled` | 总开关 |
| `exact` | 整串优先，否则包含替换（长 key 优先） |
| `regex` | `pattern` / `replace` |
| `wallet` | `0x…` 钱包，**保长**截断/填充 |

## 技术

| 项 | 值 |
|----|-----|
| Bundle | `com.aihe.abc`（进程 Runner） |
| Hook | 静态 `BRK #0xCA8` @ RVA `0x481ca8` + `EXC_BREAKPOINT` |
| 写回 | UTF16Buf 原地，不改 mode/ptr/capacity |
| 依赖 | 系统库 only，**无 Dobby / 无 substrate** |
| 最低 iOS | 14；真机验证目标 iOS 26.5 + 轻松签 |

## 构建

```bash
# Actions: push main
# 本地:
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
clang++ -arch arm64 -isysroot "$SDK" -miphoneos-version-min=14.0 \
  -std=c++17 -fobjc-arc -O2 -dynamiclib \
  -framework Foundation -framework UIKit -framework CoreGraphics \
  -install_name "@rpath/iboxhook.dylib" \
  hook.mm -o iboxhook.dylib
ldid -S iboxhook.dylib
```

## 作者

海鸥 — iOS 26 代码签把 Dobby 干废了，老子改 BRK 异常处理。

## License

MIT
