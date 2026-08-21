# ibox_hook v4

**爱盒 (com.aihe.abc) 显示文本/数字修改器** — **只注入一个 dylib**，轻松签即用。

## 用户怎么装（给别人就这一步）

1. 轻松签导入爱盒 IPA  
2. **删** `Info.plist` 的 `UISupportedDevices`（不删装不了新机）  
3. **注入** `iboxhook.dylib`  
4. 签名安装  

**不用**再 patch Flutter，**不用**电脑环境。一个 dylib 搞定。

进 App 约 4 秒 → 右上角蓝球「爱盒」→ 改规则保存。

## 原理（iOS 26）

| 方案 | 结果 |
|------|------|
| Dobby 运行时改 `__TEXT` | `CODESIGNING/Invalid Page` 秒杀 |
| 离线 patch Flutter + BRK | 能用，但用户要两步，麻烦 |
| **v4 硬件断点** | 改 debug 寄存器 BVR/BCR，**不碰代码页**，单 dylib |

命中 `Flutter + 0x481ca8`（`BLR X8`）→ 改 `x1` 的 UTF16Buf → 模拟 `BLR X8` 继续跑。

## 规则

悬浮球编辑，落盘 `Documents/ibox_hook_rules.json`：

- `exact` 整串/包含  
- `regex`  
- `wallet`（0x 保长）  
- `enabled`  

静态数字需重进页面触发 `addText`。

## 构建

```bash
# GitHub Actions push main 自动编
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
clang++ -arch arm64 -isysroot "$SDK" -miphoneos-version-min=14.0 \
  -std=c++17 -fobjc-arc -O2 -dynamiclib \
  -framework Foundation -framework UIKit -framework CoreGraphics \
  -install_name "@rpath/iboxhook.dylib" \
  hook.mm -o iboxhook.dylib
```

无 Dobby、无 substrate。

## 作者

海鸥

## License

MIT
