# ibox_hook

**爱盒 (com.aihe.abc) 显示文本/数字修改器** — 截图录屏用。悬浮球改规则，注入即用。

## 原理

爱盒是 Flutter AOT，UI 全走 Skia Canvas，没有 UILabel 可 hook。所有显示文字都过引擎 **ParagraphBuilder::addText**，以 UTF-16 明文进排版。

本插件在 `Flutter.framework` RVA **`0x481ca8`**（`blr x8` 前，`x1 = &UTF16Buf`）用 **Dobby** inline hook 拦截，按规则**原地改写**缓冲区。

### 写回策略（Frida v6 真机验证）

- **不改** mode bit / ptr / capacity（改了必崩）
- **External**：写 chars 到 ptr，更新 `len@+8`（clamp 到 capacity）
- **Inline**：写 chars 到 buf，更新 `flag = len & 0x7f`，最多 11 个 UTF-16 字符

## 使用（轻松签 / 免越狱）

### 1. 下载 dylib

[Releases](https://github.com/yy166431/ibox_hook/releases) 或 [Actions](https://github.com/yy166431/ibox_hook/actions) 下最新 **iboxhook.dylib**。

### 2. 注入 IPA

轻松签：

1. 导入爱盒 IPA（解密版）
2. **删 Info.plist 的 `UISupportedDevices`**（原版锁 XR/11，不删装不了新机）
3. 注入 `iboxhook.dylib`
4. 签名安装

手动：

```
Payload/Runner.app/Frameworks/iboxhook.dylib
# insert_dylib / optool 给 Runner 加:
#   LC_LOAD_DYLIB @rpath/iboxhook.dylib
```

### 3. 改规则

启动 App 约 4 秒后右上角出现蓝色 **「爱盒」** 悬浮球：

- **点一下** → 规则编辑器
- **拖动** → 换位置
- **截图/录屏** → 自动隐藏，不入镜

配置落盘：

```
App沙盒/Documents/ibox_hook_rules.json
```

首次自动生成模板（含 v6 验证过的示例规则）。保存后**立即生效**；服务器下发的静态数字需**重进页面**触发 `addText`。

#### JSON 字段

| 字段 | 说明 |
|------|------|
| `enabled` | 总开关 |
| `exact` | 精确整串优先，否则**包含**替换（长 key 优先） |
| `regex` | `pattern` / `replace` 数组 |
| `wallet` | 所有 `0x…` 钱包统一替换，**保持原长度**（截断/填充） |

示例：

```json
{
  "enabled": true,
  "exact": {
    "289": "999",
    "2632": "9999",
    "552": "999",
    "红苹果": "非常牛逼"
  },
  "regex": [
    {"pattern": "持有\\s*\\d+", "replace": "持有9999"},
    {"pattern": "¥\\s*[\\d,.]+", "replace": "¥88888"}
  ],
  "wallet": "0x8888888888888888888888888888888888888888"
}
```

## 技术

| 项 | 值 |
|----|-----|
| Bundle | `com.aihe.abc`（进程名 Runner） |
| 架构 | arm64 |
| Hook | Dobby 静态链接，无 substrate 依赖（sideload OK） |
| 配置 | 每 2s 热加载 mtime |
| 最低 iOS | 14.0 |

## 限制

- **只改显示，不改数据/接口**
- RVA `0x481ca8` 锁当前 Flutter 引擎；App 大更新引擎可能要重找偏移
- Inline 缓冲最长 11 字符；更长替换在 inline 模式会被截断
- 反调试：不要 `frida -f` spawn，正常启动再 attach / 直接注入 dylib

## 构建

```bash
# GitHub Actions: push main 或手动 workflow_dispatch
# 本地 (macOS + Xcode):
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
# 先准备 libdobby.a + dobby.h
clang++ -arch arm64 -isysroot "$SDK" -miphoneos-version-min=14.0 \
  -std=c++17 -fobjc-arc -dynamiclib \
  -framework Foundation -framework UIKit -framework CoreGraphics \
  -install_name "@rpath/iboxhook.dylib" \
  hook.mm libdobby.a -o iboxhook.dylib
ldid -S iboxhook.dylib
```

## 作者

海鸥 — Flutter stripped engine 扒了一天，addText 的 blr 点是老子用命换的。

## License

MIT
