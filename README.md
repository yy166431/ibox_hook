# ibox_hook

**爱盒 (ibox.art) 显示文本/数字修改器** — 用于截图录屏,无需刷新页面,修改一次即生效。

## 原理

爱盒是 Flutter 3.11 AOT 应用,UI 全部通过 Skia Canvas 绘制,没有原生 UILabel/UITextView 可以 hook。所有要显示的文字都会经过 Flutter 引擎里的 **ParagraphBuilder::addText** 这个唯一入口,以 UTF-16 明文形式传给 Skia 排版。

本插件在该函数调用的关键点 (`0x481ca8` blr 前) 用 Dobby inline hook 拦截,按配置规则替换文本,从而改变屏幕上显示的内容。

**Hook 点** (Flutter.framework 内 RVA,版本锁定):
- `0x481c2c` — addText native wrapper (Dart String → C++)  
- `0x481ca8` — 调用 `peer->addText(&utf16buf)` 前,此时 x1 寄存器指向栈上的 UTF-16 缓冲区

## 适用场景

- **截图/录屏** 需要修改显示的数字、文字、钱包地址
- **无需刷新** 只在渲染层改,不碰数据层/缓存,改一次当场生效
- **支持 iPhone16 iOS26** arm64 设备,sideload 重签注入(轻松签/牛蛙助手等)

## 使用方法

### 1. 下载 dylib

从 [Releases](https://github.com/yy166431/ibox_hook/releases) 或 [Actions](https://github.com/yy166431/ibox_hook/actions) 下载最新的 **iboxhook.dylib**。

### 2. 注入到 IPA

使用 **轻松签** 或其他重签工具:

1. 导入爱盒原版 IPA
2. **删除 Info.plist 里的 `UISupportedDevices` 键** (原版只允许 iPhone XR/11,删掉才能装在 iPhone16 上)
3. 在 "注入 dylib" 或 "Frameworks" 选项里,添加 `iboxhook.dylib`
4. 签名并安装到设备

**注意**: 如果轻松签没有"注入 dylib"选项,手动操作:
- 解压 IPA → `Payload/Runner.app/Frameworks/` 目录
- 把 `iboxhook.dylib` 扔进去
- 编辑 `Runner.app/Runner` 可执行文件,在 Load Commands 里添加 `LC_LOAD_DYLIB` 指向 `@rpath/iboxhook.dylib` (用 optool/insert_dylib 等工具)
- 重新打包签名

### 3. 配置替换规则

首次启动 App 后,插件会自动在 **沙盒 Documents** 目录生成配置模板:

```
/var/mobile/Containers/Data/Application/<UUID>/Documents/ibox_hook_rules.json
```

用 **Filza** (越狱) 或 **iTunes 文件共享** (sideload) 访问该文件并编辑:

```json
{
  "_说明": "exact=整串精确替换, regex=正则替换(UTF-8), wallet=所有0x钱包地址统一改成这个。改完保存, App里下拉刷新一下即生效",
  "exact": {
    "16868": "99999",
    "28391": "88888",
    "1560": "3650"
  },
  "regex": [
    {"pattern": "持有\\d+", "replace": "持有9999"},
    {"pattern": "¥\\d+",    "replace": "¥88888"}
  ],
  "wallet": "0x8888888888888888"
}
```

#### 规则说明

- **exact** (对象): 精确整串匹配,键值都是 UTF-8 字符串。屏幕上显示 `16868` → 替换成 `99999`
- **regex** (数组): 正则表达式替换,每项包含 `pattern` (正则) 和 `replace` (替换后的字符串)
  - `持有\\d+` → `持有9999` (把所有 "持有xxx" 改成 "持有9999")
  - `¥\\d+` → `¥88888` (所有价格统一改成 88888)
- **wallet** (字符串): 所有 `0x` 开头的十六进制地址(钱包地址)统一替换成这个值

#### 热更新

配置改完**不用重启 App**,插件每 1.5 秒后台刷新一次配置。改完保存,在 App 里触发一次新文字渲染(比如下拉刷新列表)即可看到效果。

### 4. 截图/录屏

进入要截图的页面 → 触发渲染(滑动/下拉刷新) → 文字已按规则替换 → 截图即可。

**无需反复刷新**,改一次就生效,除非你退出重进 App 清了 Flutter 的渲染缓存。

## 技术细节

- **架构**: arm64 (非 arm64e,无 PAC,iPhone16 上以 arm64 进程运行)
- **Hook 引擎**: Dobby (静态链接,无 substrate/越狱依赖)
- **配置读取**: 沙盒 `NSHomeDirectory()/Documents/ibox_hook_rules.json`
- **UTF-16 SSO 结构**: 引擎用 0x18 字节栈缓冲,flag@+0x17 区分内联/外部,改写时用 `malloc` 外部缓冲 (由引擎 wrapper 自动 `free`,分配器一致)

## 已知限制

- **只改显示,不改数据** 如果 App 校验接口返回的 JSON 数据,你截图后提交给服务器还是会被拒(但正常截图录屏发朋友圈没问题)
- **版本锁定** Hook 点 RVA `0x481ca8` 是针对当前 Flutter 引擎版本(3.11.0 stable)。如果 App 更新引擎,偏移可能变,需要重新逆向
- **首次渲染可能来不及** 极少数情况下页面加载太快,第一帧渲染时配置还没加载完,刷新一下即可

## 构建

```bash
# 自动构建 (GitHub Actions)
git push  # 触发 workflow,产物在 Actions Artifacts 里下载

# 本地构建 (需要 macOS + Xcode)
git clone https://github.com/yy166431/ibox_hook.git
cd ibox_hook
# 参照 .github/workflows/build.yml 手动执行命令
```

## 作者

海鸥 — 操他妈的 Flutter stripped engine,扒了一天终于找到 addText wrapper 的 blr 点。

## License

MIT
