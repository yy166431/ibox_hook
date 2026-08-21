// ============================================================================
//  ibox_hook — 爱盒(com.aihe.abc) Flutter 显示文本/数字修改器
//  用途: 轻松签/巨魔注入, 拦截 Flutter 渲染层, 改屏幕上的字用于截图录屏
//
//  原理:
//    爱盒是 Flutter AOT, UI 全走 Skia Canvas, 没有 UILabel 可 hook。
//    所有要显示的文字都过 ParagraphBuilder::addText, UTF-16 明文进 Skia。
//    在 blr x8 前拦 X1=&UTF16Buf, 按规则原地改写。
//
//  Hook 点 (Flutter.framework RVA, 当前引擎版本锁定):
//    0x481ca8  blr x8  <-- peer->addText(&utf16buf), x1 = &UTF16Buf
//
//  写回策略 (Frida v6 真机验证):
//    - 绝不改 mode bit / ptr / capacity (改了必崩)
//    - External: 写 chars 到 ptr, 更新 len@+8 (clamp 到 capacity)
//    - Inline:   写 chars 到 buf, 更新 flag=(len&0x7f), 最多 11 字符
//
//  iOS 26 注意:
//    轻松签 + 运行时 Dobby/inline hook 会改 __TEXT 页权限 → CODESIGNING/Invalid Page 秒杀。
//    v4: 硬件断点 (ARM_DEBUG_STATE64 BVR/BCR) + EXC_BREAKPOINT。
//        不改代码页、不 patch Flutter，用户只注入一个 dylib。
//
//  作者: 海鸥
// ============================================================================
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach/exception.h>
#include <mach/thread_status.h>
#include <pthread.h>
#include <string.h>
#include <algorithm>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <regex>
#include <stdatomic.h>

#define TAG "[ibox_hook] "
static inline void LOG(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"%@%@", @TAG, s);
}

// Flutter.framework 内 ParagraphBuilder::addText 的 blr 点, 版本锁定
static const uintptr_t RVA_ADDTEXT_BLR = 0x481ca8;
static const uint32_t  INSN_BLR_X8     = 0xD63F0100;
// DBGBCR: E=1, PMC=EL0|EL1(0b11), BAS=0b1111 → 0x1e5
static const uint64_t  HWBP_BCR_ENABLE = 0x1e5ULL;
static const int       HWBP_SLOT       = 0;

// ---------------------------------------------------------------------------
//  UTF-16 SSO 缓冲 (0x18 字节, 栈上)
//    flag @ +0x17 : bit7=1 external, bit7=0 inline
//    external: ptr@+0, len@+8, capacity@+0x10
//    inline:   data@+0, len = flag & 0x7f (最多 11 个 char16_t)
// ---------------------------------------------------------------------------
struct UTF16Buf {
    uint8_t raw[0x18];

    uint8_t flag() const { return raw[0x17]; }
    bool external() const { return (flag() & 0x80) != 0; }

    char16_t *dataPtr() {
        if (external()) {
            return *reinterpret_cast<char16_t **>(raw);
        }
        return reinterpret_cast<char16_t *>(raw);
    }

    size_t length() const {
        if (external()) {
            return *reinterpret_cast<const size_t *>(raw + 8);
        }
        return flag() & 0x7f;
    }

    size_t capacity() const {
        if (external()) {
            return *reinterpret_cast<const size_t *>(raw + 0x10);
        }
        return 11; // inline 最多 11 个 UTF-16 code unit
    }

    std::u16string get() {
        char16_t *p = dataPtr();
        size_t n = length();
        if (!p || n == 0 || n > 10000) return u"";
        return std::u16string(p, n);
    }

    // v6 原地写回: 不改 mode/ptr/capacity
    bool setInPlace(const std::u16string &s) {
        char16_t *p = dataPtr();
        if (!p) return false;

        size_t cap = capacity();
        if (cap == 0) {
            // 某些实现 capacity 可能为 0/未填, 退回用原长度当上限
            cap = length();
            if (cap == 0) cap = 1;
        }

        size_t writeLen = s.size();
        if (writeLen > cap) writeLen = cap;
        if (!external() && writeLen > 11) writeLen = 11;

        for (size_t i = 0; i < writeLen; i++) {
            p[i] = s[i];
        }

        if (external()) {
            *reinterpret_cast<size_t *>(raw + 8) = writeLen;
        } else {
            raw[0x17] = (uint8_t)(writeLen & 0x7f); // 保持 bit7=0
        }
        return true;
    }
};

// ---------------------------------------------------------------------------
//  规则
// ---------------------------------------------------------------------------
struct RegexRule {
    std::regex re;
    std::string rep;
    std::string pattern; // 仅日志
};

static std::mutex g_mu;
static std::map<std::string, std::string> g_exact;
static std::vector<RegexRule> g_regex;
static std::string g_wallet;
static time_t g_cfg_mtime = 0;
static bool g_enabled = true;
static int g_hit_count = 0;

static NSString *configPath() {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/ibox_hook_rules.json"];
}

static void loadConfig(); // 前向声明

// ---------------------------------------------------------------------------
//  悬浮球拖动
// ---------------------------------------------------------------------------
@interface UIButton (IBoxFloatDrag)
- (void)ibox_handlePan:(UIPanGestureRecognizer *)pan;
@end

// ---------------------------------------------------------------------------
//  规则编辑面板
// ---------------------------------------------------------------------------
@interface RuleEditorPanel : UIViewController <UITextViewDelegate, UIScrollViewDelegate>
@property (nonatomic, strong) UIWindow *panelWindow;
@property (nonatomic, strong) UIScrollView *scroll;
@property (nonatomic, strong) UISwitch *enableSwitch;
@property (nonatomic, strong) UITextView *walletField;
@property (nonatomic, strong) UITextView *exactField;
@property (nonatomic, strong) UITextView *regexField;
@property (nonatomic, strong) UILabel *statusLabel;
@end

@implementation RuleEditorPanel

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithWhite:0.08 alpha:0.97];

    CGFloat W = self.view.bounds.size.width;
    CGFloat H = self.view.bounds.size.height;
    CGFloat pad = 16;
    CGFloat innerW = W - pad * 2;

    // 顶栏
    UIView *nav = [[UIView alloc] initWithFrame:CGRectMake(0, 0, W, 96)];
    nav.backgroundColor = [UIColor colorWithRed:0.12 green:0.14 blue:0.20 alpha:1.0];
    [self.view addSubview:nav];

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(pad, 48, innerW - 100, 36)];
    title.text = @"爱盒 Hook";
    title.textColor = [UIColor whiteColor];
    title.font = [UIFont boldSystemFontOfSize:22];
    [nav addSubview:title];

    UIButton *closeX = [UIButton buttonWithType:UIButtonTypeSystem];
    closeX.frame = CGRectMake(W - 60, 48, 44, 36);
    [closeX setTitle:@"✕" forState:UIControlStateNormal];
    closeX.titleLabel.font = [UIFont systemFontOfSize:22 weight:UIFontWeightMedium];
    [closeX setTitleColor:[UIColor colorWithWhite:0.85 alpha:1] forState:UIControlStateNormal];
    [closeX addTarget:self action:@selector(closePanel) forControlEvents:UIControlEventTouchUpInside];
    [nav addSubview:closeX];

    self.scroll = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 96, W, H - 96 - 80)];
    self.scroll.keyboardDismissMode = UIScrollViewKeyboardDismissModeOnDrag;
    self.scroll.alwaysBounceVertical = YES;
    [self.view addSubview:self.scroll];

    CGFloat y = 16;

    // 启用开关 + 状态
    UIView *row = [[UIView alloc] initWithFrame:CGRectMake(pad, y, innerW, 44)];
    row.backgroundColor = [UIColor colorWithWhite:0.15 alpha:1];
    row.layer.cornerRadius = 10;
    [self.scroll addSubview:row];

    UILabel *enLbl = [[UILabel alloc] initWithFrame:CGRectMake(14, 0, 120, 44)];
    enLbl.text = @"启用替换";
    enLbl.textColor = [UIColor whiteColor];
    enLbl.font = [UIFont systemFontOfSize:16 weight:UIFontWeightMedium];
    [row addSubview:enLbl];

    self.enableSwitch = [[UISwitch alloc] initWithFrame:CGRectZero];
    self.enableSwitch.onTintColor = [UIColor colorWithRed:0.20 green:0.55 blue:1.0 alpha:1.0];
    self.enableSwitch.center = CGPointMake(innerW - 40, 22);
    {
        std::lock_guard<std::mutex> lk(g_mu);
        self.enableSwitch.on = g_enabled;
    }
    [row addSubview:self.enableSwitch];
    y += 56;

    self.statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(pad, y, innerW, 20)];
    self.statusLabel.textColor = [UIColor colorWithWhite:0.55 alpha:1];
    self.statusLabel.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    {
        std::lock_guard<std::mutex> lk(g_mu);
        self.statusLabel.text = [NSString stringWithFormat:@"命中 %d 次 · RVA 0x%lx", g_hit_count, (unsigned long)RVA_ADDTEXT_BLR];
    }
    [self.scroll addSubview:self.statusLabel];
    y += 32;

    // 钱包
    [self addSectionLabel:@"钱包地址 (0x… 统一替换, 保持原长度)" atY:y width:innerW];
    y += 24;
    self.walletField = [self makeTextViewAtY:y width:innerW height:44];
    self.walletField.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightRegular];
    y += 56;

    // 精确
    [self addSectionLabel:@"精确/包含替换 (每行: 原文=>新文)" atY:y width:innerW];
    y += 24;
    self.exactField = [self makeTextViewAtY:y width:innerW height:180];
    y += 192;

    // 正则
    [self addSectionLabel:@"正则替换 (每行: pattern=>replace)" atY:y width:innerW];
    y += 24;
    self.regexField = [self makeTextViewAtY:y width:innerW height:150];
    y += 162;

    UILabel *tip = [[UILabel alloc] initWithFrame:CGRectMake(pad, y, innerW, 60)];
    tip.numberOfLines = 0;
    tip.textColor = [UIColor colorWithWhite:0.45 alpha:1];
    tip.font = [UIFont systemFontOfSize:12];
    tip.text = @"保存后立即生效。静态数字需重启 App 或重新进页触发 addText。\n截图/录屏时悬浮球自动隐藏。";
    [self.scroll addSubview:tip];
    y += 70;

    self.scroll.contentSize = CGSizeMake(W, y + 20);

    // 底栏
    UIView *bar = [[UIView alloc] initWithFrame:CGRectMake(0, H - 80, W, 80)];
    bar.backgroundColor = [UIColor colorWithWhite:0.1 alpha:1];
    [self.view addSubview:bar];

    UIButton *saveBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    saveBtn.frame = CGRectMake(pad, 12, (innerW - 12) / 2, 48);
    [saveBtn setTitle:@"保存生效" forState:UIControlStateNormal];
    saveBtn.titleLabel.font = [UIFont boldSystemFontOfSize:17];
    saveBtn.backgroundColor = [UIColor colorWithRed:0.18 green:0.52 blue:1.0 alpha:1.0];
    [saveBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    saveBtn.layer.cornerRadius = 12;
    [saveBtn addTarget:self action:@selector(saveAndClose) forControlEvents:UIControlEventTouchUpInside];
    [bar addSubview:saveBtn];

    UIButton *closeBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    closeBtn.frame = CGRectMake(pad + (innerW - 12) / 2 + 12, 12, (innerW - 12) / 2, 48);
    [closeBtn setTitle:@"关闭" forState:UIControlStateNormal];
    closeBtn.titleLabel.font = [UIFont boldSystemFontOfSize:17];
    closeBtn.backgroundColor = [UIColor colorWithWhite:0.25 alpha:1.0];
    [closeBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    closeBtn.layer.cornerRadius = 12;
    [closeBtn addTarget:self action:@selector(closePanel) forControlEvents:UIControlEventTouchUpInside];
    [bar addSubview:closeBtn];

    // 键盘避让
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(kb:)
                                                 name:UIKeyboardWillChangeFrameNotification
                                               object:nil];

    [self loadCurrentRules];
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (void)kb:(NSNotification *)n {
    CGRect end = [n.userInfo[UIKeyboardFrameEndUserInfoKey] CGRectValue];
    CGFloat kbH = MAX(0, self.view.bounds.size.height - end.origin.y);
    UIEdgeInsets inset = self.scroll.contentInset;
    inset.bottom = kbH;
    self.scroll.contentInset = inset;
    self.scroll.scrollIndicatorInsets = inset;
}

- (void)addSectionLabel:(NSString *)text atY:(CGFloat)y width:(CGFloat)w {
    UILabel *lbl = [[UILabel alloc] initWithFrame:CGRectMake(16, y, w, 20)];
    lbl.text = text;
    lbl.textColor = [UIColor colorWithWhite:0.7 alpha:1.0];
    lbl.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    [self.scroll addSubview:lbl];
}

- (UITextView *)makeTextViewAtY:(CGFloat)y width:(CGFloat)w height:(CGFloat)h {
    UITextView *tv = [[UITextView alloc] initWithFrame:CGRectMake(16, y, w, h)];
    tv.backgroundColor = [UIColor colorWithWhite:0.16 alpha:1.0];
    tv.textColor = [UIColor whiteColor];
    tv.font = [UIFont systemFontOfSize:14];
    tv.layer.cornerRadius = 10;
    tv.layer.borderWidth = 1;
    tv.layer.borderColor = [UIColor colorWithWhite:0.28 alpha:1.0].CGColor;
    tv.autocorrectionType = UITextAutocorrectionTypeNo;
    tv.autocapitalizationType = UITextAutocapitalizationTypeNone;
    tv.smartDashesType = UITextSmartDashesTypeNo;
    tv.smartQuotesType = UITextSmartQuotesTypeNo;
    tv.delegate = self;
    tv.textContainerInset = UIEdgeInsetsMake(10, 8, 10, 8);
    [self.scroll addSubview:tv];
    return tv;
}

- (void)loadCurrentRules {
    NSString *path = configPath();
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data) return;
    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (![json isKindOfClass:[NSDictionary class]]) return;

    self.walletField.text = json[@"wallet"] ?: @"";

    id en = json[@"enabled"];
    if ([en isKindOfClass:[NSNumber class]]) {
        self.enableSwitch.on = [(NSNumber *)en boolValue];
    }

    NSMutableArray *exactLines = [NSMutableArray array];
    NSDictionary *exact = json[@"exact"];
    if ([exact isKindOfClass:[NSDictionary class]]) {
        // 稳定顺序: 按 key 排序
        NSArray *keys = [[exact allKeys] sortedArrayUsingSelector:@selector(compare:)];
        for (NSString *k in keys) {
            [exactLines addObject:[NSString stringWithFormat:@"%@=>%@", k, exact[k]]];
        }
    }
    self.exactField.text = [exactLines componentsJoinedByString:@"\n"];

    NSMutableArray *regexLines = [NSMutableArray array];
    NSArray *regex = json[@"regex"];
    if ([regex isKindOfClass:[NSArray class]]) {
        for (NSDictionary *r in regex) {
            NSString *p = r[@"pattern"], *rep = r[@"replace"];
            if (p && rep) [regexLines addObject:[NSString stringWithFormat:@"%@=>%@", p, rep]];
        }
    }
    self.regexField.text = [regexLines componentsJoinedByString:@"\n"];
}

- (void)saveAndClose {
    NSMutableDictionary *json = [NSMutableDictionary dictionary];
    json[@"_说明"] = @"悬浮球编辑面板生成。exact=精确/包含, regex=正则, wallet=0x钱包(保长), enabled=总开关";
    json[@"enabled"] = @(self.enableSwitch.on);

    NSString *wallet = [self.walletField.text stringByTrimmingCharactersInSet:
                        [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (wallet.length > 0) json[@"wallet"] = wallet;

    NSMutableDictionary *exact = [NSMutableDictionary dictionary];
    for (NSString *line in [self.exactField.text componentsSeparatedByString:@"\n"]) {
        NSRange sep = [line rangeOfString:@"=>"];
        if (sep.location == NSNotFound) continue;
        NSString *k = [[line substringToIndex:sep.location]
                       stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        NSString *v = [[line substringFromIndex:sep.location + sep.length]
                       stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        if (k.length > 0) exact[k] = v ?: @"";
    }
    if (exact.count > 0) json[@"exact"] = exact;

    NSMutableArray *regex = [NSMutableArray array];
    for (NSString *line in [self.regexField.text componentsSeparatedByString:@"\n"]) {
        NSRange sep = [line rangeOfString:@"=>"];
        if (sep.location == NSNotFound) continue;
        NSString *p = [[line substringToIndex:sep.location]
                       stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        NSString *r = [[line substringFromIndex:sep.location + sep.length]
                       stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        if (p.length > 0) [regex addObject:@{@"pattern": p, @"replace": r ?: @""}];
    }
    if (regex.count > 0) json[@"regex"] = regex;

    NSData *data = [NSJSONSerialization dataWithJSONObject:json
                                                   options:NSJSONWritingPrettyPrinted
                                                     error:nil];
    [data writeToFile:configPath() atomically:YES];

    // 强制 mtime 变化后重载
    g_cfg_mtime = 0;
    loadConfig();

    LOG(@"规则已保存: 精确%lu 正则%lu 钱包%@ 启用%@",
        (unsigned long)exact.count,
        (unsigned long)regex.count,
        wallet.length > 0 ? wallet : @"无",
        self.enableSwitch.on ? @"YES" : @"NO");

    [self closePanel];
}

- (void)closePanel {
    [self.view endEditing:YES];
    [self.panelWindow resignKeyWindow];
    self.panelWindow.hidden = YES;
    self.panelWindow = nil;
}

+ (UIWindowScene *)activeScene API_AVAILABLE(ios(13.0)) {
    for (UIScene *sc in [UIApplication sharedApplication].connectedScenes) {
        if (sc.activationState != UISceneActivationStateForegroundActive &&
            sc.activationState != UISceneActivationStateForegroundInactive) continue;
        if ([sc isKindOfClass:[UIWindowScene class]]) return (UIWindowScene *)sc;
    }
    for (UIScene *sc in [UIApplication sharedApplication].connectedScenes) {
        if ([sc isKindOfClass:[UIWindowScene class]]) return (UIWindowScene *)sc;
    }
    return nil;
}

+ (UIWindow *)makeOverlayWindowWithFrame:(CGRect)frame {
    UIWindow *win = nil;
    if (@available(iOS 13.0, *)) {
        UIWindowScene *scene = [self activeScene];
        if (scene) {
            win = [[UIWindow alloc] initWithWindowScene:scene];
            win.frame = frame;
        }
    }
    if (!win) {
        win = [[UIWindow alloc] initWithFrame:frame];
    }
    return win;
}

+ (void)toggle {
    static RuleEditorPanel *instance = nil;
    if (instance && instance.panelWindow && !instance.panelWindow.hidden) {
        [instance closePanel];
        instance = nil;
        return;
    }

    instance = [[RuleEditorPanel alloc] init];
    UIWindow *win = [self makeOverlayWindowWithFrame:[UIScreen mainScreen].bounds];
    win.windowLevel = UIWindowLevelAlert + 300;
    win.rootViewController = instance;
    win.hidden = NO;
    instance.panelWindow = win;
    [win makeKeyAndVisible];
}

@end

// ---------------------------------------------------------------------------
//  UTF-16 <-> UTF-8
// ---------------------------------------------------------------------------
static std::string u16_to_u8(const std::u16string &s) {
    if (s.empty()) return {};
    NSString *ns = [[NSString alloc] initWithBytes:s.data()
                                            length:s.size() * sizeof(char16_t)
                                          encoding:NSUTF16LittleEndianStringEncoding];
    const char *c = [ns UTF8String];
    return c ? std::string(c) : std::string();
}

static std::u16string u8_to_u16(const std::string &s) {
    NSString *ns = [[NSString alloc] initWithUTF8String:s.c_str()];
    if (!ns) return u"";
    NSUInteger n = ns.length;
    std::u16string out;
    out.resize(n);
    for (NSUInteger i = 0; i < n; i++) {
        out[i] = (char16_t)[ns characterAtIndex:i];
    }
    return out;
}

// ---------------------------------------------------------------------------
//  默认配置模板 (对齐 frida_v6 验证规则)
// ---------------------------------------------------------------------------
static void writeTemplateIfNeeded() {
    NSString *path = configPath();
    if ([[NSFileManager defaultManager] fileExistsAtPath:path]) return;

    NSDictionary *tpl = @{
        @"_说明": @"exact=精确整串优先,其次包含替换; regex=正则; wallet=所有0x钱包(输出截断/填充到原长度); enabled=总开关。改完保存即生效,静态内容需重进页面。",
        @"enabled": @YES,
        @"exact": @{
            @"289":   @"999",
            @"2632":  @"9999",
            @"552":   @"999",
            @"16868": @"99999",
            @"28391": @"88888",
            @"1560":  @"3650",
            @"红苹果": @"非常牛逼"
        },
        @"regex": @[
            @{@"pattern": @"持有\\s*\\d+", @"replace": @"持有9999"},
            @{@"pattern": @"¥\\s*[\\d,.]+", @"replace": @"¥88888"}
        ],
        @"wallet": @"0x8888888888888888888888888888888888888888"
    };
    NSData *d = [NSJSONSerialization dataWithJSONObject:tpl
                                                options:NSJSONWritingPrettyPrinted
                                                  error:nil];
    [d writeToFile:path atomically:YES];
    LOG(@"已生成配置模板: %@", path);
}

static void loadConfig() {
    NSString *path = configPath();
    NSDictionary *attr = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
    time_t mtime = attr ? (time_t)[[attr fileModificationDate] timeIntervalSince1970] : 0;
    if (mtime != 0 && mtime == g_cfg_mtime) return;

    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data) return;

    NSError *err = nil;
    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&err];
    if (![json isKindOfClass:[NSDictionary class]]) {
        LOG(@"配置解析失败: %@", err);
        return;
    }

    std::map<std::string, std::string> exact;
    std::vector<RegexRule> regex;
    std::string wallet;
    bool enabled = true;

    id en = json[@"enabled"];
    if ([en isKindOfClass:[NSNumber class]]) enabled = [(NSNumber *)en boolValue];

    NSDictionary *ex = json[@"exact"];
    if ([ex isKindOfClass:[NSDictionary class]]) {
        for (NSString *k in ex) {
            id v = ex[k];
            if ([k isKindOfClass:[NSString class]] && [v isKindOfClass:[NSString class]]) {
                exact[[k UTF8String]] = [(NSString *)v UTF8String];
            }
        }
    }

    NSArray *rx = json[@"regex"];
    if ([rx isKindOfClass:[NSArray class]]) {
        for (NSDictionary *r in rx) {
            NSString *p = r[@"pattern"];
            NSString *rep = r[@"replace"];
            if (![p isKindOfClass:[NSString class]] || ![rep isKindOfClass:[NSString class]]) continue;
            try {
                RegexRule rule;
                rule.re = std::regex([p UTF8String]);
                rule.rep = std::string([rep UTF8String]);
                rule.pattern = std::string([p UTF8String]);
                regex.push_back(std::move(rule));
            } catch (const std::exception &e) {
                LOG(@"正则错误 %@: %s", p, e.what());
            }
        }
    }

    NSString *w = json[@"wallet"];
    if ([w isKindOfClass:[NSString class]]) wallet = [w UTF8String];

    size_t nExact = exact.size();
    size_t nRegex = regex.size();
    std::string walletLog = wallet.empty() ? std::string("无") : wallet;

    {
        std::lock_guard<std::mutex> lk(g_mu);
        g_exact = std::move(exact);
        g_regex = std::move(regex);
        g_wallet = std::move(wallet);
        g_enabled = enabled;
        g_cfg_mtime = mtime;
    }

    LOG(@"配置加载: 精确%lu 正则%lu 钱包%s 启用%d",
        (unsigned long)nExact, (unsigned long)nRegex,
        walletLog.c_str(), (int)enabled);
}

// ---------------------------------------------------------------------------
//  规则应用 (UTF-8 in/out)
// ---------------------------------------------------------------------------
static bool looksLikeWallet(const std::string &s) {
    // 0x + 至少 10 位 hex (跟 v6 一致)
    if (s.size() < 12) return false;
    if (s[0] != '0' || (s[1] != 'x' && s[1] != 'X')) return false;
    for (size_t i = 2; i < s.size(); i++) {
        char c = s[i];
        bool ok = (c >= '0' && c <= '9') ||
                  (c >= 'a' && c <= 'f') ||
                  (c >= 'A' && c <= 'F') ||
                  c == '*';
        if (!ok) return false;
    }
    return true;
}

// 钱包输出保长: 截断或用末尾字符填充
static std::string fitWallet(const std::string &tpl, size_t len) {
    if (tpl.size() == len) return tpl;
    if (tpl.size() > len) return tpl.substr(0, len);
    std::string out = tpl;
    char pad = tpl.empty() ? '8' : tpl.back();
    out.append(len - tpl.size(), pad);
    return out;
}

static bool applyRules(const std::string &in, std::string &out) {
    std::map<std::string, std::string> exact;
    std::vector<RegexRule> regex;
    std::string wallet;
    bool enabled = true;
    {
        std::lock_guard<std::mutex> lk(g_mu);
        if (!g_enabled) return false;
        exact = g_exact;
        regex = g_regex;
        wallet = g_wallet;
        enabled = g_enabled;
    }
    if (!enabled) return false;

    // 1) 精确整串
    auto it = exact.find(in);
    if (it != exact.end()) {
        out = it->second;
        return out != in;
    }

    // 2) 包含替换 (v6: text.indexOf(k) !== -1)
    //    长 key 优先, 避免短 key 误伤
    std::vector<std::pair<std::string, std::string>> pairs(exact.begin(), exact.end());
    std::sort(pairs.begin(), pairs.end(), [](const auto &a, const auto &b) {
        return a.first.size() > b.first.size();
    });
    for (auto &kv : pairs) {
        if (kv.first.empty()) continue;
        size_t pos = in.find(kv.first);
        if (pos != std::string::npos) {
            out = in;
            out.replace(pos, kv.first.size(), kv.second);
            return out != in;
        }
    }

    // 3) 钱包地址 (保长)
    if (!wallet.empty() && looksLikeWallet(in)) {
        out = fitWallet(wallet, in.size());
        return out != in;
    }

    // 4) 正则
    std::string cur = in;
    bool changed = false;
    for (auto &r : regex) {
        try {
            std::string res = std::regex_replace(cur, r.re, r.rep);
            if (res != cur) {
                cur = std::move(res);
                changed = true;
            }
        } catch (...) {
        }
    }
    if (changed) {
        out = cur;
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
//  文本替换核心: x1 = &UTF16Buf
// ---------------------------------------------------------------------------
static void rewriteAddTextBuf(uint64_t x1) {
    if (!x1) return;
    UTF16Buf *buf = (UTF16Buf *)x1;

    std::u16string u16;
    try {
        u16 = buf->get();
    } catch (...) {
        return;
    }
    if (u16.empty()) return;

    std::string u8 = u16_to_u8(u16);
    if (u8.empty()) return;

    std::string replaced;
    if (!applyRules(u8, replaced)) return;

    std::u16string nu16 = u8_to_u16(replaced);
    if (nu16.empty() && !replaced.empty()) return;

    if (buf->setInPlace(nu16)) {
        std::lock_guard<std::mutex> lk(g_mu);
        g_hit_count++;
    }
}

// ---------------------------------------------------------------------------
//  悬浮球
// ---------------------------------------------------------------------------
static UIWindow *g_floatWin = nil;
static UIButton *g_floatBtn = nil;
static BOOL g_userHiddenFloat = NO;

static void setFloatVisible(BOOL vis) {
    if (!g_floatWin) return;
    if (g_userHiddenFloat) {
        g_floatWin.hidden = YES;
        return;
    }
    g_floatWin.hidden = !vis;
}

static void installFloatingBall() {
    if (g_floatWin) return;

    CGFloat sw = [UIScreen mainScreen].bounds.size.width;
    CGRect frame = CGRectMake(sw - 70, 120, 56, 56);
    g_floatWin = [RuleEditorPanel makeOverlayWindowWithFrame:frame];
    g_floatWin.windowLevel = UIWindowLevelAlert + 200;
    g_floatWin.backgroundColor = [UIColor clearColor];
    g_floatWin.rootViewController = [[UIViewController alloc] init];
    g_floatWin.rootViewController.view.backgroundColor = [UIColor clearColor];
    g_floatWin.hidden = NO;

    g_floatBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    g_floatBtn.frame = CGRectMake(0, 0, 56, 56);
    g_floatBtn.backgroundColor = [UIColor colorWithRed:0.18 green:0.50 blue:0.98 alpha:0.88];
    g_floatBtn.layer.cornerRadius = 28;
    g_floatBtn.layer.shadowColor = [UIColor blackColor].CGColor;
    g_floatBtn.layer.shadowOpacity = 0.35;
    g_floatBtn.layer.shadowRadius = 6;
    g_floatBtn.layer.shadowOffset = CGSizeMake(0, 3);
    [g_floatBtn setTitle:@"爱盒" forState:UIControlStateNormal];
    g_floatBtn.titleLabel.font = [UIFont boldSystemFontOfSize:14];
    g_floatBtn.titleLabel.textAlignment = NSTextAlignmentCenter;
    [g_floatBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [g_floatBtn addTarget:[RuleEditorPanel class]
                   action:@selector(toggle)
         forControlEvents:UIControlEventTouchUpInside];
    [g_floatWin.rootViewController.view addSubview:g_floatBtn];

    UIPanGestureRecognizer *pan =
        [[UIPanGestureRecognizer alloc] initWithTarget:g_floatBtn action:@selector(ibox_handlePan:)];
    [g_floatBtn addGestureRecognizer:pan];
    objc_setAssociatedObject(g_floatBtn, "floatWin", g_floatWin, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    // 截图时隐藏
    [[NSNotificationCenter defaultCenter]
        addObserverForName:UIApplicationUserDidTakeScreenshotNotification
                    object:nil
                     queue:[NSOperationQueue mainQueue]
                usingBlock:^(__unused NSNotification *note) {
                    setFloatVisible(NO);
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2ull * NSEC_PER_SEC),
                                   dispatch_get_main_queue(), ^{
                                       setFloatVisible(YES);
                                   });
                }];

    // 录屏时隐藏
    if (@available(iOS 11.0, *)) {
        [NSTimer scheduledTimerWithTimeInterval:0.5
                                        repeats:YES
                                          block:^(__unused NSTimer *t) {
                                              BOOL recording = [UIScreen mainScreen].isCaptured;
                                              if (recording) {
                                                  setFloatVisible(NO);
                                              } else if (!g_userHiddenFloat) {
                                                  setFloatVisible(YES);
                                              }
                                          }];
    }

    LOG(@"悬浮球已就绪");
}

@implementation UIButton (IBoxFloatDrag)
- (void)ibox_handlePan:(UIPanGestureRecognizer *)pan {
    UIWindow *win = objc_getAssociatedObject(self, "floatWin");
    if (!win) return;
    CGPoint translation = [pan translationInView:win];
    CGRect f = win.frame;
    f.origin.x += translation.x;
    f.origin.y += translation.y;

    CGSize screen = [UIScreen mainScreen].bounds.size;
    CGFloat margin = 4;
    if (f.origin.x < margin) f.origin.x = margin;
    if (f.origin.y < margin + 40) f.origin.y = margin + 40;
    if (f.origin.x + f.size.width > screen.width - margin)
        f.origin.x = screen.width - margin - f.size.width;
    if (f.origin.y + f.size.height > screen.height - margin)
        f.origin.y = screen.height - margin - f.size.height;

    win.frame = f;
    [pan setTranslation:CGPointZero inView:win];
}
@end

// ---------------------------------------------------------------------------
//  找 Flutter base + 硬件断点目标
// ---------------------------------------------------------------------------
static uintptr_t findFlutterBase() {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        if (strstr(name, "Flutter.framework/Flutter") != nullptr) {
            return (uintptr_t)_dyld_get_image_header(i);
        }
    }
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        if (strstr(name, "Flutter.framework") != nullptr) {
            size_t len = strlen(name);
            if (len >= 7 && strcmp(name + len - 7, "Flutter") == 0) {
                return (uintptr_t)_dyld_get_image_header(i);
            }
        }
    }
    return 0;
}

static uintptr_t g_hook_addr = 0; // Flutter base + RVA, 原指令仍是 BLR X8
static _Atomic bool g_exc_ready = false;
static _Atomic bool g_hwbp_ok = false;

// 有的 SDK 不暴露 arm_debug_state64_t, 自己铺一份布局
#ifndef ARM_DEBUG_STATE64
#define ARM_DEBUG_STATE64 15
#endif
typedef struct {
    uint64_t __bvr[16];
    uint64_t __bcr[16];
    uint64_t __wvr[16];
    uint64_t __wcr[16];
    uint64_t __mdscr_el1;
} ibox_arm_debug_state64_t;
#define ARM_DEBUG_STATE64_COUNT ((mach_msg_type_number_t)(sizeof(ibox_arm_debug_state64_t) / sizeof(uint32_t)))

static bool ensureHookTarget() {
    if (g_hook_addr) return true;
    uintptr_t base = findFlutterBase();
    if (!base) return false;

    uintptr_t addr = base + RVA_ADDTEXT_BLR;
    uint32_t insn = *(volatile uint32_t *)addr;

    if (insn == INSN_BLR_X8) {
        g_hook_addr = addr;
        LOG(@"目标 BLR X8 @ %p (base=%p RVA=0x%lx)", (void *)addr, (void *)base,
            (unsigned long)RVA_ADDTEXT_BLR);
        return true;
    }
    // 兼容: 有人已经静态打过 BRK 也能吃
    if ((insn & 0xFFE0001F) == 0xD4200000) {
        g_hook_addr = addr;
        LOG(@"目标已是 BRK @ %p, 继续用异常处理", (void *)addr);
        return true;
    }
    LOG(@"警告: Flutter@%p 指令=%08x, 期望 BLR X8(%08x), 版本可能变了",
        (void *)addr, insn, INSN_BLR_X8);
    return false;
}

// 给单个线程装硬件断点 (不改代码页)
static bool setHwBpOnThread(thread_t thread) {
    if (!g_hook_addr) return false;

    ibox_arm_debug_state64_t ds;
    memset(&ds, 0, sizeof(ds));
    mach_msg_type_number_t cnt = ARM_DEBUG_STATE64_COUNT;
    kern_return_t kr = thread_get_state(thread, ARM_DEBUG_STATE64,
                                        (thread_state_t)&ds, &cnt);
    if (kr != KERN_SUCCESS) {
        // 有的线程拿不到 debug state, 不算致命
        return false;
    }

    // 已装过就跳过
    if (ds.__bvr[HWBP_SLOT] == (uint64_t)g_hook_addr &&
        (ds.__bcr[HWBP_SLOT] & 1ULL)) {
        return true;
    }

    ds.__bvr[HWBP_SLOT] = (uint64_t)g_hook_addr;
    ds.__bcr[HWBP_SLOT] = HWBP_BCR_ENABLE;

    cnt = ARM_DEBUG_STATE64_COUNT;
    kr = thread_set_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&ds, cnt);
    return kr == KERN_SUCCESS;
}

// 扫所有线程装 HWBP (新线程也会被定时器补上)
static int applyHwBpAllThreads() {
    if (!g_hook_addr) return 0;

    thread_act_array_t threads = nullptr;
    mach_msg_type_number_t count = 0;
    kern_return_t kr = task_threads(mach_task_self(), &threads, &count);
    if (kr != KERN_SUCCESS || !threads) return 0;

    int ok = 0;
    for (mach_msg_type_number_t i = 0; i < count; i++) {
        if (setHwBpOnThread(threads[i])) ok++;
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads,
                  sizeof(thread_t) * count);
    return ok;
}

// ---------------------------------------------------------------------------
//  EXC_BREAKPOINT 异常处理 (硬件断点命中, 不写代码页)
//  1) x1 做文本替换
//  2) 模拟 BLR X8: LR=PC+4, PC=X8
// ---------------------------------------------------------------------------
#pragma pack(push, 4)
typedef struct {
    mach_msg_header_t head;
    mach_msg_body_t msgh_body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t NDR;
    exception_type_t exception;
    mach_msg_type_number_t codeCnt;
    int64_t code[2];
} exc_request_t;

typedef struct {
    mach_msg_header_t head;
    NDR_record_t NDR;
    kern_return_t RetCode;
} exc_reply_t;
#pragma pack(pop)

static mach_port_t g_exc_port = MACH_PORT_NULL;

static inline uint64_t ts64_get_pc(const arm_thread_state64_t *s) {
#if defined(arm_thread_state64_get_pc)
    return (uint64_t)(uintptr_t)arm_thread_state64_get_pc(*s);
#else
    return (uint64_t)s->__pc;
#endif
}
static inline uint64_t ts64_get_x(const arm_thread_state64_t *s, int i) {
    return (uint64_t)s->__x[i];
}
static inline void ts64_set_pc(arm_thread_state64_t *s, uint64_t v) {
#if defined(arm_thread_state64_set_pc_fptr)
    arm_thread_state64_set_pc_fptr(*s, (void *)(uintptr_t)v);
#else
    s->__pc = v;
#endif
}
static inline void ts64_set_lr(arm_thread_state64_t *s, uint64_t v) {
#if defined(arm_thread_state64_set_lr_fptr)
    arm_thread_state64_set_lr_fptr(*s, (void *)(uintptr_t)v);
#else
    s->__lr = v;
#endif
}

static bool handle_breakpoint_thread(mach_port_t thread) {
    // 新线程可能还没 HWBP, 顺手补上
    setHwBpOnThread(thread);

    arm_thread_state64_t st;
    mach_msg_type_number_t cnt = ARM_THREAD_STATE64_COUNT;
    kern_return_t kr = thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&st, &cnt);
    if (kr != KERN_SUCCESS) return false;

    uint64_t pc = ts64_get_pc(&st);
    if (!g_hook_addr || (pc & ~0x3ULL) != (g_hook_addr & ~0x3ULL)) {
        return false;
    }

    uint64_t x1 = ts64_get_x(&st, 1);
    uint64_t x8 = ts64_get_x(&st, 8);

    rewriteAddTextBuf(x1);

    // 模拟 BLR X8 (指令本身没执行, 硬件断点在执行前触发)
    if (x8 == 0) {
        ts64_set_pc(&st, pc + 4);
    } else {
        ts64_set_lr(&st, pc + 4);
        ts64_set_pc(&st, x8);
    }

    cnt = ARM_THREAD_STATE64_COUNT;
    kr = thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t)&st, cnt);
    return kr == KERN_SUCCESS;
}

static void *exc_server_thread(void *arg) {
    (void)arg;
    LOG(@"异常处理线程启动 (HWBP)");

    for (;;) {
        uint8_t storage[2048];
        memset(storage, 0, sizeof(storage));
        mach_msg_header_t *hdr = (mach_msg_header_t *)storage;

        kern_return_t kr = mach_msg(hdr,
                                    MACH_RCV_MSG,
                                    0,
                                    sizeof(storage),
                                    g_exc_port,
                                    MACH_MSG_TIMEOUT_NONE,
                                    MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) {
            LOG(@"mach_msg rcv 失败: %d", kr);
            continue;
        }

        exc_request_t *req = (exc_request_t *)storage;
        bool handled = false;

        if (req->exception == EXC_BREAKPOINT) {
            if (!g_hook_addr) ensureHookTarget();
            handled = handle_breakpoint_thread(req->thread.name);
        }

        exc_reply_t reply;
        memset(&reply, 0, sizeof(reply));
        reply.head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(hdr->msgh_bits), 0);
        reply.head.msgh_remote_port = hdr->msgh_remote_port;
        reply.head.msgh_local_port = MACH_PORT_NULL;
        reply.head.msgh_size = sizeof(reply);
        reply.head.msgh_id = hdr->msgh_id + 100;
        reply.NDR = NDR_record;
        reply.RetCode = handled ? KERN_SUCCESS : KERN_FAILURE;

        mach_msg(&reply.head, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                 sizeof(reply), 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
    }
    return NULL;
}

static bool installExceptionHandler() {
    if (atomic_load(&g_exc_ready)) return true;
    if (!ensureHookTarget()) {
        LOG(@"Hook 目标未就绪, 稍后重试");
        return false;
    }

    kern_return_t kr;
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &g_exc_port);
    if (kr != KERN_SUCCESS) {
        LOG(@"mach_port_allocate 失败: %d", kr);
        return false;
    }
    kr = mach_port_insert_right(mach_task_self(), g_exc_port, g_exc_port, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        LOG(@"mach_port_insert_right 失败: %d", kr);
        return false;
    }

    // 抢 BREAKPOINT (硬件断点 / BRK 都走这)
    kr = task_set_exception_ports(mach_task_self(),
                                  EXC_MASK_BREAKPOINT,
                                  g_exc_port,
                                  (exception_behavior_t)(EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES),
                                  ARM_THREAD_STATE64);
    if (kr != KERN_SUCCESS) {
        LOG(@"task_set_exception_ports 失败: %d", kr);
        return false;
    }

    pthread_t th;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int pe = pthread_create(&th, &attr, exc_server_thread, NULL);
    pthread_attr_destroy(&attr);
    if (pe != 0) {
        LOG(@"pthread_create 失败: %d", pe);
        return false;
    }

    atomic_store(&g_exc_ready, true);
    LOG(@"EXC_BREAKPOINT 已安装");
    return true;
}

static bool installHardwareBreakpoint() {
    if (!ensureHookTarget()) return false;
    if (!atomic_load(&g_exc_ready)) {
        if (!installExceptionHandler()) return false;
    }

    int n = applyHwBpAllThreads();
    if (n > 0) {
        atomic_store(&g_hwbp_ok, true);
        LOG(@"硬件断点已打到 %d 个线程 @ %p", n, (void *)g_hook_addr);
        return true;
    }
    LOG(@"硬件断点 thread_set_state 全失败 (可能被系统拒)");
    return false;
}

static void onImageAdded(const struct mach_header *mh, intptr_t slide) {
    (void)mh;
    (void)slide;
    if (!atomic_load(&g_hwbp_ok)) {
        installHardwareBreakpoint();
    } else {
        applyHwBpAllThreads();
    }
}

// ---------------------------------------------------------------------------
//  入口
// ---------------------------------------------------------------------------
__attribute__((constructor))
static void ibox_hook_init() {
    LOG(@"加载中... build v4 (HWBP, 单dylib, 不patch Flutter)");

    writeTemplateIfNeeded();
    loadConfig();

    // 热更新配置
    dispatch_source_t cfgTimer =
        dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                               dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0));
    dispatch_source_set_timer(cfgTimer, dispatch_time(DISPATCH_TIME_NOW, 2ull * NSEC_PER_SEC),
                              2ull * NSEC_PER_SEC, 200ull * NSEC_PER_MSEC);
    dispatch_source_set_event_handler(cfgTimer, ^{ loadConfig(); });
    dispatch_resume(cfgTimer);

    // 硬件断点 + 异常处理 (只注入 dylib, 不碰 Flutter 文件)
    auto tryInstall = ^{
        if (!atomic_load(&g_hwbp_ok)) {
            installHardwareBreakpoint();
        } else {
            applyHwBpAllThreads(); // 补新线程
        }
    };
    tryInstall();
    _dyld_register_func_for_add_image(onImageAdded);

    // 延迟再试 + 周期补新线程 (Flutter UI 线程可能后起)
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1ull * NSEC_PER_SEC),
                   dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), tryInstall);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3ull * NSEC_PER_SEC),
                   dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), tryInstall);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 8ull * NSEC_PER_SEC),
                   dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), tryInstall);

    dispatch_source_t bpTimer =
        dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                               dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
    dispatch_source_set_timer(bpTimer, dispatch_time(DISPATCH_TIME_NOW, 5ull * NSEC_PER_SEC),
                              3ull * NSEC_PER_SEC, 500ull * NSEC_PER_MSEC);
    dispatch_source_set_event_handler(bpTimer, ^{
        if (g_hook_addr) applyHwBpAllThreads();
    });
    dispatch_resume(bpTimer);

    // 悬浮球
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 4ull * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{
                       installFloatingBall();
                   });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 10ull * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{
                       if (!g_floatWin) installFloatingBall();
                   });
}
