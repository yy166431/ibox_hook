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
//  作者: 海鸥
// ============================================================================
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <algorithm>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <regex>
#include "dobby.h"

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
//  Hook 回调: 0x481ca8 blr x8 前, x1 = &UTF16Buf
// ---------------------------------------------------------------------------
static void onAddText(void *address, DobbyRegisterContext *ctx) {
    (void)address;
    UTF16Buf *buf = (UTF16Buf *)ctx->general.regs.x1;
    if (!buf) return;

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
//  找 Flutter base
// ---------------------------------------------------------------------------
static uintptr_t findFlutterBase() {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        // Flutter.framework/Flutter 或末尾 /Flutter
        if (strstr(name, "Flutter.framework/Flutter") != nullptr) {
            return (uintptr_t)_dyld_get_image_header(i);
        }
    }
    // 兜底: 有的包路径大小写/符号链接不同
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        size_t len = strlen(name);
        if (len >= 7 && strcmp(name + len - 7, "Flutter") == 0) {
            // 排除 App 自己叫 Flutter 的极端情况: 必须带 framework
            if (strstr(name, "Flutter.framework") || strstr(name, "Flutter.framework")) {
                return (uintptr_t)_dyld_get_image_header(i);
            }
        }
    }
    return 0;
}

static void tryInstallHook() {
    static bool installed = false;
    if (installed) return;

    uintptr_t base = findFlutterBase();
    if (!base) {
        LOG(@"Flutter.framework 尚未加载, 稍后重试");
        return;
    }

    void *target = (void *)(base + RVA_ADDTEXT_BLR);
    int r = DobbyInstrument(target, onAddText);
    LOG(@"Hook @ %p (base=%p RVA=0x%lx) 结果=%d", target, (void *)base, (unsigned long)RVA_ADDTEXT_BLR, r);
    if (r == 0) {
        installed = true;
        LOG(@"Hook 安装成功, 开干");
    } else {
        LOG(@"Hook 失败 code=%d", r);
    }
}

// dyld 镜像加载回调: Flutter 可能比我们晚加载
static void onImageAdded(const struct mach_header *mh, intptr_t slide) {
    (void)mh;
    (void)slide;
    tryInstallHook();
}

// ---------------------------------------------------------------------------
//  入口
// ---------------------------------------------------------------------------
__attribute__((constructor))
static void ibox_hook_init() {
    LOG(@"加载中... build v2 (inplace-v6)");

    writeTemplateIfNeeded();
    loadConfig();

    // 热更新配置
    dispatch_source_t timer =
        dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                               dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0));
    dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW, 2ull * NSEC_PER_SEC),
                              2ull * NSEC_PER_SEC, 200ull * NSEC_PER_MSEC);
    dispatch_source_set_event_handler(timer, ^{ loadConfig(); });
    dispatch_resume(timer);

    // 立刻试一次 + 监听后续镜像
    tryInstallHook();
    _dyld_register_func_for_add_image(onImageAdded);

    // 延迟挂悬浮球, 等 UIApplication/Scene 起来
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 4ull * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{
                       installFloatingBall();
                   });
    // 再兜底一次, 防止第一次 scene 还没好
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 10ull * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{
                       if (!g_floatWin) installFloatingBall();
                   });
}
