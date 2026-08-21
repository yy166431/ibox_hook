// ============================================================================
//  ibox_hook v5 — 爱盒(com.aihe.abc) Flutter 文本修改器
//  单 dylib 注入, 轻松签即用, 不 patch Flutter。
//
//  iOS 26: 禁止 runtime 改 __TEXT (CODESIGNING/Invalid Page)。
//  方案: ARM_DEBUG_STATE64 硬件断点 + EXC_BREAKPOINT。
//  热路径: 纯 C, 无 ObjC / mutex / malloc / regex (防异常死锁 0x8BADF00D)。
//
//  Hook: Flutter.framework RVA 0x481ca8  BLR X8, x1=&UTF16Buf
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
#include <stdlib.h>
#include <stdatomic.h>
#include <algorithm>
#include <string>
#include <vector>
#include <map>
#include <mutex>

#define TAG "[ibox_hook] "
static inline void LOG(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"%@%@", @TAG, s);
}

static const uintptr_t RVA_ADDTEXT_BLR = 0x481ca8;
static const uint32_t  INSN_BLR_X8     = 0xD63F0100;
// DBGBCR_EL1: E=1 | PMC=EL0(0b10<<1=0x4) | BAS=0xFF<<5(=0x1FE0) => 0x1FE5
static const uint64_t  HWBP_BCR_ENABLE = 0x1FE5ULL;
static const int       HWBP_SLOT       = 0;

// ============================ 热路径规则快照 ============================
struct ExactRuleU16 {
    char16_t *from;
    char16_t *to;
    uint16_t fromLen;
    uint16_t toLen;
};
struct RuleSnap {
    ExactRuleU16 *exact;
    size_t exactCount;
    char16_t *wallet;
    uint16_t walletLen;
    bool enabled;
};

static std::mutex g_mu;
static std::map<std::string, std::string> g_exact_utf8;
static std::string g_wallet_utf8;
static time_t g_cfg_mtime = 0;
static bool g_enabled = true;
static int g_hit_count = 0;
static _Atomic(RuleSnap *) g_snap = nullptr;

static char16_t *u8_to_u16_heap(const char *u8, uint16_t *outLen) {
    *outLen = 0;
    if (!u8) return nullptr;
    NSString *ns = [[NSString alloc] initWithUTF8String:u8];
    if (!ns) return nullptr;
    NSUInteger n = ns.length;
    if (n > 4096) n = 4096;
    char16_t *buf = (char16_t *)malloc((n + 1) * sizeof(char16_t));
    if (!buf) return nullptr;
    for (NSUInteger i = 0; i < n; i++) buf[i] = (char16_t)[ns characterAtIndex:i];
    buf[n] = 0;
    *outLen = (uint16_t)n;
    return buf;
}

static void publishSnap(const std::map<std::string, std::string> &exact,
                        const std::string &wallet, bool enabled) {
    std::vector<std::pair<std::string, std::string>> pairs(exact.begin(), exact.end());
    std::sort(pairs.begin(), pairs.end(), [](const auto &a, const auto &b) {
        return a.first.size() > b.first.size();
    });

    RuleSnap *s = (RuleSnap *)calloc(1, sizeof(RuleSnap));
    if (!s) return;
    s->enabled = enabled;
    s->exactCount = pairs.size();
    if (s->exactCount) {
        s->exact = (ExactRuleU16 *)calloc(s->exactCount, sizeof(ExactRuleU16));
        for (size_t i = 0; i < pairs.size(); i++) {
            s->exact[i].from = u8_to_u16_heap(pairs[i].first.c_str(), &s->exact[i].fromLen);
            s->exact[i].to   = u8_to_u16_heap(pairs[i].second.c_str(), &s->exact[i].toLen);
        }
    }
    if (!wallet.empty()) s->wallet = u8_to_u16_heap(wallet.c_str(), &s->walletLen);

    (void)atomic_exchange(&g_snap, s); // 旧快照不 free (异常线程可能还在读)

    std::lock_guard<std::mutex> lk(g_mu);
    g_exact_utf8 = exact;
    g_wallet_utf8 = wallet;
    g_enabled = enabled;
}

// ============================ UTF16Buf (纯C) ============================
struct UTF16Buf {
    uint8_t raw[0x18];
    uint8_t flag() const { return raw[0x17]; }
    bool external() const { return (flag() & 0x80) != 0; }
    char16_t *dataPtr() {
        return external() ? *reinterpret_cast<char16_t **>(raw)
                          : reinterpret_cast<char16_t *>(raw);
    }
    size_t length() const {
        return external() ? *reinterpret_cast<const size_t *>(raw + 8)
                          : (size_t)(flag() & 0x7f);
    }
    size_t capacity() const {
        return external() ? *reinterpret_cast<const size_t *>(raw + 0x10) : 11;
    }
    bool setInPlaceChars(const char16_t *s, size_t n) {
        char16_t *p = dataPtr();
        if (!p || !s) return false;
        size_t cap = capacity();
        if (cap == 0) { cap = length(); if (!cap) cap = 1; }
        size_t w = n;
        if (w > cap) w = cap;
        if (!external() && w > 11) w = 11;
        for (size_t i = 0; i < w; i++) p[i] = s[i];
        if (external()) *reinterpret_cast<size_t *>(raw + 8) = w;
        else raw[0x17] = (uint8_t)(w & 0x7f);
        return true;
    }
};

static inline bool u16_eq(const char16_t *a, size_t al, const char16_t *b, size_t bl) {
    if (al != bl) return false;
    for (size_t i = 0; i < al; i++) if (a[i] != b[i]) return false;
    return true;
}
static inline int u16_find(const char16_t *h, size_t hl, const char16_t *n, size_t nl) {
    if (!n || !nl || nl > hl) return -1;
    for (size_t i = 0; i + nl <= hl; i++) {
        size_t j = 0;
        for (; j < nl; j++) if (h[i + j] != n[j]) break;
        if (j == nl) return (int)i;
    }
    return -1;
}
static inline bool looksLikeWalletU16(const char16_t *s, size_t n) {
    if (n < 12 || s[0] != u'0' || (s[1] != u'x' && s[1] != u'X')) return false;
    for (size_t i = 2; i < n; i++) {
        char16_t c = s[i];
        if (!((c >= u'0' && c <= u'9') || (c >= u'a' && c <= u'f') ||
              (c >= u'A' && c <= u'F') || c == u'*')) return false;
    }
    return true;
}

// ★ 异常热路径: 禁止 ObjC / mutex / malloc / regex / LOG
static void rewriteAddTextBuf(uint64_t x1) {
    if (!x1) return;
    RuleSnap *snap = atomic_load(&g_snap);
    if (!snap || !snap->enabled) return;

    UTF16Buf *buf = (UTF16Buf *)x1;
    char16_t *p = buf->dataPtr();
    size_t n = buf->length();
    if (!p || n == 0 || n > 4096) return;

    for (size_t i = 0; i < snap->exactCount; i++) {
        ExactRuleU16 *r = &snap->exact[i];
        if (!r->from || !r->to) continue;
        if (u16_eq(p, n, r->from, r->fromLen)) {
            if (buf->setInPlaceChars(r->to, r->toLen))
                __atomic_add_fetch(&g_hit_count, 1, __ATOMIC_RELAXED);
            return;
        }
    }
    for (size_t i = 0; i < snap->exactCount; i++) {
        ExactRuleU16 *r = &snap->exact[i];
        if (!r->from || !r->to || !r->fromLen) continue;
        int pos = u16_find(p, n, r->from, r->fromLen);
        if (pos < 0) continue;
        char16_t tmp[512];
        size_t head = (size_t)pos;
        size_t tail = n - head - r->fromLen;
        size_t total = head + r->toLen + tail;
        if (total > 512) total = 512;
        size_t o = 0;
        for (size_t k = 0; k < head && o < total; k++) tmp[o++] = p[k];
        for (size_t k = 0; k < r->toLen && o < total; k++) tmp[o++] = r->to[k];
        for (size_t k = 0; k < tail && o < total; k++) tmp[o++] = p[head + r->fromLen + k];
        if (buf->setInPlaceChars(tmp, o))
            __atomic_add_fetch(&g_hit_count, 1, __ATOMIC_RELAXED);
        return;
    }
    if (snap->wallet && snap->walletLen && looksLikeWalletU16(p, n)) {
        char16_t tmp[128];
        size_t outN = n > 128 ? 128 : n;
        size_t copy = snap->walletLen < outN ? snap->walletLen : outN;
        for (size_t i = 0; i < copy; i++) tmp[i] = snap->wallet[i];
        char16_t pad = snap->wallet[snap->walletLen - 1];
        for (size_t i = copy; i < outN; i++) tmp[i] = pad;
        if (buf->setInPlaceChars(tmp, outN))
            __atomic_add_fetch(&g_hit_count, 1, __ATOMIC_RELAXED);
    }
}

// ============================ 配置 ============================
static NSString *configPath() {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/ibox_hook_rules.json"];
}
static void loadConfig();

static void writeTemplateIfNeeded() {
    NSString *path = configPath();
    if ([[NSFileManager defaultManager] fileExistsAtPath:path]) return;
    NSDictionary *tpl = @{
        @"_说明": @"exact=精确/包含; wallet=0x保长; enabled。正则字段仅作备注,热路径用exact。",
        @"enabled": @YES,
        @"exact": @{
            @"289": @"999", @"2632": @"9999", @"552": @"999",
            @"16868": @"99999", @"28391": @"88888", @"1560": @"3650",
            @"红苹果": @"非常牛逼",
            @"持有": @"持有9999" // 包含匹配兜底; 用户可改更精确
        },
        @"wallet": @"0x8888888888888888888888888888888888888888"
    };
    NSData *d = [NSJSONSerialization dataWithJSONObject:tpl
                                                options:NSJSONWritingPrettyPrinted error:nil];
    [d writeToFile:path atomically:YES];
    LOG(@"配置模板: %@", path);
}

static void loadConfig() {
    NSString *path = configPath();
    NSDictionary *attr = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
    time_t mtime = attr ? (time_t)[[attr fileModificationDate] timeIntervalSince1970] : 0;
    if (mtime != 0 && mtime == g_cfg_mtime) return;
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data) return;
    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (![json isKindOfClass:[NSDictionary class]]) return;

    std::map<std::string, std::string> exact;
    std::string wallet;
    bool enabled = true;
    id en = json[@"enabled"];
    if ([en isKindOfClass:[NSNumber class]]) enabled = [(NSNumber *)en boolValue];
    NSDictionary *ex = json[@"exact"];
    if ([ex isKindOfClass:[NSDictionary class]]) {
        for (NSString *k in ex) {
            id v = ex[k];
            if ([k isKindOfClass:[NSString class]] && [v isKindOfClass:[NSString class]])
                exact[[k UTF8String]] = [(NSString *)v UTF8String];
        }
    }
    // 无元字符的 regex 当 exact
    NSArray *rx = json[@"regex"];
    if ([rx isKindOfClass:[NSArray class]]) {
        NSCharacterSet *meta = [NSCharacterSet characterSetWithCharactersInString:@"\\.*+?[](){}^$|"];
        for (NSDictionary *r in rx) {
            NSString *p = r[@"pattern"], *rep = r[@"replace"];
            if (![p isKindOfClass:[NSString class]] || ![rep isKindOfClass:[NSString class]]) continue;
            if ([p rangeOfCharacterFromSet:meta].location == NSNotFound)
                exact[[p UTF8String]] = [rep UTF8String];
        }
    }
    NSString *w = json[@"wallet"];
    if ([w isKindOfClass:[NSString class]]) wallet = [w UTF8String];

    g_cfg_mtime = mtime;
    publishSnap(exact, wallet, enabled);
    LOG(@"配置: exact%lu wallet%s en%d",
        (unsigned long)exact.size(), wallet.empty() ? "无" : "有", (int)enabled);
}

// ============================ UI ============================
@interface UIButton (IBoxFloatDrag)
- (void)ibox_handlePan:(UIPanGestureRecognizer *)pan;
@end

@interface RuleEditorPanel : UIViewController <UITextViewDelegate>
@property (nonatomic, strong) UIWindow *panelWindow;
@property (nonatomic, strong) UIScrollView *scroll;
@property (nonatomic, strong) UISwitch *enableSwitch;
@property (nonatomic, strong) UITextView *walletField;
@property (nonatomic, strong) UITextView *exactField;
@property (nonatomic, strong) UILabel *statusLabel;
@end

@implementation RuleEditorPanel
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithWhite:0.08 alpha:0.97];
    CGFloat W = self.view.bounds.size.width, H = self.view.bounds.size.height, pad = 16, innerW = W - 32;

    UIView *nav = [[UIView alloc] initWithFrame:CGRectMake(0, 0, W, 96)];
    nav.backgroundColor = [UIColor colorWithRed:0.12 green:0.14 blue:0.20 alpha:1];
    [self.view addSubview:nav];
    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(pad, 48, innerW - 80, 36)];
    title.text = @"爱盒 Hook"; title.textColor = UIColor.whiteColor;
    title.font = [UIFont boldSystemFontOfSize:22];
    [nav addSubview:title];
    UIButton *x = [UIButton buttonWithType:UIButtonTypeSystem];
    x.frame = CGRectMake(W - 60, 48, 44, 36);
    [x setTitle:@"✕" forState:UIControlStateNormal];
    [x setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [x addTarget:self action:@selector(closePanel) forControlEvents:UIControlEventTouchUpInside];
    [nav addSubview:x];

    self.scroll = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 96, W, H - 96 - 80)];
    self.scroll.keyboardDismissMode = UIScrollViewKeyboardDismissModeOnDrag;
    [self.view addSubview:self.scroll];
    CGFloat y = 16;

    UIView *row = [[UIView alloc] initWithFrame:CGRectMake(pad, y, innerW, 44)];
    row.backgroundColor = [UIColor colorWithWhite:0.15 alpha:1]; row.layer.cornerRadius = 10;
    [self.scroll addSubview:row];
    UILabel *en = [[UILabel alloc] initWithFrame:CGRectMake(14, 0, 120, 44)];
    en.text = @"启用替换"; en.textColor = UIColor.whiteColor;
    [row addSubview:en];
    self.enableSwitch = [UISwitch new];
    self.enableSwitch.center = CGPointMake(innerW - 40, 22);
    { std::lock_guard<std::mutex> lk(g_mu); self.enableSwitch.on = g_enabled; }
    [row addSubview:self.enableSwitch];
    y += 56;

    self.statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(pad, y, innerW, 20)];
    self.statusLabel.textColor = [UIColor colorWithWhite:0.55 alpha:1];
    self.statusLabel.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    self.statusLabel.text = [NSString stringWithFormat:@"命中 %d · HWBP 0x%lx",
        __atomic_load_n(&g_hit_count, __ATOMIC_RELAXED), (unsigned long)RVA_ADDTEXT_BLR];
    [self.scroll addSubview:self.statusLabel];
    y += 32;

    UILabel *wl = [[UILabel alloc] initWithFrame:CGRectMake(pad, y, innerW, 20)];
    wl.text = @"钱包 (0x… 保长)"; wl.textColor = [UIColor colorWithWhite:0.7 alpha:1];
    wl.font = [UIFont systemFontOfSize:13]; [self.scroll addSubview:wl]; y += 24;
    self.walletField = [self tv:CGRectMake(pad, y, innerW, 44)]; y += 56;

    UILabel *el = [[UILabel alloc] initWithFrame:CGRectMake(pad, y, innerW, 20)];
    el.text = @"精确/包含 (原文=>新文 每行一条)"; el.textColor = [UIColor colorWithWhite:0.7 alpha:1];
    el.font = [UIFont systemFontOfSize:13]; [self.scroll addSubview:el]; y += 24;
    self.exactField = [self tv:CGRectMake(pad, y, innerW, 220)]; y += 240;

    self.scroll.contentSize = CGSizeMake(W, y + 20);

    UIView *bar = [[UIView alloc] initWithFrame:CGRectMake(0, H - 80, W, 80)];
    bar.backgroundColor = [UIColor colorWithWhite:0.1 alpha:1];
    [self.view addSubview:bar];
    UIButton *save = [UIButton buttonWithType:UIButtonTypeSystem];
    save.frame = CGRectMake(pad, 12, (innerW - 12) / 2, 48);
    [save setTitle:@"保存生效" forState:UIControlStateNormal];
    save.backgroundColor = [UIColor colorWithRed:0.18 green:0.52 blue:1 alpha:1];
    [save setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    save.layer.cornerRadius = 12;
    [save addTarget:self action:@selector(saveAndClose) forControlEvents:UIControlEventTouchUpInside];
    [bar addSubview:save];
    UIButton *cls = [UIButton buttonWithType:UIButtonTypeSystem];
    cls.frame = CGRectMake(pad + (innerW - 12) / 2 + 12, 12, (innerW - 12) / 2, 48);
    [cls setTitle:@"关闭" forState:UIControlStateNormal];
    cls.backgroundColor = [UIColor colorWithWhite:0.25 alpha:1];
    [cls setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    cls.layer.cornerRadius = 12;
    [cls addTarget:self action:@selector(closePanel) forControlEvents:UIControlEventTouchUpInside];
    [bar addSubview:cls];

    [self loadCurrentRules];
}
- (UITextView *)tv:(CGRect)f {
    UITextView *t = [[UITextView alloc] initWithFrame:f];
    t.backgroundColor = [UIColor colorWithWhite:0.16 alpha:1];
    t.textColor = UIColor.whiteColor; t.font = [UIFont systemFontOfSize:14];
    t.layer.cornerRadius = 10; t.autocorrectionType = UITextAutocorrectionTypeNo;
    t.autocapitalizationType = UITextAutocapitalizationTypeNone;
    t.delegate = self; [self.scroll addSubview:t]; return t;
}
- (void)loadCurrentRules {
    NSData *data = [NSData dataWithContentsOfFile:configPath()];
    if (!data) return;
    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (![json isKindOfClass:[NSDictionary class]]) return;
    self.walletField.text = json[@"wallet"] ?: @"";
    id en = json[@"enabled"];
    if ([en isKindOfClass:[NSNumber class]]) self.enableSwitch.on = [en boolValue];
    NSMutableArray *lines = [NSMutableArray array];
    NSDictionary *exact = json[@"exact"];
    if ([exact isKindOfClass:[NSDictionary class]]) {
        for (NSString *k in [[exact allKeys] sortedArrayUsingSelector:@selector(compare:)])
            [lines addObject:[NSString stringWithFormat:@"%@=>%@", k, exact[k]]];
    }
    self.exactField.text = [lines componentsJoinedByString:@"\n"];
}
- (void)saveAndClose {
    NSMutableDictionary *json = [NSMutableDictionary dictionary];
    json[@"enabled"] = @(self.enableSwitch.on);
    NSString *wallet = [self.walletField.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (wallet.length) json[@"wallet"] = wallet;
    NSMutableDictionary *exact = [NSMutableDictionary dictionary];
    for (NSString *line in [self.exactField.text componentsSeparatedByString:@"\n"]) {
        NSRange sep = [line rangeOfString:@"=>"];
        if (sep.location == NSNotFound) continue;
        NSString *k = [[line substringToIndex:sep.location] stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        NSString *v = [[line substringFromIndex:sep.location + 2] stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        if (k.length) exact[k] = v ?: @"";
    }
    if (exact.count) json[@"exact"] = exact;
    [[NSJSONSerialization dataWithJSONObject:json options:NSJSONWritingPrettyPrinted error:nil]
        writeToFile:configPath() atomically:YES];
    g_cfg_mtime = 0; loadConfig();
    [self closePanel];
}
- (void)closePanel {
    [self.view endEditing:YES];
    self.panelWindow.hidden = YES; self.panelWindow = nil;
}
+ (UIWindow *)makeWin:(CGRect)frame {
    UIWindow *w = nil;
    if (@available(iOS 13.0, *)) {
        for (UIScene *sc in UIApplication.sharedApplication.connectedScenes) {
            if ([sc isKindOfClass:UIWindowScene.class]) {
                w = [[UIWindow alloc] initWithWindowScene:(UIWindowScene *)sc];
                w.frame = frame; break;
            }
        }
    }
    if (!w) w = [[UIWindow alloc] initWithFrame:frame];
    return w;
}
+ (void)toggle {
    static RuleEditorPanel *inst;
    if (inst && inst.panelWindow && !inst.panelWindow.hidden) { [inst closePanel]; inst = nil; return; }
    inst = [RuleEditorPanel new];
    UIWindow *w = [self makeWin:UIScreen.mainScreen.bounds];
    w.windowLevel = UIWindowLevelAlert + 300;
    w.rootViewController = inst; inst.panelWindow = w;
    w.hidden = NO; [w makeKeyAndVisible];
}
@end

static UIWindow *g_floatWin;
static UIButton *g_floatBtn;
static BOOL g_userHiddenFloat;

static void setFloatVisible(BOOL vis) {
    if (!g_floatWin) return;
    g_floatWin.hidden = g_userHiddenFloat ? YES : !vis;
}
static void installFloatingBall() {
    if (g_floatWin) return;
    CGFloat sw = UIScreen.mainScreen.bounds.size.width;
    g_floatWin = [RuleEditorPanel makeWin:CGRectMake(sw - 70, 120, 56, 56)];
    g_floatWin.windowLevel = UIWindowLevelAlert + 200;
    g_floatWin.backgroundColor = UIColor.clearColor;
    g_floatWin.rootViewController = [UIViewController new];
    g_floatWin.rootViewController.view.backgroundColor = UIColor.clearColor;
    g_floatWin.hidden = NO;

    g_floatBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    g_floatBtn.frame = CGRectMake(0, 0, 56, 56);
    g_floatBtn.backgroundColor = [UIColor colorWithRed:0.18 green:0.50 blue:0.98 alpha:0.88];
    g_floatBtn.layer.cornerRadius = 28;
    [g_floatBtn setTitle:@"爱盒" forState:UIControlStateNormal];
    g_floatBtn.titleLabel.font = [UIFont boldSystemFontOfSize:14];
    [g_floatBtn addTarget:RuleEditorPanel.class action:@selector(toggle) forControlEvents:UIControlEventTouchUpInside];
    [g_floatWin.rootViewController.view addSubview:g_floatBtn];
    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:g_floatBtn action:@selector(ibox_handlePan:)];
    [g_floatBtn addGestureRecognizer:pan];
    objc_setAssociatedObject(g_floatBtn, "floatWin", g_floatWin, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationUserDidTakeScreenshotNotification
        object:nil queue:NSOperationQueue.mainQueue usingBlock:^(__unused NSNotification *n) {
            setFloatVisible(NO);
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2e9), dispatch_get_main_queue(), ^{ setFloatVisible(YES); });
        }];
    if (@available(iOS 11.0, *)) {
        [NSTimer scheduledTimerWithTimeInterval:0.5 repeats:YES block:^(__unused NSTimer *t) {
            setFloatVisible(!UIScreen.mainScreen.isCaptured);
        }];
    }
    LOG(@"悬浮球就绪");
}
@implementation UIButton (IBoxFloatDrag)
- (void)ibox_handlePan:(UIPanGestureRecognizer *)pan {
    UIWindow *win = objc_getAssociatedObject(self, "floatWin");
    if (!win) return;
    CGPoint tr = [pan translationInView:win];
    CGRect f = win.frame; f.origin.x += tr.x; f.origin.y += tr.y;
    CGSize sc = UIScreen.mainScreen.bounds.size;
    if (f.origin.x < 4) f.origin.x = 4;
    if (f.origin.y < 44) f.origin.y = 44;
    if (f.origin.x + f.size.width > sc.width - 4) f.origin.x = sc.width - 4 - f.size.width;
    if (f.origin.y + f.size.height > sc.height - 4) f.origin.y = sc.height - 4 - f.size.height;
    win.frame = f; [pan setTranslation:CGPointZero inView:win];
}
@end

// ============================ HWBP + 异常 ============================
static uintptr_t findFlutterBase() {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "Flutter.framework/Flutter"))
            return (uintptr_t)_dyld_get_image_header(i);
    }
    return 0;
}

static uintptr_t g_hook_addr = 0;
static _Atomic bool g_exc_ready = false;
static _Atomic bool g_hwbp_ok = false;

#ifndef ARM_DEBUG_STATE64
#define ARM_DEBUG_STATE64 15
#endif
typedef struct {
    __uint64_t __bvr[16];
    __uint64_t __bcr[16];
    __uint64_t __wvr[16];
    __uint64_t __wcr[16];
    __uint64_t __mdscr_el1;
} ibox_arm_debug_state64_t;
#define IBOX_DEBUG_COUNT ((mach_msg_type_number_t)(sizeof(ibox_arm_debug_state64_t)/sizeof(uint32_t)))

static bool ensureHookTarget() {
    if (g_hook_addr) return true;
    uintptr_t base = findFlutterBase();
    if (!base) return false;
    uintptr_t addr = base + RVA_ADDTEXT_BLR;
    uint32_t insn = *(volatile uint32_t *)addr;
    if (insn == INSN_BLR_X8 || (insn & 0xFFE0001F) == 0xD4200000) {
        g_hook_addr = addr;
        LOG(@"目标 @ %p insn=%08x base=%p", (void *)addr, insn, (void *)base);
        return true;
    }
    LOG(@"偏移不对 @ %p insn=%08x", (void *)addr, insn);
    return false;
}

static bool setHwBpOnThread(thread_t thread) {
    if (!g_hook_addr) return false;
    ibox_arm_debug_state64_t ds; memset(&ds, 0, sizeof(ds));
    mach_msg_type_number_t cnt = IBOX_DEBUG_COUNT;
    if (thread_get_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&ds, &cnt) != KERN_SUCCESS)
        return false;
    if (ds.__bvr[HWBP_SLOT] == (uint64_t)g_hook_addr && (ds.__bcr[HWBP_SLOT] & 1))
        return true;
    ds.__bvr[HWBP_SLOT] = (uint64_t)g_hook_addr;
    ds.__bcr[HWBP_SLOT] = HWBP_BCR_ENABLE;
    cnt = IBOX_DEBUG_COUNT;
    return thread_set_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&ds, cnt) == KERN_SUCCESS;
}

static int applyHwBpAllThreads() {
    if (!g_hook_addr) return 0;
    thread_act_array_t threads = nullptr;
    mach_msg_type_number_t count = 0;
    if (task_threads(mach_task_self(), &threads, &count) != KERN_SUCCESS || !threads) return 0;
    int ok = 0;
    for (mach_msg_type_number_t i = 0; i < count; i++) {
        if (setHwBpOnThread(threads[i])) ok++;
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads, sizeof(thread_t) * count);
    return ok;
}

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

static inline uint64_t ts_pc(const arm_thread_state64_t *s) {
#if defined(arm_thread_state64_get_pc)
    return (uint64_t)(uintptr_t)arm_thread_state64_get_pc(*s);
#else
    return s->__pc;
#endif
}
static inline uint64_t ts_x(const arm_thread_state64_t *s, int i) { return s->__x[i]; }
static inline void ts_set_pc(arm_thread_state64_t *s, uint64_t v) {
#if defined(arm_thread_state64_set_pc_fptr)
    arm_thread_state64_set_pc_fptr(*s, (void *)(uintptr_t)v);
#else
    s->__pc = v;
#endif
}
static inline void ts_set_lr(arm_thread_state64_t *s, uint64_t v) {
#if defined(arm_thread_state64_set_lr_fptr)
    arm_thread_state64_set_lr_fptr(*s, (void *)(uintptr_t)v);
#else
    s->__lr = v;
#endif
}

static bool handle_bp(mach_port_t thread) {
    // 注意: 这里绝不能 LOG / ObjC / 锁
    setHwBpOnThread(thread);

    arm_thread_state64_t st;
    mach_msg_type_number_t cnt = ARM_THREAD_STATE64_COUNT;
    if (thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&st, &cnt) != KERN_SUCCESS)
        return false;

    uint64_t pc = ts_pc(&st);
    if (!g_hook_addr || (pc & ~3ULL) != (g_hook_addr & ~3ULL)) return false;

    uint64_t x1 = ts_x(&st, 1);
    uint64_t x8 = ts_x(&st, 8);
    rewriteAddTextBuf(x1);

    if (x8) { ts_set_lr(&st, pc + 4); ts_set_pc(&st, x8); }
    else ts_set_pc(&st, pc + 4);

    cnt = ARM_THREAD_STATE64_COUNT;
    return thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t)&st, cnt) == KERN_SUCCESS;
}

static void *exc_thread(void *arg) {
    (void)arg;
    for (;;) {
        uint8_t buf[2048]; memset(buf, 0, sizeof(buf));
        mach_msg_header_t *hdr = (mach_msg_header_t *)buf;
        if (mach_msg(hdr, MACH_RCV_MSG, 0, sizeof(buf), g_exc_port,
                     MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) != KERN_SUCCESS) continue;

        exc_request_t *req = (exc_request_t *)buf;
        bool ok = false;
        if (req->exception == EXC_BREAKPOINT) {
            if (!g_hook_addr) ensureHookTarget();
            ok = handle_bp(req->thread.name);
        }
        exc_reply_t rep; memset(&rep, 0, sizeof(rep));
        rep.head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(hdr->msgh_bits), 0);
        rep.head.msgh_remote_port = hdr->msgh_remote_port;
        rep.head.msgh_size = sizeof(rep);
        rep.head.msgh_id = hdr->msgh_id + 100;
        rep.NDR = NDR_record;
        rep.RetCode = ok ? KERN_SUCCESS : KERN_FAILURE;
        mach_msg(&rep.head, MACH_SEND_MSG | MACH_SEND_TIMEOUT, sizeof(rep), 0,
                 MACH_PORT_NULL, 0, MACH_PORT_NULL);
    }
    return nullptr;
}

static bool installExc() {
    if (atomic_load(&g_exc_ready)) return true;
    if (!ensureHookTarget()) return false;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &g_exc_port) != KERN_SUCCESS)
        return false;
    if (mach_port_insert_right(mach_task_self(), g_exc_port, g_exc_port, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS)
        return false;
    if (task_set_exception_ports(mach_task_self(), EXC_MASK_BREAKPOINT, g_exc_port,
            (exception_behavior_t)(EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES),
            ARM_THREAD_STATE64) != KERN_SUCCESS)
        return false;
    pthread_t th; pthread_attr_t a;
    pthread_attr_init(&a); pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&th, &a, exc_thread, nullptr) != 0) { pthread_attr_destroy(&a); return false; }
    pthread_attr_destroy(&a);
    atomic_store(&g_exc_ready, true);
    LOG(@"EXC_BREAKPOINT OK");
    return true;
}

static bool installHWBP() {
    if (!ensureHookTarget()) return false;
    if (!atomic_load(&g_exc_ready) && !installExc()) return false;
    int n = applyHwBpAllThreads();
    if (n > 0) {
        atomic_store(&g_hwbp_ok, true);
        LOG(@"HWBP x%d @ %p", n, (void *)g_hook_addr);
        return true;
    }
    LOG(@"HWBP thread_set_state 失败");
    return false;
}

static void onImage(const struct mach_header *mh, intptr_t s) {
    (void)mh; (void)s;
    if (!atomic_load(&g_hwbp_ok)) installHWBP();
    else applyHwBpAllThreads();
}

__attribute__((constructor))
static void ibox_hook_init() {
    LOG(@"v5 HWBP async-safe 单dylib");
    writeTemplateIfNeeded();
    loadConfig();

    dispatch_source_t cfg = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
        dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0));
    dispatch_source_set_timer(cfg, dispatch_time(DISPATCH_TIME_NOW, 2e9), 2e9, 2e8);
    dispatch_source_set_event_handler(cfg, ^{ loadConfig(); });
    dispatch_resume(cfg);

    auto tryI = ^{
        if (!atomic_load(&g_hwbp_ok)) installHWBP();
        else applyHwBpAllThreads();
    };
    tryI();
    _dyld_register_func_for_add_image(onImage);
    for (int sec : {1, 3, 8}) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)sec * NSEC_PER_SEC),
                       dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), tryI);
    }
    dispatch_source_t bp = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
        dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
    dispatch_source_set_timer(bp, dispatch_time(DISPATCH_TIME_NOW, 5e9), 3e9, 5e8);
    dispatch_source_set_event_handler(bp, ^{ if (g_hook_addr) applyHwBpAllThreads(); });
    dispatch_resume(bp);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 4e9), dispatch_get_main_queue(), ^{ installFloatingBall(); });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 10e9), dispatch_get_main_queue(), ^{
        if (!g_floatWin) installFloatingBall();
    });
}
