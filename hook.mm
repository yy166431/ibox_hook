// ============================================================================
//  ibox_hook — 爱盒(ibox.art) Flutter 显示文本/数字修改器
//  用途: 重签注入(轻松签/巨魔均可), 拦截 Flutter 渲染层, 改屏幕上的字用于截图录屏
//
//  原理:
//    爱盒是 Flutter 3.11 AOT, UI 全走 Skia Canvas 画, 没有 UILabel 可 hook。
//    所有要显示的文字都会经过引擎里的 ParagraphBuilder::addText 这个唯一入口,
//    以 UTF-16 明文形式传给 Skia 排版。我们在这里拦截, 按规则替换即可。
//
//  Hook 点 (Flutter.framework 内 RVA, 版本锁定, 不随 App 更新):
//    0x481c2c  addText native wrapper (Dart String -> C++)
//    0x481ca8  blr x8  <-- 调用 peer->addText(&utf16buf) 之前, x1 = &UTF16Buf
//
//  作者: 海鸥
// ============================================================================
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <MediaPlayer/MediaPlayer.h>
#import <AVFoundation/AVFoundation.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <string>
#include <vector>
#include <map>
#include <regex>
#include "dobby.h"

#define TAG "[ibox_hook] "
static inline void LOG(NSString* fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString* s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"%@%@", @TAG, s);
}

// Flutter 引擎里 addText 的 blr 前一点点。版本锁定的 RVA。
static const uintptr_t RVA_ADDTEXT_BLR = 0x481ca8;

// ---------------------------------------------------------------------------
//  UTF-16 SSO 结构 (0x18 字节, 引擎从 0x48cc88 抽出来放栈上)
//    flag @ +0x17 : bit7=1 外部缓冲, bit7=0 内联
//    外部: ptr @ +0x0 (char16_t*),  len @ +0x8 (size_t)
//    内联: 数据从 +0x0 开始,        len = flag & 0x7f  (最多 11 个 char16_t)
// ---------------------------------------------------------------------------
struct UTF16Buf {
    char16_t inline_or_ptr[8];   // +0x0
    // 复用同一块内存, 用访问器区分
    uint8_t& flag()          { return *((uint8_t*)this + 0x17); }
    bool     external()      { return flag() & 0x80; }
    char16_t* dataPtr()      { return external() ? *(char16_t**)this : (char16_t*)this; }
    size_t   length()        { return external() ? *(size_t*)((uint8_t*)this + 8) : (flag() & 0x7f); }

    std::u16string get() {
        char16_t* p = dataPtr(); size_t n = length();
        if (!p || n == 0 || n > 100000) return u"";
        return std::u16string(p, n);
    }

    // 用外部 malloc 缓冲写回, 由引擎 wrapper 事后 free (allocator 一致, 安全)
    void set(const std::u16string& s) {
        char16_t* buf = (char16_t*)malloc((s.size() + 1) * sizeof(char16_t));
        memcpy(buf, s.data(), s.size() * sizeof(char16_t));
        buf[s.size()] = 0;
        *(char16_t**)this = buf;                        // ptr @ +0
        *(size_t*)((uint8_t*)this + 8) = s.size();      // len @ +8
        flag() = 0x80;                                  // 标记外部
    }
};

// ---------------------------------------------------------------------------
//  规则 (函数内static避免初始化顺序问题)
// ---------------------------------------------------------------------------
struct RegexRule { std::regex re; std::string rep; };

static std::map<std::string, std::string>& g_exact() {
    static std::map<std::string, std::string> m;
    return m;
}
static std::vector<RegexRule>& g_regex() {
    static std::vector<RegexRule> v;
    return v;
}
static std::string& g_wallet() {
    static std::string s;
    return s;
}
static time_t& g_cfg_mtime() {
    static time_t t = 0;
    return t;
}
static dispatch_queue_t g_cfg_q() {
    static dispatch_queue_t q = dispatch_queue_create("ibox.hook.cfg", DISPATCH_QUEUE_SERIAL);
    return q;
}

static NSString* configPath() {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/ibox_hook_rules.json"];
}

// 前向声明，RuleEditorPanel 需要
static void loadConfig();

// ---------------------------------------------------------------------------
//  音量键触发的编辑面板 (取代 Files app 改 JSON 的破操作)
// ---------------------------------------------------------------------------
@interface RuleEditorPanel : UIViewController <UITextViewDelegate>
@property (nonatomic, strong) UIWindow *panelWindow;
@property (nonatomic, strong) UITextView *walletField;
@property (nonatomic, strong) UITextView *exactField;
@property (nonatomic, strong) UITextView *regexField;
@end

@implementation RuleEditorPanel

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithWhite:0.1 alpha:0.95];

    // 顶部标题
    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(20, 50, self.view.bounds.size.width-40, 40)];
    title.text = @"爱盒 Hook 规则编辑器";
    title.textColor = [UIColor whiteColor];
    title.font = [UIFont boldSystemFontOfSize:20];
    title.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:title];

    CGFloat y = 100;

    // 钱包地址
    [self addLabel:@"钱包地址 (0x开头, 替换所有钱包)" atY:y];
    y += 25;
    self.walletField = [self makeTextViewAtY:y height:40];
    self.walletField.font = [UIFont monospacedSystemFontOfSize:14 weight:UIFontWeightRegular];
    y += 50;

    // 精确替换
    [self addLabel:@"精确替换 (每行: 原文=>新文)" atY:y];
    y += 25;
    self.exactField = [self makeTextViewAtY:y height:150];
    y += 160;

    // 正则替换
    [self addLabel:@"正则替换 (每行: pattern=>replace, UTF-8)" atY:y];
    y += 25;
    self.regexField = [self makeTextViewAtY:y height:150];
    y += 160;

    // 底部按钮
    UIButton *saveBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    saveBtn.frame = CGRectMake(20, y, (self.view.bounds.size.width-50)/2, 50);
    [saveBtn setTitle:@"保存" forState:UIControlStateNormal];
    saveBtn.titleLabel.font = [UIFont boldSystemFontOfSize:18];
    saveBtn.backgroundColor = [UIColor colorWithRed:0.2 green:0.6 blue:1.0 alpha:1.0];
    [saveBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    saveBtn.layer.cornerRadius = 8;
    [saveBtn addTarget:self action:@selector(saveAndClose) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:saveBtn];

    UIButton *closeBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    closeBtn.frame = CGRectMake(30 + (self.view.bounds.size.width-50)/2, y, (self.view.bounds.size.width-50)/2, 50);
    [closeBtn setTitle:@"关闭" forState:UIControlStateNormal];
    closeBtn.titleLabel.font = [UIFont boldSystemFontOfSize:18];
    closeBtn.backgroundColor = [UIColor colorWithWhite:0.3 alpha:1.0];
    [closeBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    closeBtn.layer.cornerRadius = 8;
    [closeBtn addTarget:self action:@selector(closePanel) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:closeBtn];

    [self loadCurrentRules];
}

- (void)addLabel:(NSString*)text atY:(CGFloat)y {
    UILabel *lbl = [[UILabel alloc] initWithFrame:CGRectMake(20, y, self.view.bounds.size.width-40, 20)];
    lbl.text = text;
    lbl.textColor = [UIColor colorWithWhite:0.8 alpha:1.0];
    lbl.font = [UIFont systemFontOfSize:14];
    [self.view addSubview:lbl];
}

- (UITextView*)makeTextViewAtY:(CGFloat)y height:(CGFloat)h {
    UITextView *tv = [[UITextView alloc] initWithFrame:CGRectMake(20, y, self.view.bounds.size.width-40, h)];
    tv.backgroundColor = [UIColor colorWithWhite:0.2 alpha:1.0];
    tv.textColor = [UIColor whiteColor];
    tv.font = [UIFont systemFontOfSize:14];
    tv.layer.cornerRadius = 6;
    tv.layer.borderWidth = 1;
    tv.layer.borderColor = [UIColor colorWithWhite:0.4 alpha:1.0].CGColor;
    tv.autocorrectionType = UITextAutocorrectionTypeNo;
    tv.autocapitalizationType = UITextAutocapitalizationTypeNone;
    tv.delegate = self;
    [self.view addSubview:tv];
    return tv;
}

- (void)loadCurrentRules {
    NSString *path = configPath();
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data) return;
    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (![json isKindOfClass:[NSDictionary class]]) return;

    // 钱包
    self.walletField.text = json[@"wallet"] ?: @"";

    // 精确
    NSMutableArray *exactLines = [NSMutableArray array];
    NSDictionary *exact = json[@"exact"];
    if ([exact isKindOfClass:[NSDictionary class]]) {
        for (NSString *k in exact) {
            [exactLines addObject:[NSString stringWithFormat:@"%@=>%@", k, exact[k]]];
        }
    }
    self.exactField.text = [exactLines componentsJoinedByString:@"\n"];

    // 正则
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
    json[@"_说明"] = @"音量键编辑面板生成, 无需手动改 JSON";

    // 钱包
    NSString *wallet = [self.walletField.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (wallet.length > 0) json[@"wallet"] = wallet;

    // 精确
    NSMutableDictionary *exact = [NSMutableDictionary dictionary];
    NSArray *exactLines = [self.exactField.text componentsSeparatedByString:@"\n"];
    for (NSString *line in exactLines) {
        NSArray *parts = [line componentsSeparatedByString:@"=>"];
        if (parts.count == 2) {
            NSString *k = [parts[0] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            NSString *v = [parts[1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            if (k.length > 0 && v.length > 0) exact[k] = v;
        }
    }
    if (exact.count > 0) json[@"exact"] = exact;

    // 正则
    NSMutableArray *regex = [NSMutableArray array];
    NSArray *regexLines = [self.regexField.text componentsSeparatedByString:@"\n"];
    for (NSString *line in regexLines) {
        NSArray *parts = [line componentsSeparatedByString:@"=>"];
        if (parts.count == 2) {
            NSString *p = [parts[0] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            NSString *r = [parts[1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            if (p.length > 0 && r.length > 0) {
                [regex addObject:@{@"pattern": p, @"replace": r}];
            }
        }
    }
    if (regex.count > 0) json[@"regex"] = regex;

    NSData *data = [NSJSONSerialization dataWithJSONObject:json options:NSJSONWritingPrettyPrinted error:nil];
    [data writeToFile:configPath() atomically:YES];

    // 立即重载配置
    loadConfig();

    LOG(@"规则已保存并生效: 精确%lu 正则%lu 钱包%@",
        (unsigned long)exact.count, (unsigned long)regex.count, wallet.length > 0 ? wallet : @"无");

    [self closePanel];
}

- (void)closePanel {
    [self.panelWindow resignKeyWindow];
    self.panelWindow.hidden = YES;
    self.panelWindow = nil;
}

+ (void)toggle {
    static RuleEditorPanel *instance = nil;
    if (instance && instance.panelWindow && !instance.panelWindow.hidden) {
        [instance closePanel];
        instance = nil;
        return;
    }

    instance = [[RuleEditorPanel alloc] init];
    UIWindow *win = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    win.windowLevel = UIWindowLevelAlert + 100;
    win.rootViewController = instance;
    instance.panelWindow = win;
    [win makeKeyAndVisible];
}

@end

// UTF-16 <-> UTF-8
static std::string u16_to_u8(const std::u16string& s) {
    NSString* ns = [[NSString alloc] initWithBytes:s.data()
                                            length:s.size() * sizeof(char16_t)
                                          encoding:NSUTF16LittleEndianStringEncoding];
    const char* c = [ns UTF8String];
    return c ? std::string(c) : std::string();
}
static std::u16string u8_to_u16(const std::string& s) {
    NSString* ns = [NSString stringWithUTF8String:s.c_str()];
    if (!ns) return u"";
    std::u16string out; out.reserve(ns.length);
    for (NSUInteger i = 0; i < ns.length; i++) out.push_back((char16_t)[ns characterAtIndex:i]);
    return out;
}

// ---------------------------------------------------------------------------
//  加载配置 (沙盒 Documents/ibox_hook_rules.json), 支持热更新(改完文件下一帧生效)
// ---------------------------------------------------------------------------
static void writeTemplateIfNeeded() {
    NSString* path = configPath();
    if ([[NSFileManager defaultManager] fileExistsAtPath:path]) return;
    NSDictionary* tpl = @{
        @"_说明": @"exact=整串精确替换, regex=正则替换(UTF-8), wallet=所有0x钱包地址统一改成这个。改完保存, App里下拉刷新一下即生效",
        @"exact": @{
            @"16868": @"99999",
            @"28391": @"88888",
            @"1560":  @"3650"
        },
        @"regex": @[
            @{@"pattern": @"持有\\d+", @"replace": @"持有9999"},
            @{@"pattern": @"¥\\d+",    @"replace": @"¥88888"}
        ],
        @"wallet": @"0x8888888888888888"
    };
    NSData* d = [NSJSONSerialization dataWithJSONObject:tpl
                                                options:NSJSONWritingPrettyPrinted error:nil];
    [d writeToFile:path atomically:YES];
    LOG(@"已生成配置模板: %@", path);
}

static void loadConfig() {
    NSString* path = configPath();
    NSDictionary* attr = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
    time_t mtime = (time_t)[[attr fileModificationDate] timeIntervalSince1970];
    if (mtime == g_cfg_mtime()) return;  // 没变

    NSData* data = [NSData dataWithContentsOfFile:path];
    if (!data) return;
    NSError* err = nil;
    NSDictionary* json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&err];
    if (![json isKindOfClass:[NSDictionary class]]) { LOG(@"配置解析失败: %@", err); return; }

    std::map<std::string,std::string> exact;
    std::vector<RegexRule> regex;
    std::string wallet;

    NSDictionary* ex = json[@"exact"];
    if ([ex isKindOfClass:[NSDictionary class]]) {
        for (NSString* k in ex) {
            id v = ex[k];
            if ([k isKindOfClass:[NSString class]] && [v isKindOfClass:[NSString class]])
                exact[[k UTF8String]] = [(NSString*)v UTF8String];
        }
    }
    NSArray* rx = json[@"regex"];
    if ([rx isKindOfClass:[NSArray class]]) {
        for (NSDictionary* r in rx) {
            NSString* p = r[@"pattern"]; NSString* rep = r[@"replace"];
            if (![p isKindOfClass:[NSString class]] || ![rep isKindOfClass:[NSString class]]) continue;
            try { regex.push_back({ std::regex([p UTF8String]), std::string([rep UTF8String]) }); }
            catch (const std::exception& e) { LOG(@"正则错误 %@: %s", p, e.what()); }
        }
    }
    NSString* w = json[@"wallet"];
    if ([w isKindOfClass:[NSString class]]) wallet = [w UTF8String];

    dispatch_sync(g_cfg_q(), ^{
        g_exact()  = exact;
        g_regex()  = regex;
        g_wallet() = wallet;
        g_cfg_mtime() = mtime;
    });
    LOG(@"配置加载: 精确%lu 正则%lu 钱包%s", exact.size(), regex.size(),
        wallet.empty() ? "无" : wallet.c_str());
}

// ---------------------------------------------------------------------------
//  应用规则 (输入/输出 UTF-8)
// ---------------------------------------------------------------------------
static bool looksLikeWallet(const std::string& s) {
    if (s.size() < 4 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X')) return false;
    for (size_t i = 2; i < s.size(); i++) {
        char c = s[i];
        bool ok = (c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F')||c=='*';
        if (!ok) return false;
    }
    return true;
}

static bool applyRules(const std::string& in, std::string& out) {
    __block std::map<std::string,std::string> exact;
    __block std::vector<RegexRule> regex;
    __block std::string wallet;
    dispatch_sync(g_cfg_q(), ^{ exact = g_exact(); regex = g_regex(); wallet = g_wallet(); });

    // 1) 精确整串
    auto it = exact.find(in);
    if (it != exact.end()) { out = it->second; return true; }

    // 2) 钱包地址
    if (!wallet.empty() && looksLikeWallet(in)) { out = wallet; return true; }

    // 3) 正则
    std::string cur = in; bool changed = false;
    for (auto& r : regex) {
        try {
            std::string res = std::regex_replace(cur, r.re, r.rep);
            if (res != cur) { cur = res; changed = true; }
        } catch (...) {}
    }
    if (changed) { out = cur; return true; }
    return false;
}

// ---------------------------------------------------------------------------
//  Hook 回调: 0x481ca8 blr x8 之前, x1 = &UTF16Buf
//  Dobby 回调签名: void(*)(void* address, DobbyRegisterContext* ctx)
// ---------------------------------------------------------------------------
static void onAddText(void* address, DobbyRegisterContext* ctx) {
    (void)address;
    UTF16Buf* buf = (UTF16Buf*)ctx->general.regs.x1;
    if (!buf) return;

    std::u16string u16 = buf->get();
    if (u16.empty()) return;

    std::string u8 = u16_to_u8(u16), out;
    if (applyRules(u8, out)) {
        buf->set(u8_to_u16(out));
    }
}

// ---------------------------------------------------------------------------
//  安装
// ---------------------------------------------------------------------------
__attribute__((constructor))
static void init() {
    LOG(@"加载中...");

    // 找 Flutter.framework 基址
    uintptr_t base = 0;
    for (uint32_t i = 0, n = _dyld_image_count(); i < n; i++) {
        const char* name = _dyld_get_image_name(i);
        if (name && strstr(name, "Flutter.framework/Flutter")) {
            base = (uintptr_t)_dyld_get_image_header(i);
            LOG(@"Flutter.framework @ 0x%lx", base);
            break;
        }
    }
    if (!base) { LOG(@"错误: 找不到 Flutter.framework, 退出"); return; }

    writeTemplateIfNeeded();
    loadConfig();

    // 每 1.5 秒后台刷新配置(改完 json 不用重启)
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0));
    dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW, 0),
                              1500ull * NSEC_PER_MSEC, 200ull * NSEC_PER_MSEC);
    dispatch_source_set_event_handler(timer, ^{ loadConfig(); });
    dispatch_resume(timer);

    void* target = (void*)(base + RVA_ADDTEXT_BLR);
    int r = DobbyInstrument(target, onAddText);
    LOG(@"Hook @ 0x%lx (RVA 0x%lx) 结果=%d", (uintptr_t)target, RVA_ADDTEXT_BLR, r);

    // 监听音量键, 弹编辑面板
    [[NSNotificationCenter defaultCenter] addObserverForName:@"AVSystemController_SystemVolumeDidChangeNotification"
                                                      object:nil
                                                       queue:[NSOperationQueue mainQueue]
                                                  usingBlock:^(NSNotification *note) {
        NSString *reason = note.userInfo[@"AVSystemController_AudioVolumeChangeReasonNotificationParameter"];
        // ExplicitVolumeChange = 用户按了音量键 (非app代码调整)
        if ([reason isEqualToString:@"ExplicitVolumeChange"]) {
            [RuleEditorPanel toggle];
        }
    }];
    LOG(@"音量键面板已就绪, 按音量+/-打开编辑器");
}
