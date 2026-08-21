// iBox文本替换 v5 - addText hook + 全内存扫描
// 用法: frida -U -n Runner -l frida_memscan.js

console.log("[*] iBox hook v5 loading...");

// ========= 替换规则 =========
var EXACT = {
    "289":   "999",
    "2632":  "9999",
    "552":   "999",
    "16868": "99999",
    "28391": "88888",
    "1560":  "3650",
    "红苹果": "非常牛逼"
};

var WALLET_REPLACE = "0x8888888888888888888888888888888888888888";

// ========= 工具函数 =========
function toUTF16LEPattern(str) {
    var bytes = [];
    for (var i = 0; i < str.length; i++) {
        var c = str.charCodeAt(i);
        bytes.push(("0" + (c & 0xff).toString(16)).slice(-2));
        bytes.push(("0" + ((c >> 8) & 0xff).toString(16)).slice(-2));
    }
    return bytes.join(" ");
}

function writeUTF16LE(addr, str) {
    for (var i = 0; i < str.length; i++) {
        addr.add(i * 2).writeU16(str.charCodeAt(i));
    }
}

// ASCII单字节写 (Dart String对象用Latin-1)
function toASCIIPattern(str) {
    var bytes = [];
    for (var i = 0; i < str.length; i++) {
        bytes.push(("0" + str.charCodeAt(i).toString(16)).slice(-2));
    }
    return bytes.join(" ");
}

function writeASCII(addr, str) {
    for (var i = 0; i < str.length; i++) {
        addr.add(i).writeU8(str.charCodeAt(i));
    }
}

// ========= 内存扫描主函数 =========
var totalReplaced = 0;

function scanAndReplace() {
    var count = 0;

    // 获取可写内存区域 (堆/栈/数据段)
    var ranges = [];
    try {
        ranges = Process.enumerateRanges('rw-');
    } catch(e) {
        console.log("[!] enumerateRanges失败: " + e);
        return;
    }

    for (var key in EXACT) {
        var val = EXACT[key];
        if (key.length !== val.length) continue;

        // --- UTF-16LE扫描 (Flutter Paragraph文本缓冲区) ---
        var u16pat = toUTF16LEPattern(key);
        for (var ri = 0; ri < ranges.length; ri++) {
            var range = ranges[ri];
            if (range.size < key.length * 2) continue;
            // 跳过可执行区
            if (range.protection.indexOf('x') !== -1) continue;
            // 跳过主要framework区域(太大扫太慢)
            if (range.size > 256 * 1024 * 1024) continue;

            try {
                Memory.scan(range.base, range.size, u16pat, {
                    onMatch: function(from, to, val) {
                        return function(addr) {
                            writeUTF16LE(addr, to);
                            console.log("[UTF16] " + from + " => " + to + " @" + addr);
                            count++;
                        };
                    }(key, val),
                    onError: function() {},
                    onComplete: function() {}
                });
            } catch(e) {}
        }

        // --- ASCII单字节扫描 (Dart String对象) ---
        var ascpat = toASCIIPattern(key);
        for (var ri = 0; ri < ranges.length; ri++) {
            var range = ranges[ri];
            if (range.size < key.length) continue;
            if (range.protection.indexOf('x') !== -1) continue;
            if (range.size > 256 * 1024 * 1024) continue;

            try {
                Memory.scan(range.base, range.size, ascpat, {
                    onMatch: function(from, to, val) {
                        return function(addr) {
                            // 检查前后字节不是数字(避免误改"12890"中的"289")
                            try {
                                var before = addr.add(-1).readU8();
                                var after  = addr.add(from.length).readU8();
                                var isDigit = function(b) { return b >= 0x30 && b <= 0x39; };
                                if (isDigit(before) || isDigit(after)) return;
                                writeASCII(addr, to);
                                console.log("[ASCII] " + from + " => " + to + " @" + addr);
                                count++;
                            } catch(e) {}
                        };
                    }(key, val),
                    onError: function() {},
                    onComplete: function() {}
                });
            } catch(e) {}
        }
    }

    // --- 钱包地址 UTF-16LE扫描 ---
    var oxPat = toUTF16LEPattern("0x");
    for (var ri = 0; ri < ranges.length; ri++) {
        var range = ranges[ri];
        if (range.size < 84) continue;
        if (range.protection.indexOf('x') !== -1) continue;
        if (range.size > 256 * 1024 * 1024) continue;

        try {
            Memory.scan(range.base, range.size, oxPat, {
                onMatch: function(addr) {
                    try {
                        // 读42字符判断是否为0x+40位hex
                        var s = "";
                        for (var i = 0; i < 42; i++) {
                            s += String.fromCharCode(addr.add(i * 2).readU16());
                        }
                        if (/^0x[0-9a-fA-F]{40}$/.test(s)) {
                            writeUTF16LE(addr, WALLET_REPLACE.substring(0, 42));
                            console.log("[WALLET] " + s.substring(0, 10) + "... => 0x8888...");
                            count++;
                        }
                    } catch(e) {}
                },
                onError: function() {},
                onComplete: function() {}
            });
        } catch(e) {}
    }

    totalReplaced += count;
    console.log("[SCAN] 本轮替换 " + count + " 处, 累计 " + totalReplaced + " 处");
}

// ========= addText Hook (动态/刷新内容) =========
function applyRules(text, maxLen) {
    // 精确匹配 - 直接返回，不限长度
    if (EXACT[text] !== undefined) {
        return EXACT[text];
    }
    // 包含精确key的文本
    for (var k in EXACT) {
        if (text.indexOf(k) !== -1) {
            return text.replace(k, EXACT[k]);
        }
    }
    if (/^0x[0-9a-fA-F]{10,}$/.test(text)) {
        return WALLET_REPLACE.substring(0, text.length);
    }
    var m1 = text.match(/^(.*持有\s*)(\d+)(.*)$/);
    if (m1) {
        var prefix = m1[1], numStr = m1[2], suffix = m1[3];
        var newNum = "9999";
        if (newNum.length <= numStr.length) {
            newNum = newNum + " ".repeat(numStr.length - newNum.length);
        } else {
            var ov = newNum.length - numStr.length;
            if (suffix.length >= ov) { suffix = suffix.substring(ov); }
            else { newNum = newNum.substring(0, numStr.length); }
        }
        var r = prefix + newNum + suffix;
        if (r.length > maxLen) r = r.substring(0, maxLen);
        if (r.length < maxLen) r = r + " ".repeat(maxLen - r.length);
        return r;
    }
    var m2 = text.match(/^(.*¥\s*)(\d[\d,.]*)(.*)$/);
    if (m2) {
        var prefix = m2[1], numStr = m2[2], suffix = m2[3];
        var newNum = "88888";
        if (newNum.length <= numStr.length) {
            newNum = newNum + " ".repeat(numStr.length - newNum.length);
        } else {
            var ov = newNum.length - numStr.length;
            if (suffix.length >= ov) { suffix = suffix.substring(ov); }
            else { newNum = newNum.substring(0, numStr.length); }
        }
        var r = prefix + newNum + suffix;
        if (r.length > maxLen) r = r.substring(0, maxLen);
        if (r.length < maxLen) r = r + " ".repeat(maxLen - r.length);
        return r;
    }
    return null;
}

var flutter = Process.findModuleByName("Flutter");
if (!flutter) {
    console.log("[!] Flutter not found!");
} else {
    console.log("[+] Flutter base:", flutter.base);
    Interceptor.attach(flutter.base.add(0x481ca8), {
        onEnter: function(args) {
            var buf = this.context.x1;
            try {
                var flag = buf.add(0x17).readU8();
                var isExt = (flag & 0x80) !== 0;
                var ptr, len;
                if (isExt) { ptr = buf.readPointer(); len = buf.add(8).readU64().toNumber(); }
                else       { ptr = buf; len = flag & 0x7f; }
                if (len <= 0 || len > 5000) return;
                var orig = "";
                for (var i = 0; i < len; i++) orig += String.fromCharCode(ptr.add(i*2).readU16());
                if (!orig) return;
                var rep = applyRules(orig, len);
                if (!rep || rep === orig) return;
                var writeLen = Math.min(rep.length, isExt ? 100000 : 0x3f);
                for (var i = 0; i < writeLen; i++) ptr.add(i*2).writeU16(rep.charCodeAt(i));
                // 更新长度字段
                if (isExt) {
                    buf.add(8).writeU64(writeLen);
                } else {
                    buf.add(0x17).writeU8(writeLen & 0x7f);
                }
                console.log("[HOOK]", orig.substring(0,30), "=>", rep.substring(0,30));
            } catch(e) {}
        }
    });
    console.log("[+] addText hook OK");
}

// ========= 启动扫描 =========
// 延迟5秒再扫,先让hook稳定
console.log("[*] 5秒后开始内存扫描...");
setTimeout(function() {
    scanAndReplace();
    // 每10秒扫一次
    setInterval(function() {
        scanAndReplace();
    }, 10000);
}, 5000);
