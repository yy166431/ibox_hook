// iBox v6 - 纯hook,不限长度
console.log("[*] iBox hook v6 loading...");

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

function applyRules(text) {
    if (EXACT[text] !== undefined) return EXACT[text];
    for (var k in EXACT) {
        if (text.indexOf(k) !== -1) return text.replace(k, EXACT[k]);
    }
    if (/^0x[0-9a-fA-F]{10,}$/.test(text)) return WALLET_REPLACE.substring(0, text.length);
    var m1 = text.match(/^(.*持有\s*)(\d+)(.*)$/);
    if (m1) return m1[1] + "9999" + m1[3].substring(Math.max(0, 4 - m1[2].length));
    var m2 = text.match(/^(.*¥\s*)(\d[\d,.]*)(.*)$/);
    if (m2) return m2[1] + "88888" + m2[3].substring(Math.max(0, 5 - m2[2].length));
    return null;
}

var flutter = Process.findModuleByName("Flutter");
if (!flutter) { console.log("[!] Flutter not found!"); }
else {
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
                var rep = applyRules(orig);
                if (!rep || rep === orig) return;

                var writeLen = rep.length;
                if (!isExt && writeLen > 11) writeLen = 11;
                for (var i = 0; i < writeLen; i++) ptr.add(i*2).writeU16(rep.charCodeAt(i));
                if (isExt) {
                    buf.add(8).writeU64(writeLen);
                } else {
                    buf.add(0x17).writeU8(writeLen & 0x7f);
                }
                console.log("[OK]", orig, "=>", rep);
            } catch(e) {}
        }
    });
    console.log("[+] Hook OK, 不限长度模式");
}

// ========= 内存扫描 (延迟执行避免超时) =========
function toU16Pat(str) {
    var b = [];
    for (var i = 0; i < str.length; i++) {
        var c = str.charCodeAt(i);
        b.push(("0"+(c&0xff).toString(16)).slice(-2));
        b.push(("0"+((c>>8)&0xff).toString(16)).slice(-2));
    }
    return b.join(" ");
}

function memScan() {
    var count = 0;
    var ranges = Process.enumerateRanges('rw-');
    for (var key in EXACT) {
        var val = EXACT[key];
        if (key.length !== val.length) continue;
        var pat = toU16Pat(key);
        for (var i = 0; i < ranges.length; i++) {
            var r = ranges[i];
            if (r.size < key.length*2 || r.size > 200*1024*1024) continue;
            if (r.protection.indexOf('x') !== -1) continue;
            try {
                Memory.scan(r.base, r.size, pat, {
                    onMatch: function(k,v){ return function(addr) {
                        for(var j=0;j<v.length;j++) addr.add(j*2).writeU16(v.charCodeAt(j));
                        count++;
                    };}(key,val),
                    onError:function(){}, onComplete:function(){}
                });
            } catch(e){}
        }
    }
    console.log("[SCAN] 替换 " + count + " 处");
}

// 10秒后开始扫描,之后每10秒扫一次
setTimeout(function() {
    memScan();
    setInterval(memScan, 10000);
}, 10000);
