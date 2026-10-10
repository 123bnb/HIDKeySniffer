#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <dlfcn.h>
#include <sys/time.h>
#include <unistd.h>

// ============================================================
// HIDKeySniffer v1.0.7 —— 翻页器=HID Digitizer 触摸设备确认版
// 实机结论（v1.0.6 日志）：
//   翻页器按键 = type=11 Digitizer 触摸事件，直接进前台 App 的
//   _UIHIDTransformer.handleHIDEvent: / _UIUpdateHIDDigitizerInput.addEvent:
//   音量键（键盘consumer）不经过 App UI 层（KVO 方案另行处理）
// v1.0.7 目标：
//   1. 过滤心跳刷屏（type=17 compat 空事件、type=11 空闲事件）
//   2. hook _UIHIDTransformer.handleHIDEvent: 返回值，打印 UIKit 转换结果
//      （UIEvent type/subtype + 每根 UITouch 的 phase/坐标/pathIdentity/touchIdentifier）
//   3. 正确解析 digitizer float 字段（X=0x23 Y=0x24 等），区分翻页器 vs 手指
// 安全：只读 + 打日志，不吞事件不修改，原调用原样放行
// ============================================================

static const char *gContainerPath = NULL;

static void HKLog(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    struct timeval tv;
    gettimeofday(&tv, NULL);
    time_t sec = tv.tv_sec;
    struct tm tmv;
    localtime_r(&sec, &tmv);
    char tbuf[64];
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tmv);
    if (gContainerPath) {
        FILE *f = fopen(gContainerPath, "a");
        if (f) { fprintf(f, "%s.%03d %s\n", tbuf, (int)(tv.tv_usec / 1000), buf); fclose(f); }
    }
    FILE *f2 = fopen("/var/mobile/Documents/HIDKeySniffer.log", "a");
    if (f2) { fprintf(f2, "%s.%03d %s\n", tbuf, (int)(tv.tv_usec / 1000), buf); fclose(f2); }
}

// ---------- IOKit ----------
typedef uint32_t (*IOHIDEventGetType_t)(void *);
typedef uint64_t (*IOHIDEventGetSenderID_t)(void *);
typedef uint32_t (*IOHIDEventGetIntegerValue_t)(void *, uint32_t);
typedef double (*IOHIDEventGetFloatValue_t)(void *, uint32_t);
static IOHIDEventGetType_t pGetType = NULL;
static IOHIDEventGetSenderID_t pGetSender = NULL;
static IOHIDEventGetIntegerValue_t pGetInt = NULL;
static IOHIDEventGetFloatValue_t pGetFloat = NULL;

// 事件类型名
static const char *HKTypeName(uint32_t t) {
    switch (t) {
        case 0: return "NULL";
        case 1: return "VendorDefined";
        case 2: return "Button";
        case 3: return "Keyboard";
        case 4: return "Accelerometer";
        case 5: return "Environment";
        case 11: return "Digitizer";
        case 12: return "Rotation";
        case 13: return "Translation";
        case 14: return "Scroll";
        case 15: return "Zoom";
        case 16: return "Pointer";
        case 17: return "Compat";
        case 20: return "StdGesture";
        case 21: return "Proximity";
        default: return "?";
    }
}

// 读 UITouch 私有 ivar
static uint32_t HKReadIvar(id obj, const char *name, size_t size) {
    Ivar iv = class_getInstanceVariable(object_getClass(obj), name);
    if (!iv) return 0xFFFFFFFF;
    uint64_t val = 0;
    memcpy(&val, (char *)obj + ivar_getOffset(iv), size);
    return (uint32_t)val;
}

// ---------- 打印 UITouch ----------
static void HKPrintTouch(UITouch *t) {
    if (!t) { HKLog("        touch=NULL"); return; }
    CGPoint loc = [t locationInView:t.view];
    CGPoint wloc = t.window ? [t locationInWindow:t.window] : CGPointZero;
    uint32_t pathId = HKReadIvar(t, "_pathIdentity", 1);
    uint32_t touchId = HKReadIvar(t, "_touchIdentifier", 4);
    HKLog("        touch phase=%ld loc=(%.1f,%.1f) win=(%.1f,%.1f) pathId=%u touchId=%u",
          (long)t.phase, loc.x, loc.y, wloc.x, wloc.y, pathId, touchId);
}

// ---------- 打印转换结果 UIEvent ----------
static void HKPrintUIEventResult(id result) {
    if (!result) { HKLog("    → 转换结果 = nil"); return; }
    Class rc = object_getClass(result);
    HKLog("    → 转换结果 isa=%s", rc ? class_getName(rc) : "?");
    if ([result isKindOfClass:[UIEvent class]]) {
        UIEvent *ev = (UIEvent *)result;
        HKLog("    → UIEvent type=%ld subtype=%ld touches=%lu",
              (long)ev.type, (long)ev.subtype, (unsigned long)ev.allTouches.count);
        for (UITouch *t in ev.allTouches) HKPrintTouch(t);
    }
}

// ---------- 打印 IOHIDEvent（过滤心跳） ----------
static void HKPrintEvent(void *event) {
    if (!event) return;
    uint32_t type = pGetType ? pGetType(event) : 0xFFFFFFFF;
    uint64_t sender = pGetSender ? pGetSender(event) : 0;

    // 过滤：type=17 compat 心跳、type=11 空闲(0x8000000800a15173)
    if (type == 17) return;
    if (type == 11 && sender == 0x8000000800a15173ull) return;

    HKLog("    type=%u(%s) sender=0x%llx", type, HKTypeName(type), (unsigned long long)sender);
    if (!pGetInt) return;
    // Keyboard 字段
    uint32_t usagePage = pGetInt(event, 0x0D);
    uint32_t usage = pGetInt(event, 0x0E);
    uint32_t down = pGetInt(event, 0x0F);
    if (type == 3 || usagePage || usage) {
        HKLog("        KB usagePage=0x%x usage=0x%x down=%u", usagePage, usage, down);
    }
    // Button / Pointer
    uint32_t btn = pGetInt(event, 0x03);
    if (type == 2 || btn) {
        HKLog("        BTN mask=0x%x", btn);
    }
    // Scroll
    if (type == 14) {
        double sx = pGetFloat ? pGetFloat(event, 0x3B) : 0;
        double sy = pGetFloat ? pGetFloat(event, 0x3C) : 0;
        HKLog("        Scroll x=%f y=%f", sx, sy);
    }
    // Digitizer：float X/Y + 事件掩码 + 触摸索引
    if (type == 11) {
        double dx = pGetFloat ? pGetFloat(event, 0x23) : 0;
        double dy = pGetFloat ? pGetFloat(event, 0x24) : 0;
        uint32_t emask = pGetInt(event, 0x2A);       // EventMask
        uint32_t tindex = pGetInt(event, 0x28);       // Index
        uint32_t tident = pGetInt(event, 0x29);       // Identity
        uint32_t ttype = pGetInt(event, 0x27);        // Type
        HKLog("        DIG X=%f Y=%f mask=0x%x idx=%u ident=%u type=%u",
              dx, dy, emask, tindex, tident, ttype);
    }
}

// ---------- IMP 对 ----------
static IMP gOrig1;
static void *HKImp1(id self, SEL _cmd, void *event) {
    return ((void *(*)(id, SEL, void *))gOrig1)(self, _cmd, event);
}
static IMP gOrig2;
static void *HKImp2(id self, SEL _cmd, void *event) {
    return ((void *(*)(id, SEL, void *))gOrig2)(self, _cmd, event);
}
static IMP gOrig3;
static void *HKImp3(id self, SEL _cmd, void *event) {
    HKLog("[入口] _UIHIDTransformer.handleHIDEvent:");
    HKPrintEvent(event);
    id result = ((id (*)(id, SEL, void *))gOrig3)(self, _cmd, event);
    HKPrintUIEventResult(result);
    return result;
}
static IMP gOrig4;
static void *HKImp4(id self, SEL _cmd, void *event) {
    HKLog("[入口] _UIUpdateHIDInput.addEvent:");
    HKPrintEvent(event);
    return ((void *(*)(id, SEL, void *))gOrig4)(self, _cmd, event);
}
static IMP gOrig5;
static void *HKImp5(id self, SEL _cmd, void *event) {
    HKLog("[入口] _UIUpdateHIDDigitizerInput.addEvent:");
    HKPrintEvent(event);
    return ((void *(*)(id, SEL, void *))gOrig5)(self, _cmd, event);
}
static IMP gOrig6;
static void *HKImp6(id self, SEL _cmd, id evt) {
    return ((void *(*)(id, SEL, id))gOrig6)(self, _cmd, evt);
}

// ---------- hook ----------
typedef struct {
    const char *clsName;
    const char *selName;
    const char *encNeedle;
    IMP *origSlot;
    IMP newImp;
} HKHookSpec;

static void HKSwizzleSpec(HKHookSpec *spec) {
    Class cls = NSClassFromString([NSString stringWithUTF8String:spec->clsName]);
    if (!cls) { HKLog("[探测] 类不存在 %s 跳过", spec->clsName); return; }
    SEL sel = sel_registerName(spec->selName);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) { HKLog("[探测] %s -%s 不存在，跳过", spec->clsName, spec->selName); return; }
    const char *enc = method_getTypeEncoding(m);
    if (!strstr(enc, spec->encNeedle)) {
        HKLog("[探测] %s -%s 签名=%s（期望含 %s）不匹配，跳过", spec->clsName, spec->selName, enc, spec->encNeedle);
        return;
    }
    *(spec->origSlot) = method_getImplementation(m);
    method_setImplementation(m, spec->newImp);
    HKLog("[探测] %s -%s 已hook ✓ 签名=%s", spec->clsName, spec->selName, enc);
}

__attribute__((constructor))
static void HKInit() {
    NSString *home = NSHomeDirectory();
    NSString *logPath = [[home stringByAppendingPathComponent:@"Documents"] stringByAppendingPathComponent:@"HIDKeySniffer.log"];
    gContainerPath = strdup([logPath UTF8String]);

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW);
    if (iokit) {
        pGetType = (IOHIDEventGetType_t)dlsym(iokit, "IOHIDEventGetType");
        pGetSender = (IOHIDEventGetSenderID_t)dlsym(iokit, "IOHIDEventGetSenderID");
        pGetInt = (IOHIDEventGetIntegerValue_t)dlsym(iokit, "IOHIDEventGetIntegerValue");
        pGetFloat = (IOHIDEventGetFloatValue_t)dlsym(iokit, "IOHIDEventGetFloatValue");
    }
    HKLog("==================================================");
    HKLog("HIDKeySniffer v1.0.7 已注入 %s (pid=%d)", [[[NSBundle mainBundle] bundleIdentifier] UTF8String], getpid());
    HKLog("容器日志路径: %s", gContainerPath);
    HKLog("IOKit解析: type=%d sender=%d int=%d float=%d",
          pGetType != NULL, pGetSender != NULL, pGetInt != NULL, pGetFloat != NULL);
    HKLog("--- hook 开始 ---");
    HKHookSpec specs[] = {
        { "UIEventFetcher", "_receiveHIDEvent:", "^{__IOHIDEvent=}", &gOrig1, (IMP)HKImp1 },
        { "UIApplication", "handleKeyHIDEvent:", "^{__IOHIDEvent=}", &gOrig2, (IMP)HKImp2 },
        { "_UIHIDTransformer", "handleHIDEvent:", "^{__IOHIDEvent=}", &gOrig3, (IMP)HKImp3 },
        { "_UIUpdateHIDInput", "addEvent:", "^{__IOHIDEvent=}", &gOrig4, (IMP)HKImp4 },
        { "_UIUpdateHIDDigitizerInput", "addEvent:", "^{__IOHIDEvent=}", &gOrig5, (IMP)HKImp5 },
        { "HIDEventService", "dispatchEvent:", "v24@0:8@16", &gOrig6, (IMP)HKImp6 },
    };
    for (size_t i = 0; i < sizeof(specs) / sizeof(specs[0]); i++) HKSwizzleSpec(&specs[i]);
    HKLog("--- hook 结束 ---");
    HKLog("初始化完成。只按翻页器7键（每键按1次，间隔1秒），看每个键的 UIKit 转换结果");
    HKLog("==================================================");
}
