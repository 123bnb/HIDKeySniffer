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
// HIDKeySniffer v1.0.8 —— 展开数组 + 子事件 + sendEvent 直取版
// v1.0.7 实机结论：
//   _UIHIDTransformer.handleHIDEvent: 返回 __NSSingleObjectArrayI（数组！非UIEvent）
//   digitizer 根事件字段全 0 → 真实数据在 IOHIDEvent 子事件（树结构）里
//  翻页器按键 = type=11 Digitizer sender=0x1000008ef 1ms级密集事件流
// v1.0.8 目标：
//   1. 遍历 IOHIDEvent 子事件，递归打印 type/坐标/按钮（数据在 child）
//   2. 展开 handleHIDEvent: 返回数组的元素 isa + description
//   3. 新增 hook UIApplication -sendEvent:（UIKit 分发最终入口）打印 UIEvent 全细节
//   4. 按键组分隔线：事件间隔 >0.5s 打印分隔，7 键一眼分开
// 安全：只读 + 打日志，不吞事件不修改
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
typedef CFArrayRef (*IOHIDEventGetChildren_t)(void *);
typedef void *(*IOHIDEventGetChild_t)(void *, int);
static IOHIDEventGetType_t pGetType = NULL;
static IOHIDEventGetSenderID_t pGetSender = NULL;
static IOHIDEventGetIntegerValue_t pGetInt = NULL;
static IOHIDEventGetFloatValue_t pGetFloat = NULL;
static IOHIDEventGetChildren_t pGetChildren = NULL;
static IOHIDEventGetChild_t pGetChild = NULL;

static double gLastKeySec = 0; // 按键组分隔
static bool gFiltered = false;

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

static double HKNow() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
}

// 读 UITouch 私有 ivar
static uint32_t HKReadIvar(id obj, const char *name, size_t size) {
    Ivar iv = class_getInstanceVariable(object_getClass(obj), name);
    if (!iv) return 0xFFFFFFFF;
    uint64_t val = 0;
    memcpy(&val, (char *)(__bridge void *)obj + ivar_getOffset(iv), size);
    return (uint32_t)val;
}

// ---------- 打印单个 IOHIDEvent 字段 ----------
static void HKPrintEventFields(void *event, int depth) {
    if (!event) return;
    uint32_t type = pGetType ? pGetType(event) : 0xFFFFFFFF;
    uint64_t sender = pGetSender ? pGetSender(event) : 0;
    char pad[16];
    memset(pad, ' ', sizeof(pad));
    pad[depth * 2] = 0;
    HKLog("%sEV type=%u(%s) sender=0x%llx", pad, type, HKTypeName(type), (unsigned long long)sender);
    if (!pGetInt) return;
    // 键盘
    uint32_t usagePage = pGetInt(event, 0x0D);
    uint32_t usage = pGetInt(event, 0x0E);
    uint32_t down = pGetInt(event, 0x0F);
    if (type == 3 || usagePage || usage) {
        HKLog("%s  KB usagePage=0x%x usage=0x%x down=%u", pad, usagePage, usage, down);
    }
    // 按钮
    uint32_t btn = pGetInt(event, 0x03);
    if (type == 2 || btn) {
        HKLog("%s  BTN mask=0x%x", pad, btn);
    }
    // 滚轮
    if (type == 14) {
        double sx = pGetFloat ? pGetFloat(event, 0x3B) : 0;
        double sy = pGetFloat ? pGetFloat(event, 0x3C) : 0;
        HKLog("%s  SCROLL x=%f y=%f", pad, sx, sy);
    }
    // Digitizer
    if (type == 11) {
        double dx = pGetFloat ? pGetFloat(event, 0x23) : 0;
        double dy = pGetFloat ? pGetFloat(event, 0x24) : 0;
        double dz = pGetFloat ? pGetFloat(event, 0x25) : 0;
        double press = pGetFloat ? pGetFloat(event, 0x2D) : 0;
        uint32_t emask = pGetInt(event, 0x2A);
        uint32_t tindex = pGetInt(event, 0x28);
        uint32_t tident = pGetInt(event, 0x29);
        uint32_t ttype = pGetInt(event, 0x27);
        uint32_t btns = pGetInt(event, 0x26);
        HKLog("%s  DIG X=%f Y=%f Z=%f press=%f mask=0x%x idx=%u ident=%u type=%u btn=0x%x",
              pad, dx, dy, dz, press, emask, tindex, tident, ttype, btns);
    }
    // 子事件递归（最多2层）
    if (depth < 2 && pGetChildren) {
        CFArrayRef kids = pGetChildren(event);
        if (kids) {
            CFIndex n = CFArrayGetCount(kids);
            for (CFIndex i = 0; i < n; i++) {
                void *child = (void *)CFArrayGetValueAtIndex(kids, i);
                HKPrintEventFields(child, depth + 1);
            }
            CFRelease(kids);
        }
    }
}

// ---------- 打印 UITouch ----------
static void HKPrintTouch(UITouch *t) {
    if (!t) { HKLog("        touch=NULL"); return; }
    CGPoint loc = [t locationInView:t.view];
    CGPoint wloc = t.window ? [t locationInView:t.window] : CGPointZero;
    uint32_t pathId = HKReadIvar(t, "_pathIdentity", 1);
    uint32_t touchId = HKReadIvar(t, "_touchIdentifier", 4);
    HKLog("        touch phase=%ld loc=(%.1f,%.1f) win=(%.1f,%.1f) pathId=%u touchId=%u",
          (long)t.phase, loc.x, loc.y, wloc.x, wloc.y, pathId, touchId);
}

// ---------- 打印 UIEvent ----------
static void HKPrintUIEvent(UIEvent *ev, const char *tag) {
    HKLog("%s UIEvent type=%ld subtype=%ld touches=%lu",
          tag, (long)ev.type, (long)ev.subtype, (unsigned long)ev.allTouches.count);
    for (UITouch *t in ev.allTouches) HKPrintTouch(t);
}

// ---------- 打印转换结果（数组/UIEvent/其他） ----------
static void HKPrintUIEventResult(id result) {
    if (!result) { HKLog("    → 转换结果 = nil"); return; }
    Class rc = object_getClass(result);
    HKLog("    → 转换结果 isa=%s", rc ? class_getName(rc) : "?");
    if ([result isKindOfClass:[NSArray class]]) {
        NSArray *arr = (NSArray *)result;
        HKLog("    → 数组 count=%lu", (unsigned long)arr.count);
        for (id obj in arr) {
            Class oc = object_getClass(obj);
            HKLog("      [元素] isa=%s", oc ? class_getName(oc) : "?");
            if ([obj isKindOfClass:[UIEvent class]]) {
                HKPrintUIEvent((UIEvent *)obj, "        ");
            } else {
                NSString *desc = [obj description];
                if (desc && desc.length) HKLog("      [元素] desc=%@", desc);
            }
        }
    } else if ([result isKindOfClass:[UIEvent class]]) {
        HKPrintUIEvent((UIEvent *)result, "        ");
    } else {
        NSString *desc = [result description];
        if (desc && desc.length) HKLog("      desc=%@", desc);
    }
}

// ---------- 打印事件入口（含过滤 + 分隔线） ----------
static void HKPrintEvent(void *event) {
    if (!event) return;
    uint32_t type = pGetType ? pGetType(event) : 0xFFFFFFFF;
    uint64_t sender = pGetSender ? pGetSender(event) : 0;
    if (type == 17) return;                          // compat 心跳
    if (type == 11 && sender == 0x8000000800a15173ull) return;  // digitizer 空闲
    double now = HKNow();
    if (now - gLastKeySec > 0.5) {
        HKLog("  ---- 按键簇分隔 ----");
    }
    gLastKeySec = now;
    HKPrintEventFields(event, 1);
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
static id HKImp3(id self, SEL _cmd, void *event) {
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
// UIApplication -sendEvent:（UIKit 分发最终入口）
static IMP gOrigSend;
static void HKImpSend(id self, SEL _cmd, UIEvent *event) {
    HKLog("[UIApp] sendEvent:");
    if (event) HKPrintUIEvent(event, "    ");
    ((void (*)(id, SEL, UIEvent *))gOrigSend)(self, _cmd, event);
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
        pGetChildren = (IOHIDEventGetChildren_t)dlsym(iokit, "IOHIDEventGetChildren");
        pGetChild = (IOHIDEventGetChild_t)dlsym(iokit, "IOHIDEventGetChild");
    }
    HKLog("==================================================");
    HKLog("HIDKeySniffer v1.0.8 已注入 %s (pid=%d)", [[[NSBundle mainBundle] bundleIdentifier] UTF8String], getpid());
    HKLog("容器日志路径: %s", gContainerPath);
    HKLog("IOKit解析: type=%d sender=%d int=%d float=%d children=%d",
          pGetType != NULL, pGetSender != NULL, pGetInt != NULL, pGetFloat != NULL, pGetChildren != NULL);
    HKLog("--- hook 开始 ---");
    HKHookSpec specs[] = {
        { "UIEventFetcher", "_receiveHIDEvent:", "^{__IOHIDEvent=}", &gOrig1, (IMP)HKImp1 },
        { "UIApplication", "handleKeyHIDEvent:", "^{__IOHIDEvent=}", &gOrig2, (IMP)HKImp2 },
        { "_UIHIDTransformer", "handleHIDEvent:", "^{__IOHIDEvent=}", &gOrig3, (IMP)HKImp3 },
        { "_UIUpdateHIDInput", "addEvent:", "^{__IOHIDEvent=}", &gOrig4, (IMP)HKImp4 },
        { "_UIUpdateHIDDigitizerInput", "addEvent:", "^{__IOHIDEvent=}", &gOrig5, (IMP)HKImp5 },
        { "HIDEventService", "dispatchEvent:", "v24@0:8@16", &gOrig6, (IMP)HKImp6 },
        { "UIApplication", "sendEvent:", "@16", &gOrigSend, (IMP)HKImpSend },
    };
    for (size_t i = 0; i < sizeof(specs) / sizeof(specs[0]); i++) HKSwizzleSpec(&specs[i]);
    HKLog("--- hook 结束 ---");
    HKLog("初始化完成。只按翻页器7键（每键按1次，间隔2秒），每组按键会打分隔线");
    HKLog("==================================================");
}
