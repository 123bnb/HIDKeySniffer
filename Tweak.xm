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
// HIDKeySniffer v1.0.5 —— App 进程自 dump 诊断版（基于 v1.0.4 实机签名修正）
// 注入：番茄小说 com.dragon.read
// v1.0.4 dump 已确认的 iOS16.4.1 真实入口（签名全部来自实机日志）：
//   UIEventFetcher         -_receiveHIDEvent:     v24@0:8^{__IOHIDEvent=}16   ← 所有HID事件唯一入口
//   UIApplication          -handleKeyHIDEvent:    v24@0:8^{__IOHIDEvent=}16   ← 键盘类事件
//   _UIHIDTransformer      -handleHIDEvent:       @24@0:8^{__IOHIDEvent=}16   ← UIKit转换入口
//   _UIUpdateHIDInput      -addEvent:             v24@0:8^{__IOHIDEvent=}16
//   _UIUpdateHIDDigitizerInput -addEvent:         v24@0:8^{__IOHIDEvent=}16
//   HIDEventService        -dispatchEvent:        v24@0:8@16                  ← 设备服务派发(id参数)
// 安全：只读 + 打日志，不吞事件不修改，原调用原样放行
// ============================================================

// ---------- 日志（双路径） ----------
static const char *gContainerPath = NULL;
static const char *gGlobalPath = "/var/mobile/Documents/HIDKeySniffer.log";

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
    const char *paths[2];
    int n = 0;
    if (gContainerPath) paths[n++] = gContainerPath;
    paths[n++] = gGlobalPath;
    for (int i = 0; i < n; i++) {
        FILE *f = fopen(paths[i], "a");
        if (f) {
            fprintf(f, "%s.%03d %s\n", tbuf, (int)(tv.tv_usec / 1000), buf);
            fclose(f);
        }
    }
}

// ---------- IOKit 函数（dlsym） ----------
typedef uint32_t (*IOHIDEventGetType_t)(void *);
typedef uint64_t (*IOHIDEventGetSenderID_t)(void *);
typedef uint32_t (*IOHIDEventGetIntegerValue_t)(void *, uint32_t);
typedef double (*IOHIDEventGetFloatValue_t)(void *, uint32_t);
static IOHIDEventGetType_t pGetType = NULL;
static IOHIDEventGetSenderID_t pGetSender = NULL;
static IOHIDEventGetIntegerValue_t pGetInt = NULL;
static IOHIDEventGetFloatValue_t pGetFloat = NULL;

// ---------- 事件打印（IOHIDEventRef） ----------
static void HKPrintEvent(void *event) {
    if (!event) { HKLog("    event=NULL"); return; }
    uint32_t type = pGetType ? pGetType(event) : 0xFFFFFFFF;
    uint64_t sender = pGetSender ? pGetSender(event) : 0;
    Class isa = object_getClass((__bridge id)event);
    HKLog("    type=%u sender=0x%llx isa=%s",
          type, (unsigned long long)sender, isa ? class_getName(isa) : "?");
    if (!pGetInt) return;
    uint32_t usagePage = pGetInt(event, 0x0E);
    uint32_t keyCode  = pGetInt(event, 0x0F);
    uint32_t usage    = pGetInt(event, 0x10);
    uint32_t posX     = pGetInt(event, 0x01);
    uint32_t posY     = pGetInt(event, 0x02);
    uint32_t btn      = pGetInt(event, 0x03);
    uint32_t btnState = pGetInt(event, 0x04);
    uint32_t sx       = pGetInt(event, 0x0A);
    uint32_t sy       = pGetInt(event, 0x0B);
    HKLog("    usagePage=0x%x keyCode=0x%x usage=0x%x pos=(%u,%u) btn=%u st=%u scroll=(%u,%u)",
          usagePage, keyCode, usage, posX, posY, btn, btnState, sx, sy);
    if (pGetFloat) {
        double fx = pGetFloat(event, 0x23);
        double fy = pGetFloat(event, 0x24);
        if (fx != 0.0 || fy != 0.0) {
            HKLog("    floatX=%f floatY=%f", fx, fy);
        }
    }
}

// ---------- 独立 orig/imp 对 ----------
static IMP gOrig1;
static void *HKImp1(id self, SEL _cmd, void *event) {
    HKLog("[入口] UIEventFetcher -_receiveHIDEvent:");
    HKPrintEvent(event);
    return ((void *(*)(id, SEL, void *))gOrig1)(self, _cmd, event);
}
static IMP gOrig2;
static void *HKImp2(id self, SEL _cmd, void *event) {
    HKLog("[入口] UIApplication -handleKeyHIDEvent:");
    HKPrintEvent(event);
    return ((void *(*)(id, SEL, void *))gOrig2)(self, _cmd, event);
}
static IMP gOrig3;
static void *HKImp3(id self, SEL _cmd, void *event) {
    HKLog("[入口] _UIHIDTransformer -handleHIDEvent:");
    HKPrintEvent(event);
    return ((void *(*)(id, SEL, void *))gOrig3)(self, _cmd, event);
}
static IMP gOrig4;
static void *HKImp4(id self, SEL _cmd, void *event) {
    HKLog("[入口] _UIUpdateHIDInput -addEvent:");
    HKPrintEvent(event);
    return ((void *(*)(id, SEL, void *))gOrig4)(self, _cmd, event);
}
static IMP gOrig5;
static void *HKImp5(id self, SEL _cmd, void *event) {
    HKLog("[入口] _UIUpdateHIDDigitizerInput -addEvent:");
    HKPrintEvent(event);
    return ((void *(*)(id, SEL, void *))gOrig5)(self, _cmd, event);
}
static IMP gOrig6;
static void *HKImp6(id self, SEL _cmd, id evt) {
    HKLog("[入口] HIDEventService -dispatchEvent:");
    if (evt) {
        Class isa = object_getClass(evt);
        HKLog("    isa=%s", isa ? class_getName(isa) : "?");
        // 尝试安全调用 HIDEvent 类的无参字段方法（dump 已见其存在）
        SEL s1 = NSSelectorFromString(@"keyboardMouseKeyToggle");
        SEL s2 = NSSelectorFromString(@"digitizerTouch");
        if ([evt respondsToSelector:s1]) {
            uint32_t (*f)(id, SEL) = (uint32_t (*)(id, SEL))objc_msgSend;
            HKLog("    keyboardMouseKeyToggle=%u", f(evt, s1));
        }
        if ([evt respondsToSelector:s2]) {
            uint32_t (*f)(id, SEL) = (uint32_t (*)(id, SEL))objc_msgSend;
            HKLog("    digitizerTouch=%u", f(evt, s2));
        }
    } else {
        HKLog("    evt=NULL");
    }
    return ((void *(*)(id, SEL, id))gOrig6)(self, _cmd, evt);
}

// ---------- hook：按 v1.0.4 dump 出的真实签名（needle 匹配）----------
typedef struct {
    const char *clsName;
    const char *selName;
    const char *encNeedle;   // 期望的 typeEncoding 特征
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
    HKLog("HIDKeySniffer v1.0.5 已注入 %s (pid=%d)", [[[NSBundle mainBundle] bundleIdentifier] UTF8String], getpid());
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
    HKLog("初始化完成。关闭辅助触控，在番茄小说里 7 键各按 2~3 下");
    HKLog("==================================================");
}
