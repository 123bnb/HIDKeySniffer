#import <objc/runtime.h>
#import <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <sys/time.h>
#include <unistd.h>

// ============================================================
// HIDKeySniffer v1.0.0 —— backboardd 层 HID 键码抓取
// 目标：拿到蓝牙翻页器 7 键的真实 HID 键码（usage/keyCode）
// 日志：/var/mobile/Documents/HIDKeySniffer.log（root 可写，Filza 可读）
// 安全：只读 + 打日志，不吞事件不修改，原调用原样放行
// ============================================================

#define HK_LOG_PATH "/var/mobile/Documents/HIDKeySniffer.log"

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
    FILE *f = fopen(HK_LOG_PATH, "a");
    if (f) {
        fprintf(f, "%s.%03d %s\n", tbuf, (int)(tv.tv_usec / 1000), buf);
        fclose(f);
    }
}

// ---------- IOKit 函数（dlsym 动态解析，避免头文件依赖） ----------
typedef uint32_t (*IOHIDEventGetType_t)(void *);
typedef uint64_t (*IOHIDEventGetSenderID_t)(void *);
typedef uint32_t (*IOHIDEventGetIntegerValue_t)(void *, uint32_t);
typedef uint64_t (*IOHIDEventGetTime_t)(void *);
static IOHIDEventGetType_t pGetType = NULL;
static IOHIDEventGetSenderID_t pGetSender = NULL;
static IOHIDEventGetIntegerValue_t pGetInt = NULL;
static IOHIDEventGetTime_t pGetTime = NULL;

// IOHIDEvent 字段（IOHIDEventField 公共值）：
//   kIOHIDEventFieldKeyboardUsagePage = 0x0E
//   kIOHIDEventFieldKeyboardKeyCode  = 0x0F
//   kIOHIDEventFieldKeyboardUsage    = 0x10
static void HKHandleEvent(void *event) {
    if (!event || !pGetType || !pGetInt || !pGetSender) return;
    uint32_t type = pGetType(event);
    uint64_t sender = pGetSender(event);
    uint32_t usagePage = pGetInt(event, 0x0E);
    uint32_t keyCode = pGetInt(event, 0x0F);
    uint32_t usage = pGetInt(event, 0x10);
    HKLog("HIDEvent type=%u sender=0x%llx usagePage=0x%x keyCode=0x%x usage=0x%x",
          type, (unsigned long long)sender, usagePage, keyCode, usage);
}

// ---------- 独立 orig/imp 对（每个候选方法独立保存原实现，避免互相覆盖递归） ----------
static void *(*gOrig1)(id, SEL, id);
static void *HKImp1(id self, SEL _cmd, id event) {
    HKHandleEvent((void *)event);
    return gOrig1(self, _cmd, event);
}
static void *(*gOrig2)(id, SEL, id);
static void *HKImp2(id self, SEL _cmd, id event) {
    HKHandleEvent((void *)event);
    return gOrig2(self, _cmd, event);
}
static void *(*gOrig3)(id, SEL, id);
static void *HKImp3(id self, SEL _cmd, id event) {
    HKHandleEvent((void *)event);
    return gOrig3(self, _cmd, event);
}
static void *(*gOrig4)(id, SEL, id);
static void *HKImp4(id self, SEL _cmd, id event) {
    HKHandleEvent((void *)event);
    return gOrig4(self, _cmd, event);
}
static void *(*gOrig5)(id, SEL, id);
static void *HKImp5(id self, SEL _cmd, id event) {
    HKHandleEvent((void *)event);
    return gOrig5(self, _cmd, event);
}

// 探测并 hook：方法存在才替换，不存在只打日志（避免 Logos 对不存在 selector 意外 addMethod）
static void HKSwizzle(Class cls, const char *selName, void *(*origSlot)(id, SEL, id), IMP newImp) {
    if (!cls) { HKLog("[探测] 类不存在 (className=?) -%s 跳过", selName); return; }
    SEL sel = sel_registerName(selName);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) { HKLog("[探测] %s -%s 不存在，跳过", class_getName(cls), selName); return; }
    *origSlot = (void *(*)(id, SEL, id))method_getImplementation(m);
    method_setImplementation(m, newImp);
    HKLog("[探测] %s -%s 已hook ✓", class_getName(cls), selName);
}

__attribute__((constructor))
static void HKInit() {
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW);
    if (iokit) {
        pGetType = (IOHIDEventGetType_t)dlsym(iokit, "IOHIDEventGetType");
        pGetSender = (IOHIDEventGetSenderID_t)dlsym(iokit, "IOHIDEventGetSenderID");
        pGetInt = (IOHIDEventGetIntegerValue_t)dlsym(iokit, "IOHIDEventGetIntegerValue");
        pGetTime = (IOHIDEventGetTime_t)dlsym(iokit, "IOHIDEventGetTime");
    }
    HKLog("==================================================");
    HKLog("HIDKeySniffer v1.0.0 已注入 backboardd (pid=%d)", getpid());
    HKLog("IOKit解析: type=%d sender=%d int=%d time=%d",
          pGetType != NULL, pGetSender != NULL, pGetInt != NULL, pGetTime != NULL);

    // 诊断：列出含 HID 的类（供下版锁定正确 hook 点）
    int count = 0;
    Class *classes = objc_copyClassList(&count);
    int printed = 0;
    for (int i = 0; i < count && printed < 50; i++) {
        const char *name = class_getName(classes[i]);
        if (strstr(name, "HID")) {
            HKLog("[类] %s", name);
            printed++;
        }
    }
    free(classes);

    // hook 候选（存在才 hook，多个候选提高命中率）
    HKSwizzle(NSClassFromString(@"BKHIDEventRouterManager"), "handleHIDEvent:", &gOrig1, (IMP)HKImp1);
    HKSwizzle(NSClassFromString(@"BKHIDEventDeliveryManager"), "handleHIDEvent:", &gOrig2, (IMP)HKImp2);
    HKSwizzle(NSClassFromString(@"BKHIDEventRouter"), "handleEvent:", &gOrig3, (IMP)HKImp3);
    HKSwizzle(NSClassFromString(@"BKSHIDEventRouterManager"), "handleHIDEvent:", &gOrig4, (IMP)HKImp4);
    HKSwizzle(NSClassFromString(@"BKHIDEventDeliveryManager"), "deliverEvent:", &gOrig5, (IMP)HKImp5);

    HKLog("初始化完成。请关闭辅助触控（如已开），用翻页器 7 键各按 2~3 下，日志自动追加");
    HKLog("==================================================");
}
