#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
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
// HIDKeySniffer v1.0.4 —— App 进程自 dump 诊断版
// 注入：番茄小说 com.dragon.read（7 键事件必然到达的进程）
// 目的：dump 出 iOS16.4.1 真实 HID hook 点 + 7 键完整事件树 + 设备指纹
// 安全：只读 + 打日志，不吞事件不修改，原调用原样放行
// 日志：App 容器 Documents（保底可写）+ /var/mobile/Documents（试写）
// ============================================================

// ---------- 日志（双路径，App 沙盒内至少容器 Documents 可写） ----------
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

// ---------- IOKit 函数（dlsym 动态解析，避免头文件依赖） ----------
typedef uint32_t (*IOHIDEventGetType_t)(void *);
typedef uint64_t (*IOHIDEventGetSenderID_t)(void *);
typedef uint32_t (*IOHIDEventGetIntegerValue_t)(void *, uint32_t);
typedef void *(*IOHIDEventGetChild_t)(void *, uint32_t);
typedef void *(*IOHIDEventGetNext_t)(void *);
static IOHIDEventGetType_t pGetType = NULL;
static IOHIDEventGetSenderID_t pGetSender = NULL;
static IOHIDEventGetIntegerValue_t pGetInt = NULL;
static IOHIDEventGetChild_t pGetChild = NULL;
static IOHIDEventGetNext_t pGetNext = NULL;

// IOHIDEvent 字段（IOHIDEventField 公共值，供参考）
// 0x01 PositionX 0x02 PositionY 0x03 ButtonNumber 0x04 ButtonState
// 0x0A ScrollX 0x0B ScrollY 0x0E KeyboardUsagePage 0x0F KeyboardKeyCode 0x10 KeyboardUsage
static void HKPrintEventTree(void *event, int depth) {
    if (!event || depth > 4) return;
    uint32_t type = pGetType ? pGetType(event) : 0xFFFFFFFF;
    uint64_t sender = pGetSender ? pGetSender(event) : 0;
    uint32_t v;
    v = pGetInt ? pGetInt(event, 0x0E) : 0; uint32_t usagePage = v;
    v = pGetInt ? pGetInt(event, 0x0F) : 0; uint32_t keyCode = v;
    v = pGetInt ? pGetInt(event, 0x10) : 0; uint32_t usage = v;
    v = pGetInt ? pGetInt(event, 0x01) : 0; uint32_t posX = v;
    v = pGetInt ? pGetInt(event, 0x02) : 0; uint32_t posY = v;
    v = pGetInt ? pGetInt(event, 0x03) : 0; uint32_t btn = v;
    v = pGetInt ? pGetInt(event, 0x04) : 0; uint32_t btnState = v;
    v = pGetInt ? pGetInt(event, 0x0A) : 0; uint32_t scrollX = v;
    v = pGetInt ? pGetInt(event, 0x0B) : 0; uint32_t scrollY = v;
    char pad[16];
    memset(pad, ' ', depth * 2);
    pad[depth * 2] = 0;
    HKLog("%s[evt] type=%u sender=0x%llx usagePage=0x%x keyCode=0x%x usage=0x%x pos=(%u,%u) btn=%u st=%u scroll=(%u,%u)",
          pad, type, (unsigned long long)sender, usagePage, keyCode, usage,
          posX, posY, btn, btnState, scrollX, scrollY);
    if (pGetChild && pGetNext) {
        void *child = pGetChild(event, 0);
        while (child) {
            HKPrintEventTree(child, depth + 1);
            child = pGetNext(child);
        }
    }
}

// ---------- 独立 orig/imp 对（每个候选方法独立保存原实现） ----------
static IMP gOrig1;
static void *HKImp1(id self, SEL _cmd, void *event) {
    HKLog("[evt-入口] UIEventFetcher _receiveHIDEvent:");
    HKPrintEventTree(event, 0);
    return ((void *(*)(id, SEL, void *))gOrig1)(self, _cmd, event);
}
static IMP gOrig2;
static void *HKImp2(id self, SEL _cmd, id event) {
    HKLog("[evt-入口] UIApplication handleKeyHIDEvent: 参数isa=%s",
          event ? object_getClassName(event) : "nil");
    HKPrintEventTree((__bridge void *)event, 0);
    return ((void *(*)(id, SEL, id))gOrig2)(self, _cmd, event);
}
static IMP gOrig3;
static void *HKImp3(id self, SEL _cmd, void *event) {
    HKLog("[evt-入口] UIApplication handleHIDEvent:");
    HKPrintEventTree(event, 0);
    return ((void *(*)(id, SEL, void *))gOrig3)(self, _cmd, event);
}
static IMP gOrig4;
static void *HKImp4(id self, SEL _cmd, id events) {
    HKLog("[evt-入口] UIEventFetcher filterEvents: 参数isa=%s",
          events ? object_getClassName(events) : "nil");
    if ([events isKindOfClass:[NSArray class]]) {
        HKLog("[evt-入口] filterEvents: 数组元素数=%lu", (unsigned long)[(NSArray *)events count]);
        for (NSUInteger i = 0; i < [(NSArray *)events count] && i < 8; i++) {
            id item = [(NSArray *)events objectAtIndex:i];
            if (item == nil) { HKLog("  [%lu] nil", (unsigned long)i); continue; }
            CFTypeID tid = CFGetTypeID((__bridge CFTypeRef)item);
            HKLog("  [%lu] isa=%s cfTypeID=%lu", (unsigned long)i, object_getClassName(item), (unsigned long)tid);
        }
    }
    return ((void *(*)(id, SEL, id))gOrig4)(self, _cmd, events);
}
static IMP gOrig5;
static void *HKImp5(id self, SEL _cmd, void *event) {
    HKLog("[evt-入口] BKSHIDEventRouterManager handleHIDEvent:");
    HKPrintEventTree(event, 0);
    return ((void *(*)(id, SEL, void *))gOrig5)(self, _cmd, event);
}
static IMP gOrig6;
static void *HKImp6(id self, SEL _cmd, void *event) {
    HKLog("[evt-入口] BKSHIDEventRouter handleEvent:");
    HKPrintEventTree(event, 0);
    return ((void *(*)(id, SEL, void *))gOrig6)(self, _cmd, event);
}

// hook 单个候选：仅当方法存在 且 恰好 1 个对象参数（签名 v24@0:8@16 这类）才替换
static void HKSwizzle(Class cls, const char *selName, IMP *origSlot, IMP newImp) {
    if (!cls) { HKLog("[探测] 类不存在 -%s 跳过", selName); return; }
    SEL sel = sel_registerName(selName);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) { HKLog("[探测] %s -%s 不存在，跳过", class_getName(cls), selName); return; }
    const char *enc = method_getTypeEncoding(m);
    // 数 @ 个数：格式 返回@self:_cmd:arg1...  => arg 数 = @数 - 2
    int ats = 0;
    for (const char *p = enc; p && *p; p++) if (*p == '@') ats++;
    if (ats - 2 != 1) {
        HKLog("[探测] %s -%s 签名=%s（参数数=%d）跳过，待下版处理", class_getName(cls), selName, enc, ats - 2);
        return;
    }
    *origSlot = method_getImplementation(m);
    method_setImplementation(m, newImp);
    HKLog("[探测] %s -%s 已hook ✓ 签名=%s", class_getName(cls), selName, enc);
}

// 枚举含 HID/Event/Touch/Key 的类及其方法（供确认真实 hook 点）
static void HKDumpClasses(void) {
    unsigned int count = 0;
    Class *classes = objc_copyClassList(&count);
    int printed = 0;
    for (unsigned int i = 0; i < count && printed < 60; i++) {
        const char *name = class_getName(classes[i]);
        if (!strstr(name, "HID") && !strstr(name, "Event") && !strstr(name, "Touch")
            && !strstr(name, "Key") && !strstr(name, "BKS") && !strstr(name, "IOKit")) continue;
        // 只打印关注类
        if (!strstr(name, "HID") && !strstr(name, "EventFetcher") && !strstr(name, "UIApplication")
            && !strstr(name, "BKSHID") && !strstr(name, "BKHID")) continue;
        unsigned int mc = 0;
        Method *ms = class_copyMethodList(classes[i], &mc);
        int shown = 0;
        char line[2048];
        int off = 0;
        off += snprintf(line + off, sizeof(line) - off, "[类] %s:", name);
        for (unsigned int j = 0; j < mc && shown < 24; j++) {
            const char *mn = sel_getName(method_getName(ms[j]));
            if (!strstr(mn, "HID") && !strstr(mn, "Event") && !strstr(mn, "Key")
                && !strstr(mn, "Touch") && !strstr(mn, "filter")) continue;
            const char *enc = method_getTypeEncoding(ms[j]);
            int l = snprintf(line + off, sizeof(line) - off, " -%s %s", mn, enc ? enc : "?");
            off += l;
            if (off > (int)sizeof(line) - 200) break;
            shown++;
        }
        if (shown) HKLog("%s", line);
        free(ms);
        printed++;
    }
    free(classes);
}

__attribute__((constructor))
static void HKInit() {
    NSString *home = NSHomeDirectory();
    NSString *docDir = [home stringByAppendingPathComponent:@"Documents"];
    NSString *logPath = [docDir stringByAppendingPathComponent:@"HIDKeySniffer.log"];
    gContainerPath = strdup([logPath UTF8String]);

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW);
    if (iokit) {
        pGetType = (IOHIDEventGetType_t)dlsym(iokit, "IOHIDEventGetType");
        pGetSender = (IOHIDEventGetSenderID_t)dlsym(iokit, "IOHIDEventGetSenderID");
        pGetInt = (IOHIDEventGetIntegerValue_t)dlsym(iokit, "IOHIDEventGetIntegerValue");
        pGetChild = (IOHIDEventGetChild_t)dlsym(iokit, "IOHIDEventGetChild");
        pGetNext = (IOHIDEventGetNext_t)dlsym(iokit, "IOHIDEventGetNext");
    }
    HKLog("==================================================");
    HKLog("HIDKeySniffer v1.0.4 已注入 %s (pid=%d)", [[[NSBundle mainBundle] bundleIdentifier] UTF8String], getpid());
    HKLog("容器日志路径: %s", gContainerPath);
    HKLog("全局日志路径: %s", gGlobalPath);
    HKLog("IOKit解析: type=%d sender=%d int=%d child=%d next=%d",
          pGetType != NULL, pGetSender != NULL, pGetInt != NULL, pGetChild != NULL, pGetNext != NULL);
    HKLog("--- 类/方法 dump 开始 ---");
    HKDumpClasses();
    HKLog("--- 类/方法 dump 结束 ---");
    HKLog("--- hook 开始 ---");
    HKSwizzle(NSClassFromString(@"UIEventFetcher"), "_receiveHIDEvent:", &gOrig1, (IMP)HKImp1);
    HKSwizzle(NSClassFromString(@"UIApplication"), "handleKeyHIDEvent:", &gOrig2, (IMP)HKImp2);
    HKSwizzle(NSClassFromString(@"UIApplication"), "handleHIDEvent:", &gOrig3, (IMP)HKImp3);
    HKSwizzle(NSClassFromString(@"UIEventFetcher"), "filterEvents:", &gOrig4, (IMP)HKImp4);
    HKSwizzle(NSClassFromString(@"BKSHIDEventRouterManager"), "handleHIDEvent:", &gOrig5, (IMP)HKImp5);
    HKSwizzle(NSClassFromString(@"BKSHIDEventRouter"), "handleEvent:", &gOrig6, (IMP)HKImp6);
    HKLog("--- hook 结束 ---");
    HKLog("初始化完成。关闭辅助触控，在番茄小说里 7 键各按 2~3 下");
    HKLog("==================================================");
}
