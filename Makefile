# HIDKeySniffer v1.0.4 —— App 进程自 dump 诊断版
# 注入：番茄小说 com.dragon.read（翻页器 7 键事件必然到达的进程）
# 目的：dump 出 iOS16.4.1 真实 HID hook 点 + 7 键完整事件树（递归打印子事件）
# 安全：只读 + 打日志，不吞事件不修改，原调用原样放行
# 日志：App 容器 Documents/HIDKeySniffer.log（保底可写）+ /var/mobile/Documents（试写）
TARGET := iphone:clang:16.5:15.0
THEOS_PACKAGE_SCHEME := roothide
PACKAGE_VERSION := 1.0.7

DEBUG = 0
ARCHS = arm64 arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = HIDKeySniffer

HIDKeySniffer_FILES = Tweak.xm
HIDKeySniffer_CFLAGS = -fobjc-arc -Wno-deprecated-declarations -Wno-unused-variable -Wno-unused-function
HIDKeySniffer_LDFLAGS = -Wl,-undefined,dynamic_lookup
HIDKeySniffer_FRAMEWORKS = Foundation UIKit
HIDKeySniffer_LIBRARIES = substrate

include $(THEOS_MAKE_PATH)/tweak.mk

# ---------- 强制 OpenStep 格式注入 Filter（只注入番茄小说）----------
before-package::
	printf '{ Filter = { Bundles = ( "com.dragon.read"); }; }\n' > "$(THEOS_STAGING_DIR)/Library/MobileSubstrate/DynamicLibraries/HIDKeySniffer.plist"
