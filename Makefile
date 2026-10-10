# HIDKeySniffer —— backboardd 层 HID 键码抓取（v1.0.0）
# 架构：
#   - 注入 backboardd（HID 事件源头，Filter=com.apple.backboardd）
#   - runtime 探测含 HID 的类 + 尝试 hook 候选方法（存在才 hook，不存在只打日志）
#   - 在回调里用 IOHIDEventGetType/GetSenderID/GetIntegerValue 读 type/senderID/keyCode/usage
#   - 日志写 /var/mobile/Documents/HIDKeySniffer.log（backboardd root 权限可写，Filza 可读）
#   - 目标：拿到翻页器 7 键的真实 HID 键码（音量+=0xE9 音量-=0xEA 上=0x52 下=0x51 左=0x50 右=0x4F 点击=0x28）
TARGET := iphone:clang:16.5:15.0
INSTALL_TARGET_PROCESSES := backboardd
THEOS_PACKAGE_SCHEME := roothide
PACKAGE_VERSION := 1.0.1

DEBUG = 0
ARCHS = arm64 arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = HIDKeySniffer

HIDKeySniffer_FILES = Tweak.xm
HIDKeySniffer_CFLAGS = -fobjc-arc -Wno-deprecated-declarations -Wno-unused-variable -Wno-unused-function
HIDKeySniffer_LDFLAGS = -Wl,-undefined,dynamic_lookup
HIDKeySniffer_FRAMEWORKS = Foundation
HIDKeySniffer_LIBRARIES = substrate

include $(THEOS_MAKE_PATH)/tweak.mk

# ---------- 强制 OpenStep 格式注入 Filter（只注入 backboardd）----------
before-package::
	printf '{ Filter = { Bundles = ( "com.apple.backboardd"); }; }\n' > "$(THEOS_STAGING_DIR)/Library/MobileSubstrate/DynamicLibraries/HIDKeySniffer.plist"
