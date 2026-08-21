TARGET = iphone:clang:latest:14.0
ARCHS = arm64
THEOS_DEVICE_IP = localhost
THEOS_DEVICE_PORT = 2222

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = iboxhook

iboxhook_FILES = hook.mm
iboxhook_CFLAGS = -fobjc-arc -Wno-unused-variable -Wno-unused-function
iboxhook_CCFLAGS = -std=c++17
iboxhook_FRAMEWORKS = Foundation UIKit CoreGraphics
iboxhook_LIBRARIES = dobby

include $(THEOS_MAKE_PATH)/tweak.mk
