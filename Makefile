TARGET := iphone:clang:latest:14.0
INSTALL_TARGET_PROCESSES = kugou

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = HookKuGou

$(TWEAK_NAME)_FILES = Tweak_runtime.m fishhook.c #Tweak.x #
$(TWEAK_NAME)_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk

# 设备信息
export THEOS_DEVICE_IP = 127.0.0.1
export THEOS_DEVICE_PORT = 2222
THEOS_DEVICE_USER ?= mobile

# 包模式配置
ROOTHIDE = 0
ROOTLESS = 1

ifeq ($(ROOTHIDE),1)
    THEOS_PACKAGE_SCHEME = roothide
endif

ifeq ($(ROOTLESS),1)
    THEOS_PACKAGE_SCHEME = rootless
endif

ifeq ($(THEOS_PACKAGE_SCHEME),rootless)
    ARCHS = arm64 arm64e
else ifeq ($(THEOS_PACKAGE_SCHEME),roothide)
    ARCHS = arm64 arm64e
else
    ARCHS = armv7 armv7s arm64 arm64e
endif
