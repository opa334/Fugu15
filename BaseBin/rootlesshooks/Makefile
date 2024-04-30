TARGET := iphone:clang:16.5:15.0
INSTALL_TARGET_PROCESSES = lsd cfprefsd
FINALPACKAGE = 1
THEOS_PACKAGE_SCHEME = rootless
ARCHS = arm64 arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = rootlesshooks

rootlesshooks_FILES = $(wildcard *.x)
rootlesshooks_CFLAGS = -fobjc-arc -I../.include
rootlesshooks_LDFLAGS = -rpath @loader_path/fallback -L../libjailbreak -ljailbreak

include $(THEOS_MAKE_PATH)/tweak.mk
