#all: mktemp choma

#mktemp:
#	rm -rf .build-dir
#	mkdir .build-dir

#choma:
#	$(MAKE) -C ChOma TARGET=ios DISABLE_SIGNING=1 DYLIB_LDFLAGS="-install_name @loader_path/libchoma.dylib" $@

all: basebin.tar

subprojects: ChOma XPF opainject libjailbreak systemhook forkfix launchdhook boomerang jbctl idownloadd watchdoghook rootlesshooks

ChOma: .build .include
	@$(MAKE) -C ChOma TARGET=ios DISABLE_SIGNING=1 DISABLE_TESTS=1 DYLIB_LDFLAGS="-install_name @loader_path/libchoma.dylib"
	@cp ChOma/output/ios/lib/libchoma.dylib .build
	@cp -r ChOma/output/ios/include/choma .include

XPF: .build .include ChOma
	@$(MAKE) -C XPF libxpf.dylib CHOMA_DYLIB_PATH="../.build"
	@cp XPF/libxpf.dylib .build
	@mkdir -p .include/xpf
	@cp XPF/src/xpf.h .include/xpf

opainject: .build .include
	$(MAKE) -C opainject FINALPACKAGE=1
	@cp opainject/.theos/obj/opainject .build

libjailbreak: .build .include ChOma
	$(MAKE) -C libjailbreak
	@cp libjailbreak/libjailbreak.dylib .build
	@mkdir -p .include/libjailbreak
	@cp libjailbreak/src/*.h .include/libjailbreak

systemhook: .build .include libjailbreak
	$(MAKE) -C systemhook
	@cp systemhook/systemhook.dylib .build

forkfix: .build .include libjailbreak
	$(MAKE) -C forkfix
	@cp forkfix/forkfix.dylib .build

launchdhook: .build .include libjailbreak
	$(MAKE) -C launchdhook
	@cp launchdhook/launchdhook.dylib .build

boomerang: .build .include libjailbreak
	$(MAKE) -C boomerang
	@cp boomerang/boomerang .build

jbctl: .build .include libjailbreak
	$(MAKE) -C jbctl
	@cp jbctl/jbctl .build

idownloadd: .build .include libjailbreak
	$(MAKE) -C idownloadd
	@cp idownloadd/idownloadd .build

watchdoghook: .build .include libjailbreak
	$(MAKE) -C watchdoghook
	@cp watchdoghook/watchdoghook.dylib .build

rootlesshooks: .build .include 
	$(MAKE) -C rootlesshooks
	@cp rootlesshooks/.theos/obj/rootlesshooks.dylib .build

.build:
	rm -rf .build
	mkdir -p .build
	cp -r _external/basebin/* .build
	cp _external/basebin/.version .build

.include:
	rm -rf .include
	mkdir -p .include
	cp -r _external/include/* .include
# If the SDK already ships XPC (it does so in iOS 17.4+), remove the local copy of it
ifneq (,$(wildcard $(shell xcrun --sdk iphoneos --show-sdk-path)/usr/include/xpc.modulemap))
	rm -rf .include/xpc
endif

basebin.tc: subprojects
	trustcache create .build/basebin.tc .build
	cp .build/basebin.tc basebin.tc

basebin.tar: basebin.tc
	@DYLD_FALLBACK_LIBRARY_PATH="." ./tar --transform "s/^.build/basebin/" -cvf "basebin.tar" ".build" --owner=0 --group=0

clean:
	@$(MAKE) -C ChOma $@
	@$(MAKE) -C XPF $@
	@$(MAKE) -C opainject $@
	@$(MAKE) -C libjailbreak $@
	@$(MAKE) -C systemhook $@
	@$(MAKE) -C forkfix $@
	@$(MAKE) -C launchdhook $@
	@$(MAKE) -C boomerang $@
	@$(MAKE) -C jbctl $@
	@$(MAKE) -C idownloadd $@
	@$(MAKE) -C watchdoghook $@
	@$(MAKE) -C rootlesshooks $@
	@rm -rf .build
	@rm -rf .include
	@rm -rf basebin.tar
	@rm -rf basebin.tc

.PHONY: clean .build .include ChOma XPF opainject libjailbreak systemhook forkfix launchdhook boomerang jbctl idownloadd watchdoghook rootlesshooks basebin.tc basebin.tar