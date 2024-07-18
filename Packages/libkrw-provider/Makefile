TARGET = libkrw-dopamine.dylib
CC = clang

CFLAGS = -I../../BaseBin/.include -Isrc -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -arch arm64e -miphoneos-version-min=15.0 -fobjc-arc -O2
LDFLAGS = -dynamiclib -rpath /var/jb/usr/lib -L../../BaseBin/.build -ljailbreak

all: $(TARGET) sign

sign: $(TARGET)
	@ldid -S $^

$(TARGET): $(wildcard src/*.c)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^
	install_name_tool -change "@loader_path/libjailbreak.dylib" "@rpath/libjailbreak.dylib" $@

clean:
	@rm -f $(TARGET)
	@rm -f libkrw-dopamine.deb

package: all
	@mkdir -p .package/DEBIAN
	@mkdir -p .package/var/jb/usr/lib/libkrw
	@cp control .package/DEBIAN/control
	@cp libkrw-dopamine.dylib .package/var/jb/usr/lib/libkrw/libkrw-dopamine.dylib
	@dpkg-deb --root-owner-group -Zzstd -b .package ./libkrw-dopamine.deb
	@rm -rf .package
