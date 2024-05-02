TARGET = libjailbreak.dylib

#ADDITIONAL_FLAGS = -O3

# for debugging
ADDITIONAL_FLAGS = -g

CC = clang

CFLAGS = -framework Foundation -framework CoreServices -framework Security -framework IOKit -framework IOSurface -I../.include -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -arch arm64e -miphoneos-version-min=15.0 -fobjc-arc -dynamiclib -install_name @loader_path/$(TARGET) -I$(shell brew --prefix)/opt/libarchive/include $(ADDITIONAL_FLAGS)
LDFLAGS = -larchive -lbsm -L../.build -lchoma

sign: $(TARGET)
	@ldid -S $<

$(TARGET): $(wildcard src/*.c src/*.m src/*.S)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	@rm -f $(TARGET)
