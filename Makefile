# Quotapus build. Needs macOS 26 and the Xcode command line tools (xcode-select --install).
APP      := build/Quotapus.app
DEST     := $(HOME)/Applications/Quotapus.app
MIN      := 26.0
# Ad-hoc signing ("-") works for an app you build yourself. macOS then asks once after each
# rebuild before Quotapus can read the logins it saved. Sign with your own certificate to avoid that:
# make install SIGN="Apple Development: Name (TEAMID)"
SIGN     ?= -

.PHONY: build install uninstall clean

build:
	mkdir -p $(APP)/Contents/MacOS build/obj
	swiftc -O -target arm64-apple-macos$(MIN) Sources/Quotapus.swift -o build/obj/Quotapus-arm64
	swiftc -O -target x86_64-apple-macos$(MIN) Sources/Quotapus.swift -o build/obj/Quotapus-x86_64
	lipo -create build/obj/Quotapus-arm64 build/obj/Quotapus-x86_64 -output $(APP)/Contents/MacOS/Quotapus
	cp Sources/Info.plist $(APP)/Contents/
	codesign --force --sign "$(SIGN)" $(APP)

install: build
	-pkill -x Quotapus
	rm -rf $(DEST) && mkdir -p $(HOME)/Applications && cp -R $(APP) $(DEST)
	open $(DEST)

# Removes the app, its settings and the logins it saved. Claude Code's own login is not touched.
uninstall:
	-pkill -x Quotapus
	rm -rf $(DEST)
	-defaults delete io.github.datasadeqist.quotapus 2>/dev/null
	-while security delete-generic-password -s Quotapus >/dev/null 2>&1; do :; done

clean:
	rm -rf build
