# Makefile

# Goのビルド設定
GOARCH = amd64
GOOS = windows

# ビルドするファイルの名前
BINARY_NAME = shellcode_injection.exe

# デフォルトのターゲットを指定
all: build

# ビルドターゲット
build:
	GOARCH=$(GOARCH) GOOS=$(GOOS) go build -o $(BINARY_NAME) shellcode_injection.go

# クリーンターゲット
clean:
	rm -f $(BINARY_NAME)

# 再ビルドターゲット
rebuild: clean build
