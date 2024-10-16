# 设置 Npcap 的安装路径

NPCAP_PATH := D:/Program Files/npcap-sdk

# 设置源文件和输出文件
SRC = main.c
OUT = main.exe

# 编译器和编译选项
CC = gcc
CFLAGS = -I"$(NPCAP_PATH)/include" -Wall
LDFLAGS = -L"$(NPCAP_PATH)/lib" -lwpcap -lws2_32

# 默认目标
all: $(OUT)

# 编译规则
$(OUT): $(SRC)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# 清理目标
clean:
	rm -f $(OUT)
