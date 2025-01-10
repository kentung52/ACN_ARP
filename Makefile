# 編譯器
CC = gcc

# 編譯選項
CFLAGS = -Wall -Wextra -O2

# 目標可執行檔
TARGET = arp

# 原始碼檔案
SRCS = main.c

# 目標檔案
OBJS = $(SRCS:.c=.o)

# 預設規則：編譯可執行檔
all: $(TARGET)

# 編譯可執行檔規則
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

# 編譯 .o 檔案規則
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 清理規則
clean:
	rm -f $(OBJS) $(TARGET)
