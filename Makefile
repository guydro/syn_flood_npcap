CC = gcc
LNK = $(CC)
NASM = nasm
CFLAGS = -ggdb -Wall -O0 -c
LNKFLAGS = $(CLFAGS)
CLIBS = -lws2_32 -liphlpapi -I C:\Users\Guy\DDOS_TV_v4\Include -L C:\Users\Guy\DDOS_TV_v4\Lib\x64 -lwpcap
SRCs = $(wildcard *.c)
OBJs := $(SRCs:%.c=%.o)

all: main

%.o: %.c
		$(CC) $(CFLAGS) $^ -o $@ $(CLIBS)

%.o: %.asm
		$(NASM) $(ASMFLAGS) $< -o $@

dev_lst: get_device_list.c
		$(LNK) $(LNKFLAGS) $^ -o $@ $(CLIBS)

main :  main.o
		$(LNK) $(LNKFLAGS) $^ -o $@ $(CLIBS)

clean:
		rm *.o -f