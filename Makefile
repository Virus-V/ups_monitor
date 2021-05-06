PROG = helloworld

CFLAGS += -I. -Iusb -Icjson -lusb -lpthread

SRCS != find usb cjson -name "*.c"
SRCS += main.c
OBJS := $(SRCS:S/.c/.o/g)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $(.TARGET) $(.ALLSRC)


