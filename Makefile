PROG = helloworld

CFLAGS += -I. -I/usr/local/include -L/usr/local/lib -Iusb -Icjson -lusb -lpthread -lmosquitto

SRCS != find usb cjson -name "*.c"
SRCS += main.c mqtt_pub.c
OBJS := $(SRCS:S/.c/.o/g)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $(.TARGET) $(.ALLSRC)


