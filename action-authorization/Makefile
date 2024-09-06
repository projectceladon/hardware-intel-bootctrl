
CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)ld

LDLIBS = -lcrypto

EXEC = action-authorization
OBJS = action-authorization.o

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.cpp
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	-rm -f $(EXEC) *.elf *.o
