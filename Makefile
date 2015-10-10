APP=binsniff
CC=gcc
OBJS=main.o
CFLAGS=-g3 -O0 -DUSE_OPENSSL -DUSE_SQLITE
LDFLAGS=-lz -lbfd -lopcodes -liberty -ldl -lssl -lcrypto -lsqlite3

all: $(OBJS) $(APP)

$(APP): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

testapp: test.c
	$(CC) -o $@ $^

.PHONY:test
test: $(APP) testapp
	./$(APP) ./testapp

clean:
	$(RM) $(OBJS) $(APP) testapp
