APP=binception
CC=gcc
OBJS=main.o
CFLAGS=-g3 -O3 -DUSE_OPENSSL -DUSE_SQLITE
LDFLAGS=-lz -lbfd -lopcodes -liberty -ldl -lssl -lcrypto -lsqlite3
TESTDB=test.sqlite3

all: $(OBJS) $(APP)

$(APP): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

testapp: test.c
	$(CC) -o $@ $^ -g3 -O0

.PHONY:test
test: clean $(APP) testapp
	./$(APP) ./testapp -d $(TESTDB)
	./$(APP) ./testapp -d $(TESTDB) -s

clean:
	$(RM) $(OBJS) $(APP) testapp $(TESTDB)
