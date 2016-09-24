# compile
CFLAGS  = -Wall -g -Iinclude
LDFLAGS = -lcrypto -luv -Iopenssl
# compiler
CC = gcc

# files
SRC = $(shell find src -name "*.c" -type f)
OBJ = $(patsubst src/%.c, build/%.o, $(SRC)) 
DEP = $(OBJ:.o=.d)
BIN = local


bin/ss-%: $(OBJ) $(DEP) build/ss-%.o build/ss-%.d
	@mkdir -p $(dir $@)
	$(CC) $(filter %.o, $(^)) $(LDFLAGS) $(CFLAGS) -o $@

define build-object
	@mkdir -p $(dir $@)
	$(CC) $< -c $(CFLAGS) -o $@
endef

define build-depend
	@mkdir -p $(dir $@)
	@$(CC) -MM $(CFLAGS) $< | sed 's#\($(notdir $*)\)\.o[ :]*#build/$*.o $@: #g' > $@
endef

build/ss-%.o: %.c
	$(build-object)
build/ss-%.d: %.c
	$(build-depend)

build/%.o: src/%.c
	$(build-object)
build/%.d: src/%.c
	$(build-depend)
	
# target
all: $(patsubst %, bin/ss-%, $(BIN))

clean:
	$(RM) -r bin build

sinclude $(DEP)
