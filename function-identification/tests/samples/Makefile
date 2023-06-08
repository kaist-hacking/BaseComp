TARGETS=hello\
				call_distance

all: $(TARGETS)

hello: hello.c
	arm-linux-gnueabi-gcc -o $@ $^

call_distance: call_distance.c
	arm-linux-gnueabi-gcc -o $@ $^
