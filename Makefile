ugidctl-y	+= ugidctl-cache.o ugidctl-dev.o
obj-m		+= ugidctl.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
