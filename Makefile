obj-m += the_data-exchange.o
the_data-exchange-objs +=  sys-data-exchange.o data-exchange.o lib/scth.o ./lib/vtpmo.o ./util/util.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

