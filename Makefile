obj-m += the_data-exchange.o
the_data-exchange-objs += data-exchange.o lib/scth.o ./lib/vtpmo.o util.o my_newque.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

