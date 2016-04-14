obj-m = my_firewall.o 

KVERSION = "$(shell uname -r)"
all:
	        make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
clean:
	        make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
