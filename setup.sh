#!/bin/bash
devfile="/dev/my_filter"

if [ ! -d "$devfile" ];then
	echo rm_dev_file
    rm -f $devfile
fi

kofile="./my_firewall.ko"

if [ ! -d "$kofile" ];then
	echo rm_kofile
    rm -f $kofile
fi

IS_MOD_EXIST=$(lsmod|grep my_firewall)
echo $IS_MOD_EXIST

if [[ "$IS_MOD_EXIST" =~ "my_firewall" ]];then
	echo rm_mod
	rmmod my_firewall
fi

make
kofile="./my_firewall.ko"

if [ ! -d "$kofile" ];then
    echo make_success
    insmod my_firewall.ko
fi

MAJOR_LINE=$(dmesg | grep my_firewall:major)
MAJOR=${MAJOR_LINE##*=}
mknod /dev/my_filter c $MAJOR 0
echo Success! major=$MAJOR
watch -n 1 "dmesg|grep my_firewall:|tail -n 20"