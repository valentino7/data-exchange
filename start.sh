make
sudo insmod the_data-exchange.ko
cd user
sudo rm a.out
gcc -o a.out user.c
sudo ./a.out
cd ..


