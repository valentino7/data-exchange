

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/msg.h>

#define TAG_GET 134
#define TAG_SEND 156
#define TAG_RECEIVE 174
#define TAG_CTL 177

#define REMOVE 0
#define AWAKE_ALL 1
#define RESTRICT 0
#define NO_RESTRICT 1


//command: IPC_CREAT oppure IPC_EXCL
int sys_tag_get(int key, int command, int permission){
    return syscall(TAG_GET, key, command, permission);
}

int sys_tag_send(int tag, int level, char* buffer, ssize_t size){
    return syscall(TAG_SEND, tag, level, buffer, size);
}

int sys_tag_receive(int tag, int level, char* buffer, ssize_t size){
    return syscall(TAG_RECEIVE, tag, level, buffer, size);
}

int sys_tag_ctl(int tag, int command){
    return syscall(TAG_CTL, tag, command);
}



int main(int argc, char** argv){

    int tag = sys_tag_get(24, IPC_CREAT, RESTRICT);


    return 0;

}