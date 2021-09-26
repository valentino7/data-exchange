

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
    sys_tag_send(tag, 2, "ciao", 10);


//    if(argc < 3){
//        printf("usage: prog num-spawns sycall-num\n");
//        return EXIT_FAILURE;
//    }
//    printf("get uid %d \n", getuid ());

//    int tag = sys_tag_get(9, IPC_CREAT  , RESTRICT);
//    printf("tag: %d \n", tag);
//
//    tag = sys_tag_get(9, IPC_EXCL , RESTRICT);
//    printf("tag: %d \n", tag);
//
//    tag = sys_tag_get(9, IPC_CREAT | IPC_EXCL  , RESTRICT);
//    printf("tag: %d \n", tag);


//    sys_tag_send(0, 3, "ciao", 4);

//    sys_tag_cmd(8, REMOVE);

    return 0;

}