

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

void primoTest(){
    int tag = sys_tag_get(24, IPC_CREAT, RESTRICT);
    printf("tag: %d \n", tag);

    tag = sys_tag_get(25, IPC_CREAT, RESTRICT);
    printf("tag: %d \n", tag);

    tag = sys_tag_get(0, IPC_CREAT, RESTRICT);
    printf("tag: %d \n", tag);

    tag = sys_tag_get(2, IPC_CREAT, RESTRICT);
    printf("tag: %d \n", tag);

    tag = sys_tag_get(3, IPC_CREAT, RESTRICT);
    printf("tag: %d \n", tag);
//    char* buffer = malloc(4);
//    int num = sys_tag_receive(tag, 3, buffer, 4);
//    printf("numero %d \n", num);
//    sys_tag_send(8, 3, "ciao", 4);

//    printf("rimozione %d \n", sys_tag_cmd(tag, REMOVE));

}

void secondoTest(){
    int tag = sys_tag_get(24, IPC_CREAT, RESTRICT);

    printf("tag: %d \n", tag);
    char* buffer = malloc(10);
    int receive_result = sys_tag_receive(tag, 2, buffer, 10);
    printf("receive_result: %d \n", receive_result);
}

int main(int argc, char** argv){

    //primoTest();
    secondoTest();
    return 0;

}