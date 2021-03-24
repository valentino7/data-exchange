

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/msg.h>

#define TAG_GET 134
#define TAG_SEND 174
#define TAG_RECEIVE 177
#define TAG_CMD 178

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

int sys_tag_cmd(int tag, int command){
    return syscall(TAG_CMD, tag, command);
}



int main(int argc, char** argv){



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

    int tag = sys_tag_get(24, IPC_CREAT, RESTRICT);
    printf("tag: %d \n", tag);

    //un thread receiver 0 va a dormire mentre l'altro elimina

//    sys_tag_get(9, 3,RESTRICT);
//    sys_tag_send(8, 3, "ciao", 4);
//
    char* buffer = malloc(4);
    int num = sys_tag_receive(tag, 3, buffer, 4);
    printf("numero %d \n", num);
//    sys_tag_send(8, 3, "ciao", 4);

//    printf("rimozione %d \n", sys_tag_cmd(tag, REMOVE));

    return 0;

}