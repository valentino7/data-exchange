

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#define TAG_GET 134
#define TAG_SEND 174
#define TAG_RECEIVE 182
#define TAG_CMD 183


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

    sys_tag_get(8, 3,3);
//    sys_tag_send(8, 3, "ciao", 4);
//    sys_tag_receive(8, 3, "cuai", 4);
//    sys_tag_cmd(8, 4);

    pause();

}