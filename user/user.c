

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

//la key può essere IPC_PRIVATE espressa anche come 0 cosi da tornare see un tag diverso
//command: IPC_CREAT oppure IPC_EXCL instanzia o apre
//Con IPC_EXCL non creo il tag ma lo apro soltanto quindi se è gia aperto torna errore
//permission: RESTRICT oppure NO_RESTRICT a seconda se può aprirlo anche un altro utente o no
int sys_tag_get(int key, int command, int permission){
    return syscall(TAG_GET, key, command, permission);
}

int sys_tag_send(int tag, int level, char* buffer, ssize_t size){
    return syscall(TAG_SEND, tag, level, buffer, size);
}

int sys_tag_receive(int tag, int level, char* buffer, ssize_t size){
    return syscall(TAG_RECEIVE, tag, level, buffer, size);
}
//command: REMOVE oppure AWAKE_ALL
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

void test_tag_get(){
    int tag;
//    tag = sys_tag_get(1, IPC_CREAT, RESTRICT);
//    printf("tag: %d \n", tag);
//
//    tag = sys_tag_get(1, IPC_CREAT, RESTRICT);
//    printf("tag: %d \n", tag);

    tag = sys_tag_get(2, IPC_EXCL, RESTRICT);
    printf("Ritorna errore perchè il tag non è ancora stato creato %d \n", tag);

    tag = sys_tag_get(2, IPC_CREAT|IPC_EXCL, RESTRICT);
    printf("tag: %d \n", tag);

    tag = sys_tag_get(2, IPC_CREAT|IPC_EXCL, RESTRICT);
    printf("concatenando creat ed excl ritorna errore se il taag è gia stato creato: %d \n", tag);

    tag = sys_tag_get(2, IPC_CREAT, RESTRICT);
    printf("tag: %d \n", tag);

    int tag_restrict = sys_tag_get(2, IPC_EXCL, RESTRICT);
    printf("tag: %d \n", tag_restrict);

    //test key ipc_private
    int tag_no_restrict = sys_tag_get(0, IPC_CREAT, NO_RESTRICT);
    printf("tag: %d \n", tag_no_restrict);

    //test su restrict
    printf("uid %d - euid %d\n",getuid(),geteuid());
    seteuid(700);
    printf("uid %d - euid %d\n",getuid(),geteuid());
//    char* buffer_no_restrict = malloc(10);
//    int receive_result_no_restrict= sys_tag_receive(tag_no_restrict, 2, buffer_no_restrict, 10);
//    printf("receive_result: %d \n", receive_result_no_restrict);

      //decommenta queste tre linee per vedere l'errore sull'utente non restrict
//    char* buffer_restrict = malloc(10);
//    int receive_result_restrict= sys_tag_receive(tag_restrict, 2, buffer_restrict, 10);
//    printf("receive_result_restrict mi aspetto un errore avendo cambiato euid: %d \n", receive_result_restrict);

    //test provo a riaprire il tag cambiando utente quando è restrict
    tag_restrict = sys_tag_get(2, IPC_EXCL, RESTRICT);
    printf("tag cambiato in NO_RESTRICT: %d \n", tag_restrict);

    //test provo a riaprire il tag mettendo no_restrict quando era creato come restrict
    tag_restrict = sys_tag_get(2, IPC_EXCL, RESTRICT);
    printf("tag cambiato in NO_RESTRICT: %d \n", tag_restrict);
//    char* buffer_restrict = malloc(10);
//    int receive_result_restrict= sys_tag_receive(tag_restrict, 2, buffer_restrict, 10);
//    printf("receive_result_restrict mi aspetto un errore avendo cambiato euid: %d \n", receive_result_restrict);

}

void test_tag_send_receive(){
    int tag = sys_tag_get(0, IPC_CREAT, RESTRICT);
    //testo che ci siano 32 livelli
    int pid;
    for (int i=0; i!= 32; i++){
        pid=fork();  // creo un nuovo processo
        if(pid<0)    exit(1);  // errore, duplicazione non eseguita
        else  {
            if(pid==0) {
                char* buffer = malloc(10);
                int receive_result= sys_tag_receive(tag, i, buffer, 10);
            }
        }
    }

    for (int i=0; i!= 32; i++){
        pid=fork();  // creo un nuovo processo
        if(pid<0)    exit(1);  // errore, duplicazione non eseguita
        else  {
            if(pid==0) {
                sys_tag_send(tag, i, "buffer", 10);
            }
        }
    }

}


int main(int argc, char** argv){

//    test_tag_get();
    test_tag_send_receive();
    return 0;

}