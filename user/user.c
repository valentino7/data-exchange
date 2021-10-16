/*I TEST SONO STATI IMPLEMENTATI SETTANDO IL NUMERO MASSIMO DEI TAG A 3 PER SEMPLICITÀ.
 * Vengono testate le 4 chiamate di sistema prodotte sys_tag_ctl, sys_tag_get, sys_tag_send, sys_tag_receive
*/



#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/msg.h>
#include <sys/wait.h>




#define TAG_GET 134
#define TAG_SEND 156
#define TAG_RECEIVE 174
#define TAG_CTL 177

#define REMOVE 0
#define AWAKE_ALL 1
#define RESTRICT 0
#define NO_RESTRICT 1





/* la key può essere IPC_PRIVATE espressa anche come 0 cosi da tornare see un tag diverso
 * command: IPC_CREAT oppure IPC_EXCL instanzia o apre.
 * Con IPC_EXCL non creo il tag ma lo apro soltanto quindi se è gia aperto torna errore
 * permission: RESTRICT oppure NO_RESTRICT a seconda se può aprirlo anche un altro utente o no
*/

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



//Funzione che testa sys_tag_get variando i parametri di input
void test_tag_get(){
    int tag;
//    tag = sys_tag_get(1, IPC_CREAT, RESTRICT);
//    printf("tag: %d \n", tag);
//
//    tag = sys_tag_get(1, IPC_CREAT, RESTRICT);
//    printf("tag: %d \n", tag);

    tag = sys_tag_get(2, IPC_EXCL, RESTRICT);
    printf("Ritorna errore perchè sto cercando di aprire un tag che non è ancora stato creato  %d \n", tag);

    tag = sys_tag_get(2, IPC_CREAT|IPC_EXCL, RESTRICT);
    printf("tag: %d \n", tag);

    tag = sys_tag_get(2, IPC_CREAT|IPC_EXCL, RESTRICT);
    printf("concatenando creat ed excl ritorna errore se il taag è gia stato creato:  %d \n", tag);

    tag = sys_tag_get(2, IPC_CREAT, RESTRICT);
    printf("Con IPC_CREAT posso sia creare che riaprire il tag:  %d \n", tag);

    int tag_restrict = sys_tag_get(2, IPC_EXCL, RESTRICT);
    printf("Ora l'apertura con IPC_EXCL non causa problemi:  %d \n", tag_restrict);

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

/*Funzione che testa il coordinamento tra sys_tag_send e sys_tag_receive utilizzando una relazione 1:1 tra sender e receiver
 * Vengono testati tutti i livelli di un singolo tag
*/

void test_tag_send_receive(){
    //la chiave scelta è del tutto casuale
    int tag = sys_tag_get(2, IPC_CREAT, RESTRICT);
    printf("tag: %d \n", tag);

    //il ciclo scorre i livelli
    for (int i=0; i!=33; i++){
        int pid;
        pid=fork();  // creo un nuovo processo
        if(pid<0)    exit(1);  // errore, duplicazione non eseguita
        else  {
            if(pid==0) {
                char* buffer = malloc(10);
                int receive_result= sys_tag_receive(tag, i, buffer, 10);
                printf("Numero byte ricevuti: %d \n", receive_result);
                return;
            }
        }
    }
   for (int j=1; j!=33; j++){
       int pid2;
       pid2=fork();  // creo un nuovo processo
       if(pid2<0)    exit(1);  // errore, duplicazione non eseguita
       else  {
           if(pid2==0) {
               sys_tag_send(tag, j, "Test", 10);
               return;
           }
       }
   }
    wait(NULL);
}

//Funzione che testa la coordinazione tra sys_tag_send e sys_tag_receive con più thread in ascolto sullo stesso livello
void test_tag_send_receive_parallel(){
    int status = 0;
    int tag = sys_tag_get(2, IPC_CREAT, RESTRICT);
    printf("tag: %d \n", tag);

    for (int i=1; i!=7; i++){
        int pid;
        pid=fork();  // creo un nuovo processo
        if(pid<0)    exit(1);  // errore, duplicazione non eseguita
        else  {
            if(pid==0) {
                char* buffer = malloc(10);
                int receive_result= sys_tag_receive(tag, 2, buffer, 10);
                printf("result %d INDICE %d stringa ricevuta %s \n", receive_result, i, buffer);
                return;
            }
            usleep(20);
            if (i==4)
                sys_tag_send(tag, 2, "Test", 10);
        }
    }
//    sys_tag_send(tag, 2, "buffer", 10);

    sleep(3);
    sys_tag_send(tag, 2, "Teseriiiinggggg", 17);

    while (wait(&status)>0);
}

/* Funzione che testa la chiamata di sistema sys_tag_ctl
 * vengono messi in attesa 2 thread su un livello e viene fatto vedere come la remove non possa eliminare
 * viene poi utilizzata l'awake all per svegliare i thread dormienti
 * viene utilizzato sys_tag_get IPC_EXCL per far vedere che il tag non esiste piu
 * viene poi fatta una REMOVE su un tag creato ma mai utilizzato
*/

void test_tag_remove_awake(){
    int status = 0;
    int tag_1 = sys_tag_get(2, IPC_CREAT, RESTRICT);
    printf("tag: %d \n", tag_1);

    int tag_2 = sys_tag_get(3, IPC_CREAT, RESTRICT);
    printf("tag: %d \n", tag_2);


    for (int i=1; i!=3; i++){
        int pid;
        pid=fork();  // creo un nuovo processo
        if(pid<0)    exit(1);  // errore, duplicazione non eseguita
        else  {
            if(pid==0) {
                char* buffer = malloc(10);
                int receive_result= sys_tag_receive(tag_1, i, buffer, 10);
                printf("result %d INDICE %d stringa ricevuta %s \n", receive_result, i, buffer);
                return;
            }
        }
    }

    sleep(3);
    //NON RIMOVIBILE PERCHE CI SONO THREAD IN ATTESA
    int result = sys_tag_ctl(tag_1, REMOVE);
    printf("risultato aspettato dalla rimozione di tag_1 è -1:%d  \n", result);

    //AWAKE ALL tag_1
    sys_tag_ctl(tag_1, AWAKE_ALL);

    while (wait(&status)>0);

    //il tag_1 è ora rimovibile avendo fatto terminare i thread
    result = sys_tag_ctl(tag_1, REMOVE);
    printf("risultato aspettato dalla rimozione di tag_1 è 1: %d  \n", result);


    //il tag_2 è rimovibile perchè non ha thread in attesa
    result = sys_tag_ctl(tag_2, REMOVE);
    printf("risultato aspettato dalla rimozione di tag_2 è 1: %d  \n", result);


    //provo a riaprire il tag per vedere se è chiuso davvero
    int tag_3 = sys_tag_get(3, IPC_EXCL, RESTRICT);
    printf("Avendo rimosso il tag mi aspetto che il risultato dell'apertura sia -1: %d \n", tag_3);
}


// Funzione eseguita per implementare la receive per il test test_tag_send_receive_multithread

pthread_mutex_t lock;
int num_thread = 0;

struct Params_rec {
    int tag;
    int level;
};

void *threadReceiversFun(void *vargp) {

    struct Params_rec *params_rec = (struct Params_rec *) vargp;

    char *buffer = malloc(10);
    int receive_result = sys_tag_receive(params_rec->tag, params_rec->level, buffer, 15);
    printf("result %d tag %d level %d stringa ricevuta %s \n", receive_result, params_rec->tag, params_rec->level, buffer);
    printf("tag: %d, level %d \n", params_rec->tag, params_rec->level);


    pthread_mutex_lock(&lock);
    num_thread++;
    pthread_mutex_unlock(&lock);
}


// Funzione eseguita per implementare la send per il test test_tag_send_receive_multithread
void *threadSendersFun(void *vargp) {

    int tag = *(int *) vargp;
    char level[3];
    char stag[2];
    char sgiro[10];

    int i;
    int giro = 0;
    char bigString[100];

    for(;;){
        for (i = 0; i != 32; i++) {
            sprintf(sgiro,"%d",giro);
            sprintf(level,"%d",i);
            bigString[0] = '\0';
            strcat(bigString,"lev");
            strcat(bigString,level);
            strcat(bigString,"tag");
            strcat(bigString,stag);
            strcat(bigString,"g");
            strcat(bigString,sgiro);
            sys_tag_send(tag, i, bigString, 15);
            strcpy(level, "");
            strcpy(stag, "");
            strcpy(sgiro, "");
            strcpy(bigString, "");
        }
        usleep(1);
        giro++;
        pthread_mutex_lock(&lock);
        if (num_thread == 96)
            break;
        pthread_mutex_unlock(&lock);
    }
}

/* Test più complesso, vengono saturati tutti i tag e tutti i livelli (da -1 a 33)
 * viene creato un sender per ogni tag
 * il sender invia un messaggio diverso ogni ms finchè non sono usciti tutti i thread
*/


void test_tag_send_receive_multithread(){

    int tag_1 = sys_tag_get(1, IPC_CREAT, RESTRICT);
    printf("Creato tag: %d \n", tag_1);

    int tag_2 = sys_tag_get(2, IPC_CREAT, RESTRICT);
    printf("Creato tag: %d \n", tag_2);

    int tag_3 = sys_tag_get(3, IPC_CREAT, RESTRICT);
    printf("Creato tag: %d \n", tag_3);
    printf("\n");

    pthread_mutex_init(&lock, NULL);
    //creazione thread per mettersi in attesa sul livello
    pthread_t tid_rec[102];
    pthread_t tid_send[3];

    //vengono lanciati i thread receiver
    struct Params_rec params_rec[102];
    int k=0;
    int j;
    int i;
    for (i = 0; i < 3; i++){
        for (j = -1; j < 33; j++){
            params_rec[k].tag = i;
            params_rec[k].level = j;
            //passare tag e livello
            pthread_create(&tid_rec[k], NULL, threadReceiversFun, (void *)&params_rec[k]);
            k++;
        }
    }

    //vengono lanciati i thread sender
    int params_send [3];
    params_send[0] = tag_1;
    params_send[1] = tag_2;
    params_send[2] = tag_3;
    for (i = 0; i < 3; i++)
        pthread_create(&tid_send[i], NULL, threadSendersFun, (void *)&params_send[i]);

    k=0;
    for (i = 0; i < 3; i++) {
        for (j = -1; j < 33; j++){
            pthread_join(tid_rec[k], NULL);
            k++;
        }
    }

    for (i = 0; i < 3; i++)
        pthread_join(tid_send[i], NULL);

    pthread_mutex_destroy(&lock);
}


/* Test più complesso, vengono saturati tutti i tag e tutti i livelli (da -1 a 33)
 * il thread padre esegue in sequenza fino a che i thread figli non hanno terminato:
 *      - send a tutti i tag a tutti i livelli
 * un altro thread effettua tentativi ripetutti di remove tag
*/



int main(int argc, char** argv){

    //test_tag_get();

    //test_tag_send_receive();

    //test_tag_send_receive_parallel();

    //test_tag_remove_awake();

    test_tag_send_receive_multithread();

    //test_tag_remove_awake_multithread();
    return 0;
}