# Data-exchange

The examination requires fulfilling the development of a project in the Linux kernel, which must comply with the following specification. Each student should develop the project individually.

TAG-based data exchange
This specification is related to the implementation of a Linux kernel subsystem that allows exchanging messages across threads. The service has 32 levels (namely, tags) by default, and should be driven by the following system calls:

* **int tag_get(int key, int command, int permission)**, this system call instantiates or opens the TAG service associated with key depending on the value of command. The IPC_PRIVATE value should be used for key to instantiate the service in such a way that it could not be re-opened by this same system call. The return value should indicate the TAG service descriptor (-1 is the return error) for handling the actual operations on the TAG service. Also, the permission value should indicate whether the TAG service is created for operations by threads running a program on behalf of the same user installing the service, or by any thread.


* __int tag_send(int tag, int level, char* buffer, size_t size)__, this service delivers to the TAG service with tag as the descriptor the message currently located in the buffer at address and made of size bytes. All the threads that are currently waiting for such a message on the corresponding value of level should be resumed for execution and should receive the message (zero lenght messages are anyhow allowed). The service does not keep the log of messages that have been sent, hence if no receiver is waiting for the message this is simply discarded.


* __int tag_receive(int tag, int level, char* buffer, size_t size)__, this service allows a thread to call the blocking receive operation of the message to be taken from the corresponding tag descriptor at a given level. The operation can fail also because of the delivery of a Posix signal to the thread while the thread is waiting for the message.


* **int tag_ctl(int tag, int command)**, this system call allows the caller to control the TAG service with tag as descriptor according to command that can be either AWAKE_ALL (for awaking all the threads waiting for messages, independently of the level), or REMOVE (for removing the TAG service from the system). A TAG service cannot be removed if there are threads waiting for messages on it.
By default, at least 256 TAG services should be allowed to be handled by software. Also, the maximum size of the handled message should be of at least 4 KB.

Also, a device driver musy be offered to check with the current state, namely the TAG service current keys and the number of threads currently waiting for messages. Each line of the corresponding device file should be therefore structured as "TAG-key TAG-creator TAG-level Waiting-threads".
