#ifndef PROC_H
#define PROC_H
#include "riscv.h"
#include "types.h"

#define NPROC (16)
#define MAX_SYSCALL_NUM 500

// Saved registers for kernel context switches.
struct context {
	uint64 ra;
	uint64 sp;
	// callee-saved
	uint64 s0;
	uint64 s1;
	uint64 s2;
	uint64 s3;
	uint64 s4;
	uint64 s5;
	uint64 s6;
	uint64 s7;
	uint64 s8;
	uint64 s9;
	uint64 s10;
	uint64 s11;
};

enum procstate { UNUSED, USED, SLEEPING, RUNNABLE, RUNNING, ZOMBIE };

// Per-process state
struct proc {
	enum procstate state;       // Process state
	int pid;                    // Process ID
	pagetable_t pagetable;      // User page table
	uint64 ustack;
	uint64 kstack;              // Virtual address of kernel stack
	struct trapframe *trapframe;// Data page for trampoline.S
	struct context context;     // swtch() here to run process
	uint64 max_page;

	// Tracks how many times each syscall was called, indexed by syscall ID
	unsigned int syscall_times[MAX_SYSCALL_NUM];

	// CPU cycle count when the process first ran, used to compute elapsed time
	uint64 start_time;
};

// Status values a task can be in, reported by sys_task_info
typedef enum {
	UnInit,
	Ready,
	Running,
	Exited,
} TaskStatus;

// Struct returned to the user by sys_task_info
typedef struct {
	TaskStatus status;
	unsigned int syscall_times[MAX_SYSCALL_NUM];
	int time;
} TaskInfo;

struct proc *curr_proc();
void exit(int);
void proc_init();
void scheduler() __attribute__((noreturn));
void sched();
void yield();
struct proc *allocproc();
void swtch(struct context *, struct context *);

#endif // PROC_H