#include "syscall.h"
#include "console.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"

uint64 sys_write(int fd, uint64 va, uint len)
{
	debugf("sys_write fd = %d str = %x, len = %d", fd, va, len);
	if (fd != STDOUT)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	debugf("size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return size;
}

uint64 sys_read(int fd, uint64 va, uint64 len)
{
	debugf("sys_read fd = %d str = %x, len = %d", fd, va, len);
	if (fd != STDIN)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	for (int i = 0; i < len; ++i) {
		int c = consgetc();
		str[i] = c;
	}
	copyout(p->pagetable, va, str, len);
	return len;
}

__attribute__((noreturn)) void sys_exit(int code)
{
	exit(code);
	__builtin_unreachable();
}

uint64 sys_sched_yield()
{
	yield();
	return 0;
}

uint64 sys_gettimeofday(uint64 val, int _tz)
{
	struct proc *p = curr_proc();
	uint64 cycle = get_cycle();
	TimeVal t;
	t.sec = cycle / CPU_FREQ;
	t.usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
	copyout(p->pagetable, val, (char *)&t, sizeof(TimeVal));
	return 0;
}

uint64 sys_mmap(void *start, uint64 len, int port, int flag, int fd)
{
	// Length of zero means nothing to map, just return success
	if (len == 0)
		return 0;

	uint64 start_addr = (uint64)start;

	// The start address must land exactly on a page boundary
	if (start_addr % PGSIZE != 0)
		return -1;

	// We refuse requests larger than 1 GiB
	if (len > (1u << 30))
		return -1;

	// Only the bottom 3 bits of port are valid permission flags
	if (port & ~0x7)
		return -1;

	// Mapping with no read, write, or execute permission makes no sense
	if ((port & 0x7) == 0)
		return -1;

	// Round the end address up so we cover all requested bytes
	uint64 end = PGROUNDUP(start_addr + len);
	struct proc *p = curr_proc();

	// Before allocating anything, make sure none of these pages are already in use
	for (uint64 va = start_addr; va < end; va += PGSIZE) {
		if (walkaddr(p->pagetable, va) != 0)
			return -1;
	}

	/* The code in `ch3` will leads to memory bugs*/
	// Convert the port permission bits into the flags the page table expects.
	// We always include PTE_U so the user program can actually access the pages.
	int perm = PTE_U;
	if (port & 1) perm |= PTE_R;
	if (port & 2) perm |= PTE_W;
	if (port & 4) perm |= PTE_X;

	// Allocate one physical page at a time and map each one into the page table
	for (uint64 va = start_addr; va < end; va += PGSIZE) {
		void *pa = kalloc();
		if (!pa)
			return -1;
		memset(pa, 0, PGSIZE);  // zero it out before handing it to the user
		if (mappages(p->pagetable, va, PGSIZE, (uint64)pa, perm) != 0) {
			kfree(pa);
			return -1;
		}
	}

	// Update max_page so the kernel knows how far this process's memory extends
	if (end / PGSIZE > p->max_page)
		p->max_page = end / PGSIZE;
	return 0;
}
uint64 sys_munmap(void *start, uint64 len)
{
	if (len == 0)
		return 0;

	uint64 start_addr = (uint64)start;

	if (start_addr % PGSIZE != 0)
		return -1;

	uint64 end = PGROUNDUP(start_addr + len);
	struct proc *p = curr_proc();

	// Make sure every page in the range is actually mapped before we remove anything
	for (uint64 va = start_addr; va < end; va += PGSIZE) {
		if (walkaddr(p->pagetable, va) == 0)
			return -1;
	}

	// Remove all the mappings and free the physical memory they were using
	uvmunmap(p->pagetable, start_addr, (end - start_addr) / PGSIZE, 1);
	return 0;
}

uint64 sys_getpid()
{
	return curr_proc()->pid;
}

uint64 sys_getppid()
{
	struct proc *p = curr_proc();
	return p->parent == NULL ? IDLE_PID : p->parent->pid;
}

uint64 sys_clone()
{
	debugf("fork!\n");
	return fork();
}

uint64 sys_exec(uint64 va)
{
	struct proc *p = curr_proc();
	char name[200];
	copyinstr(p->pagetable, name, va, 200);
	debugf("sys_exec %s\n", name);
	return exec(name);
}

uint64 sys_wait(int pid, uint64 va)
{
	struct proc *p = curr_proc();
	int *code = (int *)useraddr(p->pagetable, va);
	return wait(pid, code);
}

uint64 sys_spawn(uint64 va)
{
	// TODO: your job is to complete the sys call
	char file[128];
	struct proc *p = curr_proc();
	struct proc *np;     // this will be our new child process

    // Copy the program name from user memory into our kernel buffer
    copyinstr(p->pagetable, file, va, 128);
    // Look up which program slot matches that name
    int id = get_id_by_name(file);
    if (id < 0)
        return -1; // program not found
    // Allocate a brand new process
    np = allocproc();
    if (np == NULL)
        return -1; // no free process slots
    // Set the parent so wait() can find this child later
    np->parent = p;
    // Load the program into the new process's memory
    if (loader(id, np) < 0)
        return -1;
    // Put the new process in the run queue so the scheduler sees it
    np->state = RUNNABLE;
    return np->pid; // return the child's pid to the parent
}

uint64 sys_set_priority(long long prio){
    // TODO: your job is to complete the sys call
	// Priority must be 2 or more; 1 or less doesn't make sense for this formula
    if (prio < 2)
        return -1;

    struct proc *p = curr_proc(); // get the current process
    p->priority = prio;           // set its new priority
    // Recalculate pass: higher priority = smaller pass = stride grows slowly = picked more often
    p->pass = BIG_STRIDE / p->priority;

    return prio; // return the new priority to confirm success
}


extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);
	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_read:
		ret = sys_read(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
		// __builtin_unreachable();
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday(args[0], args[1]);
		break;
	case SYS_getpid:
		ret = sys_getpid();
		break;
	case SYS_getppid:
		ret = sys_getppid();
		break;
	case SYS_clone: // SYS_fork
		ret = sys_clone();
		break;
	case SYS_execve:
		ret = sys_exec(args[0]);
		break;
	case SYS_wait4:
		ret = sys_wait(args[0], args[1]);
		break;
	case SYS_spawn:
		ret = sys_spawn(args[0]);
		break;
	case SYS_set_priority:
        ret = sys_set_priority(args[0]);
		break;
	case SYS_mmap:
        ret = sys_mmap((void *)args[0], args[1], args[2], args[3], args[4]);
        break;
    case SYS_munmap:
        ret = sys_munmap((void *)args[0], args[1]);
        break;
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}
