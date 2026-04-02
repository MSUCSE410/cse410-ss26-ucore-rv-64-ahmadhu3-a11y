#include "syscall.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"

uint64 sys_write(int fd, uint64 va, uint len)
{
	debugf("sys_write fd = %d va = %x, len = %d", fd, va, len);
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

uint64 sys_gettimeofday(TimeVal *val, int _tz)
{
	if (!val)
		return -1;

	// Build the time result here in kernel memory first,
	// because val is a user virtual address — we cannot write to it directly
	TimeVal temp;
	uint64 cycle = get_cycle();
	temp.sec  = cycle / CPU_FREQ;
	temp.usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;

	// Use copyout to safely transfer it into the user's memory
	if (copyout(curr_proc()->pagetable, (uint64)val,
	            (char *)&temp, sizeof(TimeVal)) < 0)
		return -1;

	return 0;
}

uint64 sys_task_info(TaskInfo *info)
{
	if (!info)
		return -1;

	struct proc *cur = curr_proc();

	// Same idea as gettimeofday — build the result in kernel memory first
	TaskInfo temp;
	temp.status = Running;

	// Copy how many times each syscall was called from the process record
	for (int i = 0; i < MAX_SYSCALL_NUM; i++)
		temp.syscall_times[i] = cur->syscall_times[i];

	// Calculate how long the process has been running in milliseconds
	uint64 elapsed = get_cycle() - cur->start_time;
	temp.time = (int)(elapsed * 1000 / CPU_FREQ);

	// Now safely write the completed result into the user's memory
	if (copyout(cur->pagetable, (uint64)info,
	            (char *)&temp, sizeof(TaskInfo)) < 0)
		return -1;

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

extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);

	// Every time a syscall is made, record it so task_info can report it later
	curr_proc()->syscall_times[id]++;

	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday((TimeVal *)args[0], args[1]);
		break;
	case SYS_taskinfo:
		ret = sys_task_info((TaskInfo *)args[0]);
		break;
	// Route mmap and munmap to their handlers, casting args to the right types
	case SYS_mmap:
		ret = sys_mmap((void *)args[0], args[1],
		               (int)args[2], (int)args[3], (int)args[4]);
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