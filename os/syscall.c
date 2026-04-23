#include "syscall.h"
#include "console.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"
#include "stat.h"
uint64 console_write(uint64 va, uint64 len)
{
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	tracef("write size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return len;
}

uint64 console_read(uint64 va, uint64 len)
{
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	tracef("read size = %d", len);
	for (int i = 0; i < len; ++i) {
		int c = consgetc();
		str[i] = c;
	}
	copyout(p->pagetable, va, str, len);
	return len;
}

uint64 sys_write(int fd, uint64 va, uint64 len)
{
	if (fd < 0 || fd > FD_BUFFER_SIZE)
		return -1;
	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		errorf("invalid fd %d\n", fd);
		return -1;
	}
	switch (f->type) {
	case FD_STDIO:
		return console_write(va, len);
	case FD_INODE:
		return inodewrite(f, va, len);
	default:
		panic("unknown file type %d\n", f->type);
	}
}

uint64 sys_read(int fd, uint64 va, uint64 len)
{
	if (fd < 0 || fd > FD_BUFFER_SIZE)
		return -1;
	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		errorf("invalid fd %d\n", fd);
		return -1;
	}
	switch (f->type) {
	case FD_STDIO:
		return console_read(va, len);
	case FD_INODE:
		return inoderead(f, va, len);
	default:
		panic("unknown file type %d\n", f->type);
	}
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
	debugf("fork!");
	return fork();
}

static inline uint64 fetchaddr(pagetable_t pagetable, uint64 va)
{
	uint64 *addr = (uint64 *)useraddr(pagetable, va);
	return *addr;
}

uint64 sys_exec(uint64 path, uint64 uargv)
{
	struct proc *p = curr_proc();
	char name[MAX_STR_LEN];
	copyinstr(p->pagetable, name, path, MAX_STR_LEN);
	uint64 arg;
	static char strpool[MAX_ARG_NUM][MAX_STR_LEN];
	char *argv[MAX_ARG_NUM];
	int i;
	for (i = 0; uargv && (arg = fetchaddr(p->pagetable, uargv));
	     uargv += sizeof(char *), i++) {
		copyinstr(p->pagetable, (char *)strpool[i], arg, MAX_STR_LEN);
		argv[i] = (char *)strpool[i];
	}
	argv[i] = NULL;
	return exec(name, (char **)argv);
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
	struct proc *p = curr_proc();
	char name[MAX_STR_LEN];
	// copy program path from user space into kernel
	copyinstr(p->pagetable, name, va, MAX_STR_LEN);

	// look up the inode for the executable on the filesystem
	struct inode *ip = namei(name);
	if (ip == 0) return -1;

	// allocate a fresh process control block
	struct proc *child = allocproc();
	if (child == 0) { iput(ip); return -1; }

	// give the child stdin/stdout/stderr and record its parent
	init_stdio(child);
	child->parent = p;

	// load the binary into the child's address space
	if (bin_loader(ip, child) < 0) { iput(ip); return -1; }
	iput(ip);

	// pass the program name as argv[0]
	char *argv[2] = { name, NULL };
	child->trapframe->a0 = push_argv(child, argv);

	// put the child on the run queue
	add_task(child);
	return child->pid;
}

uint64 sys_set_priority(long long prio)
{
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

uint64 sys_openat(uint64 va, uint64 omode, uint64 _flags)
{
	struct proc *p = curr_proc();
	char path[200];
	copyinstr(p->pagetable, path, va, 200);
	return fileopen(path, omode);
}

uint64 sys_close(int fd)
{
	if (fd < 0 || fd > FD_BUFFER_SIZE)
		return -1;
	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		errorf("invalid fd %d", fd);
		return -1;
	}
	fileclose(f);
	p->files[fd] = 0;
	return 0;
}

int sys_fstat(int fd,uint64 stat){
	//TODO: your job is to complete the syscall
	if (fd < 0 || fd >= FD_BUFFER_SIZE) return -1;
	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	// fd must be valid and point to an actual inode, not stdio
	if (f == NULL || f->type != FD_INODE) return -1;
 
	struct inode *ip = f->ip;
	ivalid(ip); // make sure the in-memory inode is loaded from disk
 
	struct Stat st;
	memset(&st, 0, sizeof(st));
	st.dev   = ip->dev;    // which disk
	st.ino   = ip->inum;   // inode number
	st.nlink = ip->nlink;  // how many hard links exist
	// translate internal type to the user-visible mode constant
	st.mode  = (ip->type == T_DIR) ? DIR : FILE;
 
	// copy the filled struct out to user space
	if (copyout(p->pagetable, stat, (char *)&st, sizeof(st)) < 0)
		return -1;
	return 0;
}

int sys_linkat(int olddirfd, uint64 oldpath, int newdirfd, uint64 newpath, uint64 flags){
	//TODO: your job is to complete the syscall
	struct proc *p = curr_proc();
	char old[MAXPATH], lnew[MAXPATH];
	copyinstr(p->pagetable, old,  oldpath, MAXPATH);
	copyinstr(p->pagetable, lnew, newpath, MAXPATH);
 
	// linking a file to itself is an error per the spec
	if (strncmp(old, lnew, MAXPATH) == 0) return -1;
 
	// find the inode oldpath points to
	struct inode *ip = namei(old);
	if (ip == 0) return -1;
	ivalid(ip);
 
	// add a new directory entry in root that maps lnew to the same inode
	struct inode *dp = root_dir();
	if (dirlink(dp, lnew, ip->inum) < 0) { iput(dp); iput(ip); return -1; }
 
	// now two entries point here, so increment the link count
	ip->nlink++;
	iupdate(ip); // write updated nlink to disk
 
	iput(dp);
	iput(ip);
	return 0;
}

int sys_unlinkat(int dirfd, uint64 name, uint64 flags){
	//TODO: your job is to complete the syscall
	struct proc *p = curr_proc();
	char path[MAXPATH];
	copyinstr(p->pagetable, path, name, MAXPATH);
 
	struct inode *dp = root_dir();
	// get the inode so we can update its link count
	struct inode *ip = dirlookup(dp, path, 0);
	if (ip == 0) { iput(dp); return -1; }
	ivalid(ip);
 
	// decrement first, then remove the directory entry
	ip->nlink--;
	iupdate(ip);
 
	// dirunlink zeros out the dirent slot; it does not touch nlink
	if (dirunlink(dp, path) < 0) {
		// shouldn't happen — restore nlink to keep fs consistent
		ip->nlink++;
		iupdate(ip);
		iput(dp);
		iput(ip);
		return -1;
	}
 
	iput(dp);
	// if nlink == 0 and ref drops to 0, iput frees all data blocks
	iput(ip);
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
	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_read:
		ret = sys_read(args[0], args[1], args[2]);
		break;
	case SYS_openat:
		ret = sys_openat(args[0], args[1], args[2]);
		break;
	case SYS_close:
		ret = sys_close(args[0]);
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
		ret = sys_exec(args[0], args[1]);
		break;
	case SYS_wait4:
		ret = sys_wait(args[0], args[1]);
		break;
	case SYS_fstat:
	    ret = sys_fstat(args[0],args[1]);
		break;
	case SYS_linkat:
	    ret = sys_linkat(args[0],args[1],args[2],args[3],args[4]);
		break;
	case SYS_unlinkat:
	    ret = sys_unlinkat(args[0],args[1],args[2]);
		break;
	case SYS_spawn:
		ret = sys_spawn(args[0]);
		break;
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}
