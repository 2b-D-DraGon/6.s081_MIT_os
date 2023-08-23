

### lab3 Page tables

**(easy)**
思路就是递归就好了，然后记得在exec中函数调用一下

```c
void vmprint_rec(pagetable_t vmpa, int n)
{

    if(n>3)
    {
      return;
    }

    for(int i = 0; i < 512; i++){
        pte_t pte = vmpa[i];

        if((pte & PTE_V) != 0){
      // this PTE points to a lower-level page table.
        uint64 child = PTE2PA(pte);
        for(int j =0;j<n;j++)
        {
                printf("..");
                if(j!=n-1){
                printf(" ");
                }
        }
        printf("%d: pte %p pa %p\n",i,pte,child);
        vmprint_rec((pagetable_t)child,n+1);
        }
    }
}

void vmprint(pagetable_t vmpa)
{
	printf("page table %p\n", vmpa);
  	vmprint_rec(vmpa, 1);
}
```

**(hard)**
这一题就是为每个进程都分配一个内核页表副本（也不是副本 就是跟内核页表初始化一样，初始化一个新的页表，映射关系等都一样），xv6 原本的设计是，用户进程在用户态使用各自的用户态页表，但是一旦进入内核态（例如使用了系统调用），则切换到内核页表（通过修改 satp 寄存器，trampoline.S）。然而这个内核页表是全局共享的，也就是全部进程进入内核态都共用同一个内核态页表：

1. 首先为struct proc添加一个页表变量
```c
// kernel/proc.h
  ...
  pagetable_t pagetable;       // User page table
  pagetable_t kernelPagetable;
  struct trapframe *trapframe; // data page for trampoline.S
  ...

```

2. 然后为模仿原来内核页表的映射，进行我们自己创建的内核页表的映射
```c
pagetable_t 
kvmmake_map_newpg()
{

  pagetable_t pagetable_proc;
  pagetable_proc = uvmcreate();
  if(pagetable_proc == 0)
    return 0;

  // uart registers
  kvmmap(pagetable_proc, UART0, UART0, PGSIZE, PTE_R | PTE_W);

  // virtio mmio disk interface
  kvmmap(pagetable_proc, VIRTIO0, VIRTIO0, PGSIZE, PTE_R | PTE_W);

  // // CLINT
  // kvmmap(pagetable_proc, CLINT, CLINT, 0x10000, PTE_R | PTE_W);

  // PLIC
  kvmmap(pagetable_proc, PLIC, PLIC, 0x400000, PTE_R | PTE_W);

  // map kernel text executable and read-only.
  kvmmap(pagetable_proc, KERNBASE, KERNBASE, (uint64)etext-KERNBASE, PTE_R | PTE_X);

  // map kernel data and the physical RAM we'll make use of.
  kvmmap(pagetable_proc, (uint64)etext, (uint64)etext, PHYSTOP-(uint64)etext, PTE_R | PTE_W);

  // map the trampoline for trap entry/exit to
  // the highest virtual address in the kernel.
  kvmmap(pagetable_proc, TRAMPOLINE, (uint64)trampoline, PGSIZE, PTE_R | PTE_X);
  
  return pagetable_proc;
}

pagetable_t 
kvminit_newpg(void)
{
  return kvmmake_map_newpg();
}
```

  原本的 xv6 设计中，所有处于内核态的进程都共享同一个页表，即意味着共享同一个地址空间。由于 xv6 支持多核/多进程调度，同一时间可能会有多个进程处于内核态，所以需要对所有处于内核态的进程创建其独立的内核态内的栈，也就是内核栈，供给其内核态代码执行过程。
	
  xv6 在启动过程中，会在 procinit() 中为所有可能的 64 个进程位都预分配好内核栈 kstack，具体为在高地址空间里，每个进程使用一个页作为 kstack，并且两个不同 kstack 中间隔着一个无映射的 guard page 用于检测栈溢出错误。但是由于我们给进程设置了自己的页表，所以就不用给每个进程设置kstack。

3. 这里开始取消每个进程初始化时，映射到原本的全局内核页表的kstack
```c
// initialize the proc table at boot time.
void
procinit(void)
{
  struct proc *p;
  
  initlock(&pid_lock, "nextpid");
  //initlock(&wait_lock, "wait_lock");
  for(p = proc; p < &proc[NPROC]; p++) {
      initlock(&p->lock, "proc");
      //这里删除了原本为所有进程与分配的kstack，改为进程初始化时分配到自身的表中
  }
  kvminithart();
}
```
然后进行进程初始化时的修改
```c
 p->pagetable = proc_pagetable(p);
  if(p->pagetable == 0){
    freeproc(p);
    release(&p->lock);
    return 0;
  }
//modify start
  p->kernelPagetable=kvminit_newpg();//创建的新页表
  if(p->kernelPagetable==0){
    freeproc(p);
    release(&p->lock);
    return 0;
  }
  char *pa = kalloc();//为kstack分配地址空间
  if(pa == 0)
    panic("kalloc");
  uint64 va = KSTACK((int) (p - proc));//kstack的虚拟地址，我是用进程数组的偏移量计算的，但这个可以是固定的地址，只要是在合法的地址空间就行
  //将VA和PA形成映射
  kvmmap(p->kernelPagetable, va, (uint64)pa, PGSIZE, PTE_R | PTE_W);
  p->kstack = va;
  //end modify
```

然后在调度器将 CPU 交给进程执行之前，切换到该进程对应的内核页表,参考实验文档提示：

```c

    for(p = proc; p < &proc[NPROC]; p++) {
      acquire(&p->lock);
      if(p->state == RUNNABLE) {
        // Switch to chosen process.  It is the process's job
        // to release its lock and then reacquire it
        // before jumping back to us.
        p->state = RUNNING;
        c->proc = p;
//modify start
        // 切换到进程独立的内核页表
        w_satp(MAKE_SATP(p->kernelPagetable));
        sfence_vma(); // 清除快表缓存
//modify end
        swtch(&c->context, &p->context);
```

这时候，内核页表分配和使用就都已经做好了，但是还要负责页表的释放

```c
static void
freeproc(struct proc *p)
{
  if(p->trapframe)
    kfree((void*)p->trapframe);
  p->trapframe = 0;

  pte_t *pte = walk(p->kernelPagetable, p->kstack, 0);
  if(pte == 0)
    panic("freeproc: free kstack");
  kfree((void*)PTE2PA(*pte));//释放物理空间
  p->kstack = 0;

  if(p->kernelPagetable)
    free_newpage(p->kernelPagetable);
  p->kernelPagetable=0;
  if(p->pagetable)
    proc_freepagetable(p->pagetable, p->sz);
  p->pagetable = 0;
  p->sz = 0;
  p->pid = 0;
  p->parent = 0;
  p->name[0] = 0;
  p->chan = 0;
  p->killed = 0;
  p->xstate = 0;
  p->state = UNUSED;
}
```

```c
void free_newpage(pagetable_t pagetable)
{
  for(int i = 0; i < 512; i++){
    pte_t pte = pagetable[i];
    uint64 child = PTE2PA(pte);
    if((pte & PTE_V) && (pte & (PTE_R|PTE_W|PTE_X)) == 0){
      // this PTE points to a lower-level page table.
      free_newpage((pagetable_t)child);
      pagetable[i] = 0;
    }
  }
  kfree((void*)pagetable);
}
//vm.c
//这里是进行了释放我们自制的页表的物理空间，但并不释放指向的物理空间，因为真正的内核页表也在用。所以使用这个释放函数，而不是直接proc_freepagetable
```

**（hard）**
  在上一个实验中，已经使得每一个进程都拥有独立的内核态页表了，这个实验的目标是，在进程的内核态页表中维护一个用户态页表映射的副本，这样使得内核态也可以对用户态传进来的指针（逻辑地址）进行解引用。这样做相比原来 copyin 的实现的优势是，原来的 copyin 是通过软件模拟访问页表的过程获取物理地址的，而在内核页表内维护映射副本的话，可以利用 CPU 的硬件寻址功能进行寻址，效率更高并且可以受快表加速。
  要实现这样的效果，我们需要在每一处内核对用户页表进行修改的时候，将同样的修改也同步应用在进程的内核页表上，使得两个页表的程序段（0 到 PLIC 段）地址空间的映射同步。
  接下来，为映射程序内存做准备。实验中提示内核启动后，能够用于映射程序内存的地址范围是 [0,PLIC)，我们将把进程程序内存映射到其内核页表的这个范围内，首先要确保这个范围没有和其他映射冲突。
  查阅 xv6 book 可以看到，在 PLIC 之前还有一个 CLINT（核心本地中断器）的映射，该映射会与我们要 map 的程序内存冲突。查阅 xv6 book 的 Chapter 5 以及 start.c 可以知道 CLINT 仅在内核启动的时候需要使用到，而用户进程在内核态中的操作并不需要使用到该映射。所以修改映射,这里应该就会懂上面的CLINT这里为什么会注释掉。
```c
pagetable_t 
kvmmake_map_newpg()
{

  pagetable_t pagetable_proc;
  pagetable_proc = uvmcreate();
  if(pagetable_proc == 0)
    return 0;

  // uart registers
  kvmmap(pagetable_proc, UART0, UART0, PGSIZE, PTE_R | PTE_W);

  // virtio mmio disk interface
  kvmmap(pagetable_proc, VIRTIO0, VIRTIO0, PGSIZE, PTE_R | PTE_W);

  // // CLINT
  // kvmmap(pagetable_proc, CLINT, CLINT, 0x10000, PTE_R | PTE_W);

  // PLIC
  kvmmap(pagetable_proc, PLIC, PLIC, 0x400000, PTE_R | PTE_W);

  // map kernel text executable and read-only.
  kvmmap(pagetable_proc, KERNBASE, KERNBASE, (uint64)etext-KERNBASE, PTE_R | PTE_X);

  // map kernel data and the physical RAM we'll make use of.
  kvmmap(pagetable_proc, (uint64)etext, (uint64)etext, PHYSTOP-(uint64)etext, PTE_R | PTE_W);

  // map the trampoline for trap entry/exit to
  // the highest virtual address in the kernel.
  kvmmap(pagetable_proc, TRAMPOLINE, (uint64)trampoline, PGSIZE, PTE_R | PTE_X);
  
  return pagetable_proc;
}

pagetable_t 
kvminit_newpg(void)
{
  return kvmmake_map_newpg();
}
```
在exec中加入判断，防止地址超过PLIC
```c
  if((sz1 = uvmalloc(pagetable, sz, ph.vaddr + ph.memsz)) == 0)
      goto bad;
    if(sz1 >= PLIC) { // 添加检测，防止程序大小超过 PLIC
      goto bad;
    }
    sz = sz1;
//exec.c
```

后面的步骤就是在每个修改到进程用户页表的位置，都将相应的修改同步到进程内核页表中。一共要修改：fork()、growproc()、userinit()，sbrk()。

需要先添加一下辅助的函数

```c
int
kvmcopymapping(pagetable_t src, pagetable_t dst, uint64 start, uint64 sz)
{
  pte_t *pte;
  uint64 pa,i;
  uint flags;

  for(i = PGROUNDUP(start);i<start+sz;i+=PGSIZE)
  {
    if((pte = walk(src,i,0))==0)
    {
      panic("kvmcopymapping: pte should exist");
    }
    if((*pte & PTE_V) == 0)
      panic("kvmcopymapping: page not present");
    pa = PTE2PA(*pte);

    flags=PTE_FLAGS(*pte)& ~PTE_U;

    if(mappages(dst,i,PGSIZE,pa,flags)!=0)
      goto err;
  }
  return 0;
  
  err:
  uvmunmap(dst, PGROUNDUP(start), (i - PGROUNDUP(start)) / PGSIZE, 0);
  return -1;

}


uint64
kvmdealloc(pagetable_t pagetable, uint64 oldsz, uint64 newsz)
{
  if(newsz >= oldsz)
    return oldsz;

  if(PGROUNDUP(newsz) < PGROUNDUP(oldsz)){
    int npages = (PGROUNDUP(oldsz) - PGROUNDUP(newsz)) / PGSIZE;
    uvmunmap(pagetable, PGROUNDUP(newsz), npages, 0);
  }

  return newsz;
}
//vm.c
```

```c
int
fork(void)
{
  int i, pid;
  struct proc *np;
  struct proc *p = myproc();

  // Allocate process.
  if((np = allocproc()) == 0){
    return -1;
  }
//modify start
  // Copy user memory from parent to child.
  if(uvmcopy(p->pagetable, np->pagetable, p->sz) < 0||
    kvmcopymapping(np->pagetable, np->kernelPagetable, 0, p->sz) < 0){
    freeproc(np);
    release(&np->lock);
    return -1;
  }
  np->sz = p->sz;
//modify end
```

```c
int
growproc(int n)
{
  uint sz;
  struct proc *p = myproc();

  sz = p->sz;
  if(n > 0){
    uint64 newsz;
    if((newsz = uvmalloc(p->pagetable, sz, sz + n)) == 0) {//分配的新大小
      return -1;
    }
     if(kvmcopymapping(p->pagetable, p->kernelPagetable, sz, n) != 0) {//将其映射
      uvmdealloc(p->pagetable, newsz, sz);
      return -1;
    }
    sz = newsz;
  } else if(n < 0){
    uvmdealloc(p->pagetable, sz, sz + n);
    sz = kvmdealloc(p->kernelPagetable, sz, sz + n);
  }
  p->sz = sz;
  return 0;
}
//proc.c
```

不要忘了考虑初始进程init

```c
void
userinit(void)
{
  struct proc *p;

  p = allocproc();
  initproc = p;
  
  // allocate one user page and copy init's instructions
  // and data into it.
  uvminit(p->pagetable, initcode, sizeof(initcode));
  p->sz = PGSIZE;
  kvmcopymapping(p->pagetable, p->kernelPagetable, 0, p->sz);

  // prepare for the very first "return" from kernel to user.
  p->trapframe->epc = 0;      // user program counter
  p->trapframe->sp = PGSIZE;  // user stack pointer

  safestrcpy(p->name, "initcode", sizeof(p->name));
  p->cwd = namei("/");

  p->state = RUNNABLE;

  release(&p->lock);
}
```

然后替换copyout,copyin就是给取个别名然后再函数调用。这个实验就结束啦

### lab4 trap
(moderate)
```c
void backtrace()
{
  printf("backtrace:\n");

  uint64 stackTop_fp= r_fp();//获取fp指针

  uint64 base = PGROUNDUP(stackTop_fp);

  while(stackTop_fp < base) {
    printf("%p\n", *((uint64*)(stackTop_fp - 8)));
    stackTop_fp = *((uint64*)(stackTop_fp - 16));
  }
}
```

再添加进sys_sleep

```c
uint64
sys_sleep(void)
{
  int n;
  uint ticks0;


  backtrace();
	...//sysproc.c
```

(hard)

添加系统调用，这里之前的lab中提到过，所以就不赘述了，直接省略

```c
int sigalarm(int ticks, void (*handler)());
int sigreturn(void);
```

然后添加具体的proc结构体的变量

```c
 struct proc {
  struct spinlock lock;

  // p->lock must be held when using these:
  enum procstate state;        // Process state
  void *chan;                  // If non-zero, sleeping on chan
  int killed;                  // If non-zero, have been killed
  int xstate;                  // Exit status to be returned to parent's wait
  int pid;                     // Process ID

  // wait_lock must be held when using this:
  struct proc *parent;         // Parent process

  // these are private to the process, so p->lock need not be held.
 uint64 kstack;               // Virtual address of kernel stack
  uint64 sz;                   // Size of process memory (bytes)
  pagetable_t pagetable;       // User page table
  pagetable_t kernelPagetable;
  struct trapframe *trapframe; // data page for trampoline.S
  struct trapframe *trapframe2;//时钟中断时刻的 trapframe，用于中断处理完成后恢复原程序的正常执行
  struct context context;      // swtch() here to run process
  struct file *ofile[NOFILE];  // Open files
  struct inode *cwd;           // Current directory
  char name[16];               // Process name (debugging)

  int alarm_interval;       //时钟周期
  uint64  fn_address;           //时钟回调处理函数
  int alarm_ticks;          //how many ticks have passed
}
```

sys_sigalarm 与 sys_sigreturn 具体实现：

```c
uint64 sys_sigalarm(void)
{
  int interval;
  uint64 fnadd;
  struct proc *pro = myproc();

  if(argint(0,&interval)<0||argaddr(1,&fnadd)<0)//获取参数
  { 
    return -1;
  }

  pro->alarm_interval=interval;
  pro->fn_address = fnadd;
  pro->alarm_ticks=0;

  return 1;

}

uint64 sys_sigreturn()
{
  struct proc *pro = myproc();
  
  *pro->trapframe=*pro->trapframe2;//将trapframe恢复到之前的样子

  pro->alarm_ticks=0;

  return 0;
}

```

初始化proc的值和释放进程时做的事

```c
	p->alarm_ticks=0;
	// Allocate a trapframe page.
  if((p->trapframe = (struct trapframe *)kalloc()) == 0){
    release(&p->lock);
    return 0;
  }

  if((p->trapframe2 = (struct trapframe *)kalloc()) == 0){//分配一个空间
    release(&p->lock);
    return 0;
  }
  // proc.c
```

```c
 p->state = UNUSED;
  p->alarm_interval=0;
  p->alarm_ticks=0;
  p->fn_address=0;
...freeproc.c
```

在usertrap中实现时钟机制

```c
 // give up the CPU if this is a timer interrupt.
  if(which_dev == 2)
  {
    if(p->alarm_interval<0)
    {
      yield();
    }
    p->alarm_ticks++;//时钟数++
    if(p->alarm_ticks == p->alarm_interval)//如果达到了时钟数，保存trapframe
    {
      *p->trapframe2=*p->trapframe;//不保存某个寄存器，直接全部保存，简单粗暴
      p->trapframe->epc = p->fn_address;//修改 pc 寄存器的值，将程序流转跳到 alarm_handler 中，alarm_handler 执行完毕后再恢复原本的执行流
    }
  }
```

### lab 5 lazy page 
这个实验所有要做的，课程视频中已经全部带着手敲完了，所以看视频照着敲一遍就行，我估计这也是2021版本取消这个lab的原因，但是一定要体会一下
### lab 6 cow fork

首先修改uvmcopy

```c
int
uvmcopy(pagetable_t old, pagetable_t new, uint64 sz)
{
  pte_t *pte;
  uint64 pa, i;
  uint flags;
  // char *mem;

  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walk(old, i, 0)) == 0)
      panic("uvmcopy: pte should exist");
    if((*pte & PTE_V) == 0)
      panic("uvmcopy: page not present");
    pa = PTE2PA(*pte);
    flags = PTE_FLAGS(*pte);

    *pte = ((*pte) & (~PTE_W)) | PTE_COW;//将父文本的改成不可读写以及设置为COW状态
    // if((mem = kalloc()) == 0)
    //   goto err;
    // memmove(mem, (char*)pa, PGSIZE);
    if(mappages(new, i, PGSIZE, (uint64)pa, (flags & (~PTE_W)) | PTE_COW) != 0){//开始映射子进程的，并且不给分配空间
      // kfree(mem);
      goto err;
    }
    krefpage((void*)pa);
  }
  return 0;

 err:
  uvmunmap(new, 0, i / PGSIZE, 1);
  return -1;
}
```

添加一个位,这里添加到哪个没用的位都行，但是不能在已经分配好的地方添加

```c
#define PTE_V (1L << 0) // valid
#define PTE_R (1L << 1)
#define PTE_W (1L << 2)
#define PTE_X (1L << 3)
#define PTE_U (1L << 4) // 1 -> user can access
#define PTE_COW (1L << 8)
```

添加的内容usertrap

```c
  } else if((which_dev = devintr()) != 0){
    // ok
  } 
  else if((r_scause() == 13 || r_scause() == 15) && uvmcheckcowpage(r_stval())) { // copy-on-write
    if(cow_uvmcopy(r_stval()) == -1){ // 如果内存不足，则杀死进程
      p->killed = 1;
    }
  }
  else {
    printf("usertrap(): unexpected scause %p pid=%d\n", r_scause(), p->pid);
    printf("            sepc=%p stval=%p\n", r_sepc(), r_stval());
    p->killed = 1;
  }
```

这里有两个上面未知的函数

```c
int uvmcheckcowpage(uint64 va){//检查每一个页面是否是cow_fork
  pte_t* pte;
  struct proc* p = myproc();

  return  va < p->sz//检查是否超出了进程使用的地址空间范围，这个一定要添加，否则测试中会出现PANIC
          &&((pte = walk(p->pagetable, va, 0))!=0)//找到PTE
          && (*pte & PTE_V)//是否有效
          &&*pte&PTE_COW;//是否是cow_fork
}

int cow_uvmcopy(uint64 va){//分配页面
  pte_t *pte;
  struct proc* p = myproc();

  if((pte = walk(p->pagetable, va, 0)) == 0)
    panic("cow_uvmcopy: pte should exist");
  
  uint64 pa = PTE2PA(*pte);
  
  uint64 new = (uint64)kcopy_n_deref((void*)pa); // 将一个懒复制的页引用变为一个实复制的页
  if(new == 0)
    return -1;

  uint64 flags = (PTE_FLAGS(*pte) | PTE_W) & ~PTE_COW;//set flags
  uvmunmap(p->pagetable,PGROUNDDOWN(va),1,0);//释放之前的页表项，但是不要释放物理空间，因为可能别的进程还在用这个空间，所以最后一个参数为0

  if(mappages(p->pagetable,va,1,new,flags)==-1){//add a new pte with new flags
    panic("cow_uvmcopy: mappages!");
  }
  return 0;
}
```

- kalloc(): 分配物理页，将其引用计数置为 1
- krefpage(): 创建物理页的一个新引用，引用计数加 1
- kcopy_n_deref(): 将物理页的一个引用实复制到一个新物理页上（引用计数为 1），返回得到的副本页；并将本物理页的引用计数减 1
- kfree(): 释放物理页的一个引用，引用计数减 1；如果计数变为 0，则释放回收物理页

```c
void krefpage(void *pa) {// add num of ref 
  acquire(&pgreflock);    //warning: it's physical address 
  PA2PGREF(pa)++;
  release(&pgreflock);
}

void *kcopy_n_deref(void *pa){//如果引用只有一个了，这时候说明只有当前进程使用，直接返回当前地址即可
  acquire(&pgreflock);

  if(PA2PGREF(pa) <= 1) { // if ref == 1 it's meanless that alloc a new space 
    release(&pgreflock);
    return pa;
  }
//为当前进程创建页面物理地址
  uint64 newpa = (uint64)kalloc();//alloc a physical space 
  if(newpa == 0) {
    release(&pgreflock);
    return 0; // out of memory
  }
  memmove((void*)newpa, (void*)pa, PGSIZE);// copy data

  PA2PGREF(pa)--;//将此页面的ref--因为有一个进程有自己的物理地址了

  release(&pgreflock);
  return (void*)newpa;//返回新分配的地址
}
```

一些辅助的宏

```c
// 用于访问物理页引用计数数组
#define PA2PGREF_ID(p) (((p)-KERNBASE)/PGSIZE)//可以当成是数组的Index
#define PGREF_MAX_ENTRIES PA2PGREF_ID(PHYSTOP) //计算可分配的所有物理页的数量

struct spinlock pgreflock; // 用于 pageref 数组的锁，防止竞态条件引起内存泄漏
int pageref[PGREF_MAX_ENTRIES]; // 从 KERNBASE 开始到 PHYSTOP 之间的每个物理页的引用计数
// note:  reference counts are incremented on fork, not on mapping. this means that
//        multiple mappings of the same physical page within a single process are only
//        counted as one reference.
//        this shouldn't be a problem, though. as there's no way for a user program to map
//        a physical page twice within it's address space in xv6.

// 通过物理地址获得引用计数 也就是有一个全局数组记录着每一个物理块的引用计数值，在kalloc中会初始化为1
#define PA2PGREF(p) pageref[PA2PGREF_ID((uint64)(p))]
```

修改kalloc和kfree

```c
void
kfree(void *pa)
{
  struct run *r;

  if(((uint64)pa % PGSIZE) != 0 || (char*)pa < end || (uint64)pa >= PHYSTOP)
    panic("kfree");

  acquire(&pgreflock);

  if(--PA2PGREF(pa) <= 0){//only if ref ==0  release add the free physical memory
      // Fill with junk to catch dangling refs.
    memset(pa, 1, PGSIZE);
    r = (struct run*)pa;
    acquire(&kmem.lock);
    r->next = kmem.freelist;
    kmem.freelist = r;
    release(&kmem.lock);
  }

  release(&pgreflock);
}

// Allocate one 4096-byte page of physical memory.
// Returns a pointer that the kernel can use.
// Returns 0 if the memory cannot be allocated.
void *
kalloc(void)
{
  struct run *r;

  acquire(&kmem.lock);
  r = kmem.freelist;//获取一个空闲物理块
  if(r)
    kmem.freelist = r->next;
  release(&kmem.lock);

  if(r){
    memset((char*)r, 5, PGSIZE); // fill with junk
    PA2PGREF(r) = 1;// init_ref
  }
  return (void*)r;
}//这里就更改了初始化时加了个引用计数初始化

```

 copyout() 由于是软件访问页表，不会触发缺页异常，所以需要手动添加同样的监测代码（同 lab5），检测接收的页是否是一个懒复制页，如果是的话就执行分配一个新空间的操作

```c
int
copyout(pagetable_t pagetable, uint64 dstva, char *src, uint64 len)
{
  uint64 n, va0, pa0;

  while(len > 0){
    
    if(uvmcheckcowpage(dstva)) // 检查每一个被写的页是否是 COW 页
      cow_uvmcopy(dstva);

    va0 = PGROUNDDOWN(dstva);
    pa0 = walkaddr(pagetable, va0);
```

### lab 7 thread

此章节难度不大，大部分就是模拟proc.c中的写即可，重要的是体会为什么只用保存少数几个寄存器，因为函数调用时调用者自己保存了自己需要的到trapframe中了，这里上下文保存的是被调用者需要的寄存器

(moderate)

```c
    /* YOUR CODE HERE
     * Invoke thread_switch to switch from t to next_thread:
     * thread_switch(??, ??);
     */
    thread_switch((uint64)&t->ctx,(uint64)&next_thread->ctx); // 切换线程  
```

```c
void 
thread_create(void (*func)())
{
  struct thread *t;

  for (t = all_thread; t < all_thread + MAX_THREAD; t++) {
    if (t->state == FREE) break;
  }
  t->state = RUNNABLE;

  memset(&t->ctx, 0, sizeof(t->ctx));// 模拟alloproc()
  t->ctx.ra = (uint64)func;       // 设置返回地址
  // Set up new context to start executing at func()
  t->ctx.sp = (uint64)&t->stack + (STACK_SIZE - 1);  // 栈指针
  // 将线程的栈指针指向其独立的栈，注意到栈的生长是从高地址到低地址，所以
  // 要将 sp 设置为指向 stack 的最高地址
}
```

```c
struct context {//proc.h
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

struct thread {
  char       stack[STACK_SIZE]; /* the thread's stack */
  int        state;             /* FREE, RUNNING, RUNNABLE */
  struct     context ctx;
};
```

（moderete）

```c
pthread_mutex_t lock[NBUCKET];            // declare a lock


```

```c
static 
void put(int key, int value)
{
  int i = key % NBUCKET;

  // is the key already present?
  struct entry *e = 0;
  for (e = table[i]; e != 0; e = e->next) {
    if (e->key == key)
      break;
  }
  pthread_mutex_lock(&lock[i]);
  if(e){
    // update the existing key.
    e->value = value;
  } else {
    // the new is new.
    insert(key, value, &table[i], table[i]);
  }
  pthread_mutex_unlock(&lock[i]);
}

```

```c
int
main(int argc, char *argv[])
{
  pthread_t *tha;
  void *value;
  double t1, t0;

  //pthread_mutex_init(&lock, NULL); // initialize the lock  (for safe)

  for(int i=0;i<NBUCKET;i++) {   //(for fast)
    pthread_mutex_init(&lock[i], NULL); 
  }

  if (argc < 2) {
    fprintf(stderr, "Usage: %s nthreads\n", argv[0]);
    exit(-1);
  }
  nthread = atoi(argv[1]);
  tha = malloc(sizeof(pthread_t) * nthread);
  srandom(0);
  assert(NKEYS % nthread == 0);
  for (int i = 0; i < NKEYS; i++) {
    keys[i] = random();
  }
```

(moderate)

```c
static void 
barrier()
{
  pthread_mutex_lock(&bstate.barrier_mutex);
  if(++bstate.nthread < nthread) {
    pthread_cond_wait(&bstate.barrier_cond, &bstate.barrier_mutex);//到达就等待释放锁
  } else {
    bstate.nthread = 0;
    bstate.round++;
    pthread_cond_broadcast(&bstate.barrier_cond);//所有都达到，则释放所有的线程进行新一轮
  }
  pthread_mutex_unlock(&bstate.barrier_mutex);
}

```

这里需要保证在改变到达屏障的``nthread``时是互斥的就可以了
### lab 8 lock

（moderate）

```C
struct {
  struct spinlock lock;
  struct run *freelist;
} kmem[NCPU];//为每个CPU创建一个空闲表

char* nameOfKemLock[]=//给每个锁的名字 可有可无这个 可以统一叫kmem
{
  "cpu_1_lock",
  "cpu_2_lock",
  "cpu_3_lock",
  "cpu_4_lock",
  "cpu_5_lock",
  "cpu_6_lock",
  "cpu_7_lock",
  "cpu_8_lock",
};
```

```c
void
kinit()
{
  for(int i=0;i<NCPU;i++){//为每个锁初始化
    initlock(&kmem[i].lock, nameOfKemLock[i]);
  }
  freerange(end, (void*)PHYSTOP);
}
```

```c
void
kfree(void *pa)
{
  struct run *r;

  if(((uint64)pa % PGSIZE) != 0 || (char*)pa < end || (uint64)pa >= PHYSTOP)
    panic("kfree");

  // Fill with junk to catch dangling refs.
  memset(pa, 1, PGSIZE);

  r = (struct run*)pa;

  push_off();//这里和POP的跨度不能太大，否则会造成panic
  int cpu_id = cpuid();
  pop_off();
  acquire(&kmem[cpu_id].lock);
  r->next = kmem[cpu_id].freelist;
  kmem[cpu_id].freelist = r;
  release(&kmem[cpu_id].lock);
	//pop_off()
}

// Allocate one 4096-byte page of physical memory.
// Returns a pointer that the kernel can use.
// Returns 0 if the memory cannot be allocated.
void *
kalloc(void)
{
  struct run *r;
  push_off();//no interrupt
  int cpu_id=cpuid();
  pop_off();//finish using cup_id

  acquire(&kmem[cpu_id].lock);
  r = kmem[cpu_id].freelist;

  if(r)//find free block
    kmem[cpu_id].freelist = r->next;
  else{//start stealing
    for(int i=0;i<NCPU;i++){
      if(i==cpu_id){
        continue;
      }
      acquire(&kmem[i].lock);
      r = kmem[i].freelist;
      if(r){
        kmem[i].freelist = r->next;
      }
      release(&kmem[i].lock);
      if(r) break;
    }
  }
  release(&kmem[cpu_id].lock);
  if(r)
    memset((char*)r, 5, PGSIZE); // fill with junk
  return (void*)r;
}
```

(hard)

首先进行对struct补充

```c
struct buf {
  int valid;   // has data been read from disk?
  int disk;    // does disk "own" buf?
  uint dev;
  uint blockno;
  struct sleeplock lock;
  uint refcnt;
  struct buf *prev; // LRU cache list
  struct buf *next;
  uchar data[BSIZE];
  uint useticks;
};
```

然后进行桶和锁的相关操作

```c
#define NBUFMAP_BUCKET 13

int MAPHASHFN(int blockno){
  return (blockno)%(NBUFMAP_BUCKET);
}

extern uint ticks;

struct {
  struct spinlock biglock;
  struct buf buf[NBUF];

  // Linked list of all buffers, through prev/next.
  // Sorted by how recently the buffer was used.
  // head.next is most recent, head.prev is least.
  struct buf head[NBUFMAP_BUCKET];
  struct spinlock bufmap_locks[NBUFMAP_BUCKET];
} bcache;
```

然后进行锁的初始化

```c
void
binit(void)
{
  struct buf *b;

  initlock(&bcache.biglock, "bcache_biglock");

  for(int i =0;i<NBUFMAP_BUCKET;i++){
    initlock(&bcache.bufmap_locks[i], "bcache_buf");
  }
//INITIAL BUF 这里的思想是先将所有桶给初始化
  for (int i = 0; i < NBUFMAP_BUCKET; i++) {
    bcache.head[i].next = &bcache.head[i];
    bcache.head[i].prev = &bcache.head[i];
  }

  for(b = bcache.buf; b < bcache.buf+NBUF; b++){//将所有的缓存块暂时缓存到第一个桶里，后面的如果缺了就从这个桶里借
    b->next = bcache.head[0].next;
    b->prev = &bcache.head[0];
    initsleeplock(&b->lock, "buffer");
    bcache.head[0].next->prev = b;
    bcache.head[0].next = b;
  }
}
```

最关键的部分三步

1. 先看一下这个桶里有没有缓存区
2. 寻找可以使用的缓存区，如果我这个桶里有，那么直接使用
3. 如果没有，那么去别的桶里借

```c
// Look through buffer cache for block on device dev.
// If not found, allocate a buffer.
// In either case, return locked buffer.
static struct buf*
bget(uint dev, uint blockno)
{
  struct buf *b,*b2=0;

  int hasFound =0;//是否找到可用的块

  int min_ticks = 0;

  uint key = MAPHASHFN(blockno);//hash

  acquire(&bcache.bufmap_locks[key]);//acquire bucket locks

// Is the block already cached?
  for(b = bcache.head[key].next; b!=&bcache.head[key]; b = b->next){
    if(b->dev == dev && b->blockno == blockno){
      b->refcnt++;
      release(&bcache.bufmap_locks[key]);
      acquiresleep(&b->lock);
      return b;
    }
  }

  release(&bcache.bufmap_locks[key]);//if no cached release 提高并发性 允许其他的cpu可以运行上述代码
    
    
//Your solution might need to hold two locks in some cases; for example, during eviction you may need to hold the bcache lock and a lock per bucket. Make sure you avoid deadlock.
  acquire(&bcache.biglock);
  acquire(&bcache.bufmap_locks[key]);
//这里为什么再寻找一遍的原因是 当我放弃锁后，可能其他的CPU提前获得上面的两把锁进行了寻找，有可能会导致刚才没有缓存现在缓存了，所以再检查一遍
  for(b = bcache.head[key].next; b!=&bcache.head[key]; b = b->next){
    if(b->dev == dev && b->blockno == blockno){
      b->refcnt++;
      release(&bcache.bufmap_locks[key]);
      release(&bcache.biglock);
      acquiresleep(&b->lock);
      return b;
    }
  }

// can't find  so find LRU from bucket 
   //根据LRU进行寻找 看这个桶里有没有合适的
  for (b = bcache.head[key].next; b != &bcache.head[key]; b = b->next) {
    if (b->refcnt == 0 && (b2 == 0 || b->useticks < min_ticks)) {
      min_ticks = b->useticks;
      b2 = b;
      hasFound=1;//标记发现了合适的BUF
    }
  }

  if (hasFound) {//设置BUF信息
    b2->dev = dev;
    b2->blockno = blockno;
    b2->refcnt++;
    b2->valid = 0;
    release(&bcache.bufmap_locks[key]);//找到后进行释放这个桶的锁
    release(&bcache.biglock);
    acquiresleep(&b2->lock);
    return b2;
  }

// find usable LRU block from other bucket

  for (int j = MAPHASHFN(key + 1); j != key; j = MAPHASHFN(j + 1)) {//便利所有桶 进行LRU，这里跟上面的代码区别不大，除了移块
    acquire(&bcache.bufmap_locks[j]);
    for (b = bcache.head[j].next; b != &bcache.head[j]; b = b->next) {
      if (b->refcnt == 0 && (b2 == 0 || b->useticks < min_ticks)) {
        min_ticks = b->useticks;
        b2 = b;
        hasFound=1;
      }
    }
    if(hasFound) {
      b2->dev = dev;
      b2->refcnt++;
      b2->valid = 0;
      b2->blockno = blockno;
      // remove block from its original bucket.
        //将其他桶中合适的BUF从链表中删除，单独拿出来 然后释放其他桶的锁
      b2->next->prev = b2->prev;
      b2->prev->next = b2->next;
      release(&bcache.bufmap_locks[j]);
      // add block
        //将找到的BUF添加进桶里，然后释放锁
      b2->next = bcache.head[key].next;
      b2->prev = &bcache.head[key];
      bcache.head[key].next->prev = b2;
      bcache.head[key].next = b2;
      release(&bcache.bufmap_locks[key]);
      release(&bcache.biglock);
      acquiresleep(&b2->lock);
      return b2;
    }
    release(&bcache.bufmap_locks[j]);//如果这个桶没找到，别忘了解开这个桶的锁
  }
  release(&bcache.bufmap_locks[key]);//所有桶都不行，那么解锁然后PANIC
  release(&bcache.biglock);
  panic("bget: no buffers");
}

```

然后其他的就是修改下加锁的代码就好了

```c
void
brelse(struct buf *b)
{
  if(!holdingsleep(&b->lock))
    panic("brelse");

  releasesleep(&b->lock);

  int key = MAPHASHFN(b->blockno);

  acquire(&bcache.bufmap_locks[key]);//对桶中的BUF操作
  b->refcnt--;
  if (b->refcnt == 0) {//如果没有引用了，设置其TICKS，方便进行LRU
    b->useticks = ticks;
  }
  release(&bcache.bufmap_locks[key]);
}
//下面的两个没什么可说的，改一下就好啦
void
bpin(struct buf *b) {

  int key = MAPHASHFN(b->blockno);

  acquire(&bcache.bufmap_locks[key]);
  b->refcnt++;
  release(&bcache.bufmap_locks[key]);
}

void
bunpin(struct buf *b) {

  int key = MAPHASHFN(b->blockno);

  acquire(&bcache.bufmap_locks[key]);
  b->refcnt--;
  release(&bcache.bufmap_locks[key]);
}
```

### lab 9 fs

（moderate）

```c
#define NDIRECT 11//这两部分意思就是将一个直接映射块给改成双层映射
#define NINDIRECT (BSIZE / sizeof(uint))
#define N2INDIRECT NINDIRECT*NINDIRECT
#define MAXFILE (NDIRECT + NINDIRECT + N2INDIRECT)

// On-disk inode structure
struct dinode {
  short type;           // File type
  short major;          // Major device number (T_DEVICE only)
  short minor;          // Minor device number (T_DEVICE only)
  short nlink;          // Number of links to inode in file system
  uint size;            // Size of file (bytes)
  uint addrs[NDIRECT+2];   // Data block addresses
};
```



```c
struct inode {//同步一下
  uint dev;           // Device number
  uint inum;          // Inode number
  int ref;            // Reference count
  struct sleeplock lock; // protects everything below here
  int valid;          // inode has been read from disk?

  short type;         // copy of disk inode
  short major;
  short minor;
  short nlink;
  uint size;
  uint addrs[NDIRECT+2];
};
```

然后进行BMAP的修改

```c
static uint
bmap(struct inode *ip, uint bn)
{
  uint addr, *a, *b;
  struct buf *bp;

  if(bn < NDIRECT){
    if((addr = ip->addrs[bn]) == 0)
      ip->addrs[bn] = addr = balloc(ip->dev);
    return addr;
  }
  bn -= NDIRECT;

  if(bn < NINDIRECT){
    // Load indirect block, allocating if necessary.
    if((addr = ip->addrs[NDIRECT]) == 0)
      ip->addrs[NDIRECT] = addr = balloc(ip->dev);
    bp = bread(ip->dev, addr);
    a = (uint*)bp->data;
    if((addr = a[bn]) == 0){
      a[bn] = addr = balloc(ip->dev);
      log_write(bp);
    }
    brelse(bp);
    return addr;
  }
  bn-=NINDIRECT;//如果单层引用不行 就开始使用下面的双层引用

  if(bn < N2INDIRECT){//在双层引用的范围内
    // Load 2_indirect block, allocating if necessary.
    if((addr = ip->addrs[NDIRECT+1]) == 0)
      ip->addrs[NDIRECT+1] = addr = balloc(ip->dev);
    // now we should load a block for 1_indirect block
    
    bp = bread(ip->dev, addr);//读块
    a = (uint*)bp->data;//将块看成是一个数组，便于下面的寻找
    
    uint index_1_indirect = bn/(NINDIRECT);// for addr + index_1_indirect
    uint index_block = bn%(NINDIRECT);// for addr + index_1_indirect[index_block]
    
    if((addr=a[index_1_indirect])==0){//如果第一层映射没有 就分配一个块
      a[index_1_indirect] = addr = balloc(ip->dev);
      log_write(bp);
    }
    brelse(bp);

    bp = bread(ip->dev, addr);//读块内容
    b = (uint*)bp->data;

    if((addr = b[index_block]) == 0){//如果第二层的块没有映射，那么进行第二次的的分配
      b[index_block] = addr = balloc(ip->dev);
      log_write(bp);
    }
    brelse(bp);
    return addr;
  }

  panic("bmap: out of range");
}
```

这里有一个课上和代码中一直强调的模式，然后再看上面的代码就会比较清晰和知道是为什么了 ，背后是锁的应用，非常玄妙，瞻仰一下，正好课上忽略了这一点，在作业中算是补充了吧。

```c
// log_write() replaces bwrite(); a typical use is:
//   bp = bread(...)
//   modify bp->data[]
//   log_write(bp)
//   brelse(bp)
```

（moderate）

这个实验就是添加一个软链接，然后在打开文件时SYS_open时，识别一下是不是软链接，是的话就一直进行路径的递归，知道找到文件、

```c
//添加系统调用，自己看前面的LAB中的步骤就行啦，然后开始主体部分
```

```c
uint64
sys_symlink(void){
  struct inode *ip;
  char target[MAXPATH], path[MAXPATH];
  if(argstr(0, target, MAXPATH) < 0 || argstr(1, path, MAXPATH) < 0)//读取传入的参数
    return -1;

  begin_op();//开始进行文件操作

  ip = create(path, T_SYMLINK, 0, 0);//创建一个Inode
  if(ip == 0){
    end_op();
    return -1;
  }

  // use the first data block to store target path.
  if(writei(ip, 0, (uint64)target, 0, strlen(target)) < 0) {
    end_op();
    return -1;
  }

  iunlockput(ip);

  end_op();
  return 0;
}
//这一段就是将inode初始化一下，并且写入路径
```

```c
uint64
sys_open(void)
{
  char path[MAXPATH];
  int fd, omode;
  struct file *f;
  struct inode *ip;
  int n;

  if((n = argstr(0, path, MAXPATH)) < 0 || argint(1, &omode) < 0)
    return -1;

  begin_op();

  if(omode & O_CREATE){
    ip = create(path, T_FILE, 0, 0);
    if(ip == 0){
      end_op();
      return -1;
    }
  } 
  else {//如果不是文件
    int symlink_depth = 0;//设置最深的深度，以避免回路
    while(1){
      if((ip = namei(path)) == 0){//如果找不到文件名
       end_op();
        return -1;
      }
     ilock(ip);//加锁
     if(ip->type == T_SYMLINK && omode != O_NOFOLLOW){//如果是软链接并且允许FOLLOW则开始递归，这里也可以写一个递归函数，然后调用
       if(++symlink_depth>10){//判断是否超过最大深度
         iunlockput(ip);
         end_op();
         return -1;
       }
        if(readi(ip,0,(uint64)path,0,MAXPATH)<0){//使用readi函数读取符号链接的目标路径，并将其存储在path变量中
         iunlockput(ip);
         end_op();
         return -1;
        }
       iunlockput(ip);//解锁进行下一次的递归
      }
     else{//如果上述条件都不满足，那么直接退出
      break;
      }
    }
  }

  if(ip->type == T_DEVICE && (ip->major < 0 || ip->major >= NDEV)){
    iunlockput(ip);
    end_op();
    return -1;
  }
```

### lab10 mmap

首先进行系统调用的添加，如前面的几个一样，省略

然后进行VMA结构体的设置

```c
#define NVMA 16

struct vma{
  int used;
  uint64 addr;
  uint64 length;
  int prot;
  int flags;
  struct file* f;
  uint64 file_start;
};

struct proc {
  struct spinlock lock;

  // p->lock must be held when using these:
  enum procstate state;        // Process state
  struct proc *parent;         // Parent process
  void *chan;                  // If non-zero, sleeping on chan
  int killed;                  // If non-zero, have been killed
  int xstate;                  // Exit status to be returned to parent's wait
  int pid;                     // Process ID

  // these are private to the process, so p->lock need not be held.
  uint64 kstack;               // Virtual address of kernel stack
  uint64 sz;                   // Size of process memory (bytes)
  pagetable_t pagetable;       // User page table
  struct trapframe *trapframe; // data page for trampoline.S
  struct context context;      // swtch() here to run process
  struct file *ofile[NOFILE];  // Open files
  struct inode *cwd;           // Current directory
  char name[16];               // Process name (debugging)
  struct vma vma[NVMA];          //设置一个数组 大小为16
};

```

完善SYS_MAP

```c
uint64 sys_mmap(){
  int len,prot,flags,fd;
  struct file* f;

  if(argint(1,&len)<0||argint(2,&prot)<0||argint(3,&flags)<0||argfd(4,&fd,&f)<0)//读取参数
    return -1;

   if(!f->writable && (prot & PROT_WRITE) && (flags & MAP_SHARED ) )//如果文件不可写，但是MAP想写 那么错误退出
   {
      return -1;
   }

   struct proc* p = myproc();

   for(int i=0;i<NVMA;i++){//查看该进程的VMA数组，找到一个合适的
    struct vma *v = &p->vma[i];
    if(!v->used){
      v->used=1;
      v->addr=p->sz;//空间紧接着下一个接着使用
      len = PGROUNDUP(len);//对齐分配
      p->sz += len;//进程使用大小变大
      v->length=len;//映射的区域长度
      v->flags = flags;
      v->prot=prot;
      v->f = filedup(f);//增减文件的调用
      v->file_start=0;//默认为0
      return v->addr;
    }
   }
   return -1;
}
```

然后进行USERTRAP的修改

```c
 else if((which_dev = devintr()) != 0){
    // ok
  } 
  else if(r_scause()==13 || r_scause()==15){//缺页
    uint64 va = r_stval();

    if(va>=p->sz) goto a;//判断虚拟地址是否在进程空间有效
    if(va<p->trapframe->sp) goto a;

    uint lazy=0;//是否分配了空间

    for(int i=0;i<NVMA;i++){
      struct vma* v = &p->vma[i];
      if(v->used&&va>=v->addr&&va<v->addr+v->length){//虚拟地址是否在映射的范围内
        char * mem = kalloc();
        if(mem==0) goto a;
        memset(mem,0,PGSIZE);
        va = PGROUNDDOWN(va);
        uint64 off=v->file_start+va-v->addr;

          //PROT_XX 和PTE_XX的关系就是两倍的关系
        if(mappages(p->pagetable,va,PGSIZE,(uint64)mem,(v->prot<<1) |PTE_U  )!=0)//进行页表的映射
	      {
	       kfree(mem);
	       goto a;
	      }
        ilock(v->f->ip);
        readi(v->f->ip,1,va,off,PGSIZE);//读取文件
	      iunlock(v->f->ip);
	      lazy=1;
	      break;
      }
    }
    if(!lazy) goto a;
  }
  else {
  a:
    printf("usertrap(): unexpected scause %p pid=%d\n", r_scause(), p->pid);
    printf("            sepc=%p stval=%p\n", r_sepc(), r_stval());
    p->killed = 1;
  }

  if(p->killed)
    exit(-1);
...
```

进行sys_ummap

```c
int write_back(struct file *f,uint64 addr,int n, uint off){
  int r=0;
  if(f->writable==0) return -1;

  int max = ((MAXOPBLOCKS-1-1-2)/2)*BSIZE;
  int i=0;

  while(i<n){
    int n1 = n-i;
    if(n1>max) n1=max;

    begin_op();
    ilock(f->ip);
    if((r=writei(f->ip,1,addr+i,off,n1))>0){
      off+=r;
    }
    iunlock(f->ip);
    end_op();

    if(r!=n1) break;
    i+=r;
  }
  return 0;
}

uint64 sys_munmap(void){
  uint64 addr;
  int length;
  int close=0;
  if(argaddr(0,&addr)<0||argint(1,&length)<0){
    return -1;
  }

  struct proc *p = myproc();

  for(int i=0;i<NVMA;i++){
    struct vma* v = &p->vma[i];
    if(v->used&&addr>=v->addr&&addr<=v->addr+v->length){//判断地址有效
      uint64 npage = 0;
      uint off = v->file_start;
      if(addr==v->addr){//从头开始的unmap
        if(length>=v->length){
          length=v->length;
          v->used=0;
          close=1;
        }
        else{
          v->addr+=length;
          v->file_start += length;
        }
      } 
      length=PGROUNDUP(length);
      npage= length/PGSIZE;
      v->length-=length;//更新大小
      p->sz-=length;

      if(v->flags&MAP_SHARED){//要将修改的文件写回磁盘
        write_back(v->f,addr,length,off);
      }

      uvmunmap(p->pagetable,PGROUNDDOWN(addr),npage,0);//取消映射

      if(close) fileclose(v->f);//最后减少文件的指针

      return 0;
    }
  }
  return -1;
}
```

fork和exit

```c
void
exit(int status)
{
  struct proc *p = myproc();

  if(p == initproc)
    panic("init exiting");

  // Close all open files.
  for(int fd = 0; fd < NOFILE; fd++){
    if(p->ofile[fd]){
      struct file *f = p->ofile[fd];
      fileclose(f);
      p->ofile[fd] = 0;
    }
  }

  for(int i=0;i<NVMA;i++){
    struct vma *v = &p->vma[i];
    if(v->used){
      uvmunmap(p->pagetable,v->addr,v->length,0);
      memset(v,0,sizeof(struct vma));
    }
  }

  begin_op();
  ....
```

```c
int
fork(void)
{
  int i, pid;
  struct proc *np;
  struct proc *p = myproc();

  // Allocate process.
  if((np = allocproc()) == 0){
    return -1;
  }

  for(int i=0;i<NVMA;i++){//将映射的位置一致了
    struct vma *v = &p->vma[i];
    struct vma *nv = &np->vma[i];
    if(v->used){
      memmove(nv,v,sizeof(struct vma));
      filedup(nv->f);
    }
  }
....
```

由于是懒分配，可能p->sz的范围内的不全部映射过来，所以修改下uvmunmap和uvmcopy

uvmunmap

```c
void
uvmunmap(pagetable_t pagetable, uint64 va, uint64 npages, int do_free)
{
  uint64 a;
  pte_t *pte;

  if((va % PGSIZE) != 0)
    panic("uvmunmap: not aligned");

  for(a = va; a < va + npages*PGSIZE; a += PGSIZE){
    if((pte = walk(pagetable, a, 0)) == 0)
      panic("uvmunmap: walk");
    if((*pte & PTE_V) == 0) return;
    //panic("uvmunmap: not mapped");
```

uvmcopy

```c
int
uvmcopy(pagetable_t old, pagetable_t new, uint64 sz)
{
  pte_t *pte;
  uint64 pa, i;
  uint flags;
  char *mem;

  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walk(old, i, 0)) == 0)
      panic("uvmcopy: pte should exist");
    if((*pte & PTE_V) == 0) continue;
    //panic("uvmcopy: page not present");
```

### lab 11 net

按照hints一步一步的写就行，Hints就是伪代码

```c
int
e1000_transmit(struct mbuf *m)
{
  acquire(&e1000_lock);
  uint32 index = regs[E1000_TDT];

  if(!(tx_ring[index].status&E1000_TXD_STAT_DD)){
    release(&e1000_lock);
    return -1;
  }

  if(tx_mbufs[index]){
    mbuffree(tx_mbufs[index]);
  }
  tx_mbufs[index]=m;
  memset(&tx_ring[index],0,sizeof(tx_ring[index]));

  tx_ring[index].addr = (uint64)m->head;
  tx_ring[index].length = m->len;

  tx_ring[index].cmd=E1000_TXD_CMD_RS|E1000_TXD_CMD_EOP;

  regs[E1000_TDT]=(index+1)%TX_RING_SIZE;
  release(&e1000_lock);
  return 0;
}

static void
e1000_recv(void)
{
  while(1){
    uint32 index = regs[E1000_RDT];
    index = (index+1)%RX_RING_SIZE;

    if(!(rx_ring[index].status&E1000_RXD_STAT_DD)){
      return ;
    }

    rx_mbufs[index]->len = rx_ring[index].length;

    net_rx(rx_mbufs[index]);

    struct mbuf* m = mbufalloc(0);

    rx_mbufs[index]=m;

    rx_ring[index].addr=(uint64)m->head;

    rx_ring[index].status=0;
    regs[E1000_RDT] = index;
  }
}
```

