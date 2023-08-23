## 系统调用
1. xv6是一个简单的UNIX系统
1. 系统调用是陷入系统调用的方式

## lecture  2 syscall
**isolation、kernel/usermode ,system call，multiplexing/**

1. Os shoule be defensive means strong isolation between apps+OS

2. strong isolation requires a hard boundary between apps/OS  
3. typical isolation  methods: 1. user/kernel mode  2. page table /VM
4. 特权指令，非特权指令
5. kernel : must have no bugs;must treat process as malicious

6. micro kernel(微内核)/monolithic kernel宏内核
## lecture 3 page
** address space; paging hw(risc_v); xv6 vmmode+layout **
for isolation
every program run in its own  space and has its own map
## lecture 4 gdb
layout asm/src/split/reg
## lecture 5 trap
有三种方式进行状态转化：
1. 系统调用，用户态程序执行ecall
2. 异常exception，用户或者内核态进行了非法指令
3. 设备中断（device interrupt）
xv6系统利用trap统称上述的情况。

stvec：The kernel writes the address of its trap handler here; the RISC-V jumps here to
handle a trap
sepc：When a trap occurs, RISC-V saves the program counter here；The sret (return from trap) instruction copies sepc to the pc
scause: The RISC-V puts a number here that describes the reason for the trap.
sscratch: The kernel places a value here that comes in handy at the very start of a trap
handler
sstatus: The SIE bit in sstatus controls whether device interrupts are enabled. If the
kernel clears SIE, the RISC-V will defer device interrupts until the kernel sets SIE. The SPP
bit indicates whether a trap came from user mode or supervisor mode, and controls to what
mode sret returns

the register above must be in Kernel mode.

**当需要执行trap时，硬件做一下这几件事**

1. If the trap is a device interrupt, and the sstatus SIE bit is clear, don’t do any of the
following.
2. Disable interrupts by clearing SIE.
3. Copy the pc to sepc.
4. Save the current mode (user or supervisor) in the SPP bit in sstatus.
5. Set scause to reflect the trap’s cause.
6. Set the mode to supervisor.
7. Copy stvec to the pc.
8. Start executing at the new pc.

**上述阶段不进行页表的转换**

+ uservec
  + must switch satp to point to kernel page table
  + swaps $ao $sscratch
  + save the user register
  + per-process has trapframe that has space to save register
  
+ usertrap

  + determine cause of trap;process it;return 

+ usertrapret

  + first step in returning to user space

    该函数设置RISC-V控制寄存器，为将来从用户空间发生的陷阱做准备。这涉及更改stvec以引用uservec，准备uservec所依赖的trapframe字段，并将sepc设置为先前保存的用户程序计数器。最后，usertrapret在用户和内核页表中映射的跳转页面上调用userret；原因是userret中的汇编代码将切换页表。

## lecture 6 page fault
**plan :  inplement VM features using page fault**
vm benefits : 
	1. isolation
	2. level of indirection
information needed : 1) faulting va  2)  the type of page fault 3) the va of instruction that cause the fault

page fault : 当使用的虚拟地址在堆上并且这一块并没有分配物理地址时。
+ allocate 1 page
+ zere the page
+ map the page
+ restart the instruction

cow(copy on work) -fork
+ cp page
+ map
+ restart instruction

## lecture7 interrupt
hardware want attention now 
software save it's work,process interrupt,resume its work

管理 设备的代码叫做驱动

**many device drivers execute code in two contexts: top half run in a process's kernel thread and a botttom half executes at interrupt time**


## lecture 8 multiprocess and locks
** when to lock?**
access a shared data structure

`` A process that wants to give up the CPU must acquire its own process lock p->lock, release any other locks it is holding, update its own state (p->state), and then call sched``

## lecture 9 sleep & wake up(coordination)
**no other lock for swtch**

## lecture 10 file system

#### log

1. 将磁盘写入的描述放置到日志文件中
2. 向磁盘提交所有描述全部放置到日志中
3. 进行实际地磁盘写入描述实现
4. 清除日志

