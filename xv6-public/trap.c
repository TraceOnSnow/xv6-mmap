#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "x86.h"
#include "traps.h"
#include "spinlock.h"
#include "mmap.h"

// Interrupt descriptor table (shared by all CPUs).
struct gatedesc idt[256];
extern uint vectors[];  // in vectors.S: array of 256 entry pointers
struct spinlock tickslock;
uint ticks;

void
tvinit(void)
{
  int i;

  for(i = 0; i < 256; i++)
    SETGATE(idt[i], 0, SEG_KCODE<<3, vectors[i], 0);
  SETGATE(idt[T_SYSCALL], 1, SEG_KCODE<<3, vectors[T_SYSCALL], DPL_USER);

  initlock(&tickslock, "time");
}

void
idtinit(void)
{
  lidt(idt, sizeof(idt));
}

void handle_page_fault(struct trapframe *tf) {
  struct proc *p = myproc();
  uint page_fault_addr = rcr2();
  for (int i = 0; i < p->total_mmaps; i++) {
    // Check if the mapping has the MAP_GROWSUP flag set
      if (p->mmaps[i].flags & MAP_GROWSUP) {
        // cprintf("HELLOOOOOOO\n");
        if (page_fault_addr >= p->mmaps[i].guard_page && page_fault_addr <= p->mmaps[i].guard_page + PGSIZE) {
          // The fault occurred in the guard page. Check the margin constraint.
           // cprintf("HELLOOOOOOO\n");
          if (i < p->total_mmaps - 1 && page_fault_addr + PGSIZE >= p->mmaps[i + 1].virt_addr - PGSIZE) {
            // Violates the margin constraint; trigger a segmentation fault.
            cprintf("Segmentation Fault\n");
            // cprintf("Segmentation Fault: %p\n", rcr2());
            myproc()->killed = 1;
            return;
          }
          // cprintf("HELLOOOOOOO\n");
          // Extend the mapping by one page.
          p->mmaps[i].size += PGSIZE;
          uint remsize = p->mmaps[i].size - p->mmaps[i].stored_size;
          int size = PGSIZE > remsize ? remsize : PGSIZE;
          if (mmap_store_data(p, PGROUNDDOWN(page_fault_addr), size, p->mmaps[i].flags, p->mmaps[i].protection,
                              p->mmaps[i].f, p->mmaps[i].offset + PGROUNDDOWN(page_fault_addr) - p->mmaps[i].virt_addr) < 0) {
            myproc()->killed = 1;
          }
          p->mmaps[i].stored_size += PGSIZE;
          p->mmaps[i].guard_page += PGSIZE;
          return;
        }
        else {
          uint start = p->mmaps[i].virt_addr;
          uint end = start + p->mmaps[i].size;
          if (page_fault_addr >= start && page_fault_addr <= end) {
            pde_t *pte;
            if (get_physical_page(p, PGROUNDDOWN(page_fault_addr), &pte) != 0) {
              cprintf("Segmentation Fault\n");
              // cprintf("Segmentation Fault: %p\n", rcr2());
              myproc()->killed = 1;
              return;
            }
          uint remsize = p->mmaps[i].size - p->mmaps[i].stored_size;
          int size = PGSIZE > remsize ? remsize : PGSIZE;
          if (mmap_store_data(p, PGROUNDDOWN(page_fault_addr), size, p->mmaps[i].flags, p->mmaps[i].protection,
                          p->mmaps[i].f, p->mmaps[i].offset + PGROUNDDOWN(page_fault_addr) - p->mmaps[i].virt_addr) < 0) {
                          myproc()->killed = 1;
          }
        p->mmaps[i].stored_size += PGSIZE;
      return;
        }
      }
    }

    else {
    uint start = p->mmaps[i].virt_addr;
    uint end = start + p->mmaps[i].size;
    if (page_fault_addr >= start && page_fault_addr <= end) {
      pde_t *pte;
      if (get_physical_page(p, PGROUNDDOWN(page_fault_addr), &pte) != 0) {
        cprintf("Segmentation Fault\n");
        // cprintf("Segmentation Fault: %p\n", rcr2());
        myproc()->killed = 1;
        return;
      }
        uint remsize = p->mmaps[i].size - p->mmaps[i].stored_size;
        int size = PGSIZE > remsize ? remsize : PGSIZE;
        if (mmap_store_data(p, PGROUNDDOWN(page_fault_addr), size, p->mmaps[i].flags, p->mmaps[i].protection,
                          p->mmaps[i].f, p->mmaps[i].offset + PGROUNDDOWN(page_fault_addr) - p->mmaps[i].virt_addr) < 0) {
                          myproc()->killed = 1;
        }
        p->mmaps[i].stored_size += PGSIZE;
      return;
    }
    }
  }
  cprintf("Segmentation Fault\n");
  // cprintf("Segmentation Fault: %p\n", rcr2());

  myproc()->killed = 1;
}


// To handle page faults for mmap (lazy mapping)
/*
void handle_page_fault(struct trapframe *tf) {
  struct proc *p = myproc();
  uint page_fault_addr = rcr2();
  for (int i = 0; i < p->total_mmaps; i++) {
    uint start = p->mmaps[i].virt_addr;
    uint end = start + p->mmaps[i].size;
    if (page_fault_addr >= start && page_fault_addr <= end) {
      pde_t *pte;
      if (get_physical_page(p, PGROUNDDOWN(page_fault_addr), &pte) != 0) {
        cprintf("Segmentation Fault\n");
        // cprintf("Segmentation Fault: %p\n", rcr2());
        myproc()->killed = 1;
        return;
      }
      // Check if the mapping has the MAP_GROWSUP flag set
      if (p->mmaps[i].flags & MAP_GROWSUP) {
        // cprintf("HELLOOOOOOO\n");
        if (page_fault_addr >= p->mmaps[i].guard_page && page_fault_addr <= p->mmaps[i].guard_page + PGSIZE) {
          // The fault occurred in the guard page. Check the margin constraint.
          cprintf("HELLOOOOOOO\n");
          if (i < p->total_mmaps - 1 && page_fault_addr + PGSIZE >= p->mmaps[i + 1].virt_addr - PGSIZE) {
            // Violates the margin constraint; trigger a segmentation fault.
            cprintf("Segmentation Fault\n");
            // cprintf("Segmentation Fault: %p\n", rcr2());
            myproc()->killed = 1;
            return;
          }

          // Extend the mapping by one page.
          uint remsize = p->mmaps[i].size - p->mmaps[i].stored_size;
          int size = PGSIZE > remsize ? remsize : PGSIZE;
          if (mmap_store_data(p, PGROUNDDOWN(page_fault_addr), size, p->mmaps[i].flags, p->mmaps[i].protection,
                              p->mmaps[i].f, p->mmaps[i].offset + PGROUNDDOWN(page_fault_addr) - p->mmaps[i].virt_addr) < 0) {
            myproc()->killed = 1;
          }
          p->mmaps[i].stored_size += PGSIZE;
          p->mmaps[i].guard_page += PGSIZE;
          return;
        }
      }

      
        uint remsize = p->mmaps[i].size - p->mmaps[i].stored_size;
        int size = PGSIZE > remsize ? remsize : PGSIZE;
        if (mmap_store_data(p, PGROUNDDOWN(page_fault_addr), size, p->mmaps[i].flags, p->mmaps[i].protection,
                          p->mmaps[i].f, p->mmaps[i].offset + PGROUNDDOWN(page_fault_addr) - p->mmaps[i].virt_addr) < 0) {
                          myproc()->killed = 1;
        }
        p->mmaps[i].stored_size += PGSIZE;
      return;
      
      
    }
  }
  cprintf("Segmentation Fault\n");
  // cprintf("Segmentation Fault: %p\n", rcr2());

  myproc()->killed = 1;
}
*/

//PAGEBREAK: 41
void
trap(struct trapframe *tf)
{
  if(tf->trapno == T_SYSCALL){
    if(myproc()->killed)
      exit();
    myproc()->tf = tf;
    syscall();
    if(myproc()->killed)
      exit();
    return;
  }

  switch(tf->trapno){
  case T_IRQ0 + IRQ_TIMER:
    if(cpuid() == 0){
      acquire(&tickslock);
      ticks++;
      wakeup(&ticks);
      release(&tickslock);
    }
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_IDE:
    ideintr();
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_IDE+1:
    // Bochs generates spurious IDE1 interrupts.
    break;
  case T_IRQ0 + IRQ_KBD:
    kbdintr();
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_COM1:
    uartintr();
    lapiceoi();
    break;

  case T_IRQ0 + 7:
  case T_IRQ0 + IRQ_SPURIOUS:
    cprintf("cpu%d: spurious interrupt at %x:%x\n",
            cpuid(), tf->cs, tf->eip);
    lapiceoi();
    break;
  case T_PGFLT: //14  
    // cprintf("\tPagefault at virtual addr %x\n", rcr2());
    if (rcr2() >= MMAPBASE && rcr2() < KERNBASE) {
      handle_page_fault(tf);
      break;
    }

  //PAGEBREAK: 13
  default:
    if(myproc() == 0 || (tf->cs&3) == 0){
      // In kernel, it must be our mistake.
      cprintf("unexpected trap %d from cpu %d eip %x (cr2=0x%x)\n",
              tf->trapno, cpuid(), tf->eip, rcr2());
      panic("trap");
    }
    // In user space, assume process misbehaved.
    cprintf("pid %d %s: trap %d err %d on cpu %d "
            "eip 0x%x addr 0x%x--kill proc\n",
            myproc()->pid, myproc()->name, tf->trapno,
            tf->err, cpuid(), tf->eip, rcr2());
    myproc()->killed = 1;
  }

  // Force process exit if it has been killed and is in user space.
  // (If it is still executing in the kernel, let it keep running
  // until it gets to the regular system call return.)
  if(myproc() && myproc()->killed && (tf->cs&3) == DPL_USER)
    exit();

  // Force process to give up CPU on clock tick.
  // If interrupts were on while locks held, would need to check nlock.
  if(myproc() && myproc()->state == RUNNING &&
     tf->trapno == T_IRQ0+IRQ_TIMER)
    yield();

  // Check if the process has been killed since we yielded
  if(myproc() && myproc()->killed && (tf->cs&3) == DPL_USER)
    exit();
}
