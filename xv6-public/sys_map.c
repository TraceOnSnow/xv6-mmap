#include "types.h"
#include "defs.h"
#include "param.h"
#include "mmu.h"
#include "proc.h"
#include "fs.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "file.h"
#include "fcntl.h"
#include "defs.h"
#include "memlayout.h"
#include "mmap.h"

// <!! ---------------- Mmap Utils -------------------- !!>

// whole mmap region structure
void zero_mmap_region_struct(struct mmap_region *mr)
{
  mr->virt_addr = 0;
  mr->size = 0;
  mr->flags = 0;
  mr->protection = 0;
  mr->f = 0;
  mr->offset = 0;
  mr->flags = 0;
  mr->stored_size = 0;
}

// Copy the mmap regions from src to dest
// First arg: dest
// Second arg: src
void copy_mmap_struct(struct mmap_region *mr1, struct mmap_region *mr2)
{
  mr1->virt_addr = mr2->virt_addr;
  mr1->size = mr2->size;
  mr1->flags = mr2->flags;
  mr1->protection = mr2->protection;
  mr1->f = mr2->f;
  mr1->offset = mr2->offset;
}

// Get physical Address of page from virtual address of process
uint get_physical_page(struct proc *p, uint tempaddr, pte_t **pte)
{
  *pte = walkpgdir(p->pgdir, (char *)tempaddr, 0);
  if (!*pte)
  {
    return 0;
  }
  uint pa = PTE_ADDR(**pte);
  return pa;
}

// Copy mmaps from parent to child process
int copy_maps(struct proc *parent, struct proc *child)
{
  pte_t *pte;
  int i = 0;
  while (i < parent->total_mmaps)
  {
    uint virt_addr = parent->mmaps[i].virt_addr;
    int protection = parent->mmaps[i].protection;
    int isshared = parent->mmaps[i].flags & MAP_SHARED;
    uint size = parent->mmaps[i].size;
    uint start = virt_addr;
    for (; start < virt_addr + size; start += PGSIZE)
    {
      uint pa = get_physical_page(parent, start, &pte);
      // MAP_SHARED flag
      if (isshared)
      {
        // If pa is zero then page is not allocated yet, allocate and continue
        if (pa == 0)
        {
          int total_mmap_size = parent->mmaps[i].size - parent->mmaps[i].stored_size;
          int size = PGSIZE > total_mmap_size ? total_mmap_size : PGSIZE;
          if (mmap_store_data(parent, start, size, parent->mmaps[i].flags, protection, parent->mmaps[i].f, parent->mmaps[i].offset) < 0)
          {
            return -1;
          }
          parent->mmaps[i].stored_size += size;
        }
        pa = get_physical_page(parent, start, &pte);
        // If the page is shared and then all the data should be stored in page
        // and mapped to each process
        char *parentmem = (char *)P2V(pa);
        if (mappages(child->pgdir, (void *)start, PGSIZE, V2P(parentmem), protection) < 0)
        {
          // ERROR: Shared mappages failed
          cprintf("CopyMaps: mappages failed\n");
        }
      }
      // MAP_PRIVATE flag
      else
      {
        // If the mapping is private, lazy mapping can be done
        if (pa == 0)
        {
          continue;
        }
        char *mem = kalloc();
        if (!mem)
        {
          // ERROR: Private kalloc failed
          return -1;
        }
        char *parentmem = (char *)P2V(pa);
        memmove(mem, parentmem, PGSIZE);
        if (mappages(child->pgdir, (void *)start, PGSIZE, V2P(mem), protection) < 0)
        {
          // ERROR: Private mappages failed
          return -1;
        }
      }
    }
    copy_mmap_struct(&child->mmaps[i], &parent->mmaps[i]);
    if (isshared)
    {
      child->mmaps[i].ref_count = 1;
    }
    i += 1;
  }
  child->total_mmaps = parent->total_mmaps;
  return 0;
}

// Right shift the array and add the mappings at i + 1 index
int setup_mmap_arr(struct proc *p, int size, int i, uint mmapaddr)
{
  int j = p->total_mmaps;
  while (j > i + 1)
  {
    copy_mmap_struct(&p->mmaps[j], &p->mmaps[j - 1]);
    j--;
  }
  if (PGROUNDUP(mmapaddr + size) >= KERNBASE)
  {
    // Address Exceeds KERNBASE
    return -1;
  }
  p->mmaps[i + 1].virt_addr = mmapaddr;
  p->mmaps[i + 1].size = size;
  // Initialize the guard page after the new mapping
  p->mmaps[i + 1].guard_page = mmapaddr + size;
  return i + 1; // Return the index of mmap mapping
}

// To check if mmap is possible at user provided address
int check_mmap_possible(struct proc *p, uint addr, int size)
{
  uint mmap_addr = PGROUNDUP(addr);
  if (mmap_addr > PGROUNDUP(p->mmaps[p->total_mmaps - 1].virt_addr + p->mmaps[p->total_mmaps - 1].size))
  {
    return setup_mmap_arr(p, size, p->total_mmaps - 1, mmap_addr);
  }
  int i = 0;
  for (; i < p->total_mmaps - 1; i++)
  {
    if (p->mmaps[i].virt_addr >= mmap_addr)
    {
      return -1;
    }
    int start_addr = PGROUNDUP(p->mmaps[i].virt_addr + p->mmaps[i].size);
    int end_addr = PGROUNDUP(p->mmaps[i + 1].virt_addr);
    if (mmap_addr > start_addr && end_addr > mmap_addr + size)
    {
      return setup_mmap_arr(p, size, i, mmap_addr);
    }
  }
  return -1;
}

// To find the mmap region virtual address
int find_mmap_addr(struct proc *p, int size)
{
  if (p->total_mmaps == 0)
  {
    if (PGROUNDUP(MMAPBASE + size) >= KERNBASE)
    {
      // Address Exceeds KERNBASE
      return -1;
    }
    p->mmaps[0].virt_addr = PGROUNDUP(MMAPBASE);
    p->mmaps[0].size = size;
    // Initialize the guard page after the first mapping
    p->mmaps[0].guard_page = PGROUNDUP(MMAPBASE) + size;
    return 0; // Return the index in mmap region array
  }
  int i = 0;
  uint mmapaddr;
  // If mapping is possible between MMAPBASE & first mapping
  if (p->mmaps[0].virt_addr - MMAPBASE > size)
  {
    mmapaddr = MMAPBASE;
    return setup_mmap_arr(p, size, -1, mmapaddr);
  }
  // Find the map address
  while (i < p->total_mmaps && p->mmaps[i + 1].virt_addr != 0)
  {
    uint start_addr = PGROUNDUP(p->mmaps[i].virt_addr + p->mmaps[i].size);
    uint end_addr = PGROUNDUP(p->mmaps[i + 1].virt_addr);
    if (end_addr - start_addr > size)
    {
      break;
    }
    i += 1;
  }
  mmapaddr = PGROUNDUP(p->mmaps[i].virt_addr + p->mmaps[i].size);
  if (mmapaddr + size > KERNBASE)
  {
    return -1;
  }
  // Right shift the mappings to arrange in increasing order
  return setup_mmap_arr(p, size, i, mmapaddr);
}

// <!! -------- File Backed Mapping -------------- !!>
// Function to map the pagecache page to process
static int map_pagecache_page_util(struct proc *p, struct file *f, uint mmapaddr, int protection, int offset, int size)
{
  char *temp = kalloc(); // Allocate a temporary page
  if (!temp)
  {
    // Kalloc failed
    return -1;
  }
  memset(temp, 0, PGSIZE);
  // copy the file content from page cache to allocated memory
  int tempsize = size;
  int i = 0;
  while (tempsize != 0)
  {
    // Get the page from page cache
    int curroff = offset % PGSIZE;
    int currsize = PGSIZE - curroff > tempsize ? tempsize : PGSIZE - curroff;
    if (curroff > f->ip->size)
    {
      break;
    }
    int a = copyPage(f->ip, offset + PGSIZE * i, f->ip->inum, f->ip->dev,
                     temp + size - tempsize, currsize, curroff);
    if (a == -1)
      return -1;
    tempsize -= currsize;
    offset = 0;
    i += 1;
  }
  // Map the page to user process
  if (mappages(p->pgdir, (void *)mmapaddr, PGSIZE, V2P(temp), protection) < 0)
  {
    return -1;
  }
  return size;
}

// Main function which does file backed memory mapping
static int map_pagecache_page(struct proc *p, struct file *f, uint mmapaddr, int protection, int offset, int size)
{
  int currsize = 0;
  int mainsize = size;
  for (; currsize < mainsize; currsize += PGSIZE)
  {
    int mapsize = PGSIZE > size ? size : PGSIZE;
    if (map_pagecache_page_util(p, f, mmapaddr + currsize, protection, offset + currsize, mapsize) < 0)
    {
      return -1;
    }
    size -= PGSIZE;
  }
  return size;
}

// <!!-------- Anonymous Mapping --------------- !!>
static int map_anon_page(struct proc *p, uint off, int protection)
{
  char *mapped_page = kalloc();
  if (!mapped_page)
  {
    // Kalloc failed
    return -1;
  }
  memset(mapped_page, 0, PGSIZE);
  if (mappages(p->pgdir, (void *)off, PGSIZE, V2P(mapped_page), protection) < 0)
  {
    // mappages failed
    deallocuvm(p->pgdir, off - PGSIZE, off);
    kfree(mapped_page);
    return -1;
  }
  return 0;
}

// Function to map anonymous private page
static int map_anon_main(struct proc *p, uint mmapaddr, int protection, int size)
{
  int i = 0;
  for (; i < size; i += PGSIZE)
  {
    if (map_anon_page(p, mmapaddr + i, protection) < 0)
      return -1;
  }
  return size;
}

// <!! ------------------ Main Functions ------------- !!>
int mmap_store_data(struct proc *p, int addr, int size, int flags, int protection, struct file *f, int offset)
{
  if (!(flags & MAP_ANONYMOUS))
  { // File backed mapping
    if (map_pagecache_page(p, f, addr, protection, offset, size) == -1)
    {
      return -1;
    }
  }
  else
  { // Anonymous mapping
    if (map_anon_main(p, addr, protection, size) < 0)
    {
      return -1;
    }
  }
  return 0;
}

int argfd(int n, int *pfd, struct file **pf)
{
  int fd;
  struct file *f;

  if(argint(n, &fd) < 0)
    return -1;
  if(fd < 0 || fd >= NOFILE || (f=myproc()->ofile[fd]) == 0)
		return -1;
  if(pfd)
    *pfd = fd;
  if(pf)
    *pf = f;
  return 0;
}

// mmap system call main function
// void *my_mmap(int addr, struct file *f, int size, int offset, int flags, int protection) {
void *my_mmap(int addr, int length, int prot, int flags, int fd, int offset)
// void *my_mmap(int addr, int length, int prot, int flags, struct file *f, int offset)
{
  // int fd;
  struct file *f = 0;
  // struct proc *p = myproc();
  
  int val = argfd(4, &fd, &f);
  if (val < 0) {
    if (!(flags & MAP_ANONYMOUS)) {
      return (void *)-1;
    }
  } else {
    // Duplicate the file so it will work even when the descriptor is closed
    filedup(f);
  }

  if (!(flags & MAP_PRIVATE) && !(flags & MAP_SHARED))
  {
    // Invalid arguements
    return (void *)-1;
  }
  // When size provided is less or equal to zero and offset is less than zero
  if (length <= 0 || offset < 0)
  {
    return (void *)-1;
  }
  // File mapping without read permission on file
  if (!(flags & MAP_ANONYMOUS) && !f->readable)
  {
    return (void *)-1;
  }
  // When the mapping is shared and write permission is provided but opened file
  // is not opened in write mode
  if ((flags & MAP_SHARED) && (prot & PROT_WRITE) && !f->writable)
  {
    return (void *)-1;
  }
  struct proc *p = myproc();
  if (p->total_mmaps == 30)
  {
    // Mappings count exceeds
    return (void *)-1;
  }
  // check if MAP_FIXED flag
  int i = -1;
  if (flags & MAP_FIXED)
  {
    if ((void *)addr != (void *)0)
    {
      // Check if the provided address is within the valid range
      uint rounded_addr = PGROUNDUP(PGROUNDUP(addr) + length);
      if (addr < MMAPBASE || rounded_addr > KERNBASE || addr % PGSIZE != 0)
      {
        return (void *)-1;
      }
      // Check if the provided address overlaps with existing mappings
      i = check_mmap_possible(p, (uint)addr, length);
      if (i == -1)
      {
        return (void *)-1;
      }
    }
  }
  // not MAP_FIXED flag
  else
  {
      i = find_mmap_addr(p, length);
    if (i == -1)
    {
      return (void *)-1;
    }
  }
  // Store mmap info in process's mmap array
  p->mmaps[i].flags = flags;
  if (prot == PROT_NONE)
  {
    p->mmaps[i].protection = 0;
  }
  else
  {
    p->mmaps[i].protection = PTE_U | prot;
  }
  p->mmaps[i].offset = offset;
  p->mmaps[i].f = f;
  p->total_mmaps += 1;
  return (void *)p->mmaps[i].virt_addr;
}

// Main function of munmap system call
int my_munmap(struct proc *p, int addr, int size)
{
  pte_t *pte;
  uint mainaddr = PGROUNDUP(addr);
  int unmapping_size = PGROUNDUP(size);
  int i = 0;
  int total_size = 0;
  // Find the mmap entry
  for (; i < 30; i++)
  {
    if (p->mmaps[i].virt_addr == mainaddr)
    {
      total_size = p->mmaps[i].size;
      break;
    }
  }
  // Page with given address does not exist
  if (i == 30 || total_size == 0)
  {
    // Addr not present in mappings
    return -1;
  }
  uint isanon = p->mmaps[i].flags & MAP_ANONYMOUS;
  uint isshared = p->mmaps[i].flags & MAP_SHARED;
  if (isshared && !isanon && (p->mmaps[i].protection & PROT_WRITE))
  {
    // write into the file
    p->mmaps[i].f->off = p->mmaps[i].offset;
    if (filewrite(p->mmaps[i].f, (char *)p->mmaps[i].virt_addr, p->mmaps[i].size) < 0)
    {
      // File write failed
      return -1;
    }
  }
  // Free the allocated page
  int currsize = 0;
  int main_map_size = unmapping_size > total_size ? total_size : unmapping_size;
  for (; currsize < main_map_size; currsize += PGSIZE)
  {
    uint tempaddr = addr + currsize;
    uint pa = get_physical_page(p, tempaddr, &pte);
    if (pa == 0)
    {
      // Page was not mapped yet
      continue;
    }
    char *v = P2V(pa);
    kfree(v);
    *pte = 0;
  }
  if (p->mmaps[i].size <= unmapping_size)
  {
    zero_mmap_region_struct(&p->mmaps[i]);
    // Left shift the mmap array
    while (i < 30 && p->mmaps[i + 1].virt_addr)
    {
      copy_mmap_struct(&p->mmaps[i], &p->mmaps[i + 1]);
      i += 1;
    }
    p->total_mmaps -= 1;
  }
  else
  {
    p->mmaps[i].virt_addr += unmapping_size;
    p->mmaps[i].size -= unmapping_size;
  }

  return 0;
}

void delete_mmaps(struct proc *p)
{
  int total_maps = p->total_mmaps;
  while (total_maps > 0)
  {
    if (p->mmaps[p->total_mmaps - 1].ref_count == 0)
    {
      my_munmap(p, p->mmaps[total_maps - 1].virt_addr,
                p->mmaps[total_maps - 1].size);
    }
    total_maps--;
  }
  p->total_mmaps = 0;
}