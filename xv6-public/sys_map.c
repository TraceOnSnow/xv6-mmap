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


int copy_maps(struct proc *parent, struct proc *child)
{
  // loop through pages
  for (int i = 0; i < parent->total_mmaps; i++) {
    struct mmap_region *parent_mmap = &parent->mmaps[i];
    struct mmap_region *child_mmap = &child->mmaps[i];
    
    child_mmap->virt_addr = parent_mmap->virt_addr;
    child_mmap->protection = parent_mmap->protection;
    child_mmap->flags = parent_mmap->flags;
    child_mmap->size = parent_mmap->size;
    child_mmap->stored_size = 0; // Initialize stored size for shared memory
    child_mmap->f = parent_mmap->f;
    child_mmap->offset = parent_mmap->offset;
    child_mmap->guard_page = parent_mmap->guard_page;
    child_mmap->ref_count = parent_mmap->ref_count;

    for (uint addr = parent_mmap->virt_addr; addr < parent_mmap->virt_addr + parent_mmap->size; addr += PGSIZE) {
      pte_t *pte;
      uint pa = get_physical_page(parent, addr, &pte);
      
      // check if page has been allocated
      if (pa == 0) {
        // If the page is not allocated, allocate and copy contents
        int total_mmap_size = parent_mmap->size - parent_mmap->stored_size;
        int size_to_copy = PGSIZE > total_mmap_size ? total_mmap_size : PGSIZE;
        
        if (mmap_store_data(parent, addr, size_to_copy, parent_mmap->flags, parent_mmap->protection, parent_mmap->f, parent_mmap->offset) < 0) {
          return -1;
        }
        
        parent_mmap->stored_size += size_to_copy;
        pa = get_physical_page(parent, addr, &pte);
      }
      // shared flag
      if (child_mmap->flags & MAP_SHARED) {
        char *parentmem = (char *)P2V(pa);
        if (mappages(child->pgdir, (void *)addr, PGSIZE, V2P(parentmem), child_mmap->protection) < 0) {
          cprintf("mmap page failed\n");
        }
      } 
      // private
      else if (child_mmap->flags & MAP_PRIVATE) {
        char *mem = kalloc();
        if (!mem) {
          return -1; // error
        }
        char *parentmem = (char *)P2V(pa);
        memmove(mem, parentmem, PGSIZE);
        if (mappages(child->pgdir, (void *)addr, PGSIZE, V2P(mem), child_mmap->protection) < 0) {
          return -1; // error
        }
      }
    }
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
    p->mmaps[j] = p->mmaps[j - 1];
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
  int i = 0;

  while (i < p->total_mmaps) {
    if (p->mmaps[i].virt_addr >= mmap_addr) {
      return -1;
    }

    uint start_addr = PGROUNDUP(p->mmaps[i].virt_addr + p->mmaps[i].size);
    uint end_addr = (i == p->total_mmaps - 1) ? 0 : PGROUNDUP(p->mmaps[i + 1].virt_addr);

    if (mmap_addr < start_addr && (end_addr == 0 || mmap_addr + size <= start_addr)) {
      return setup_mmap_arr(p, size, i - 1, mmap_addr);
    }

    i++;
  }

  return setup_mmap_arr(p, size, p->total_mmaps - 1, mmap_addr);
}

// To find the mmap region virtual address
int find_mmap_addr(struct proc *p, int size)
{
  int i = 0;
  uint mmapaddr = MMAPBASE;

  if (p->total_mmaps > 0) {
    while (i < p->total_mmaps) {
      uint start_addr = PGROUNDUP(p->mmaps[i].virt_addr + p->mmaps[i].size);
      uint end_addr = (i == p->total_mmaps - 1) ? KERNBASE : PGROUNDUP(p->mmaps[i + 1].virt_addr);

      if (mmapaddr + size <= start_addr) {
        return setup_mmap_arr(p, size, i - 1, mmapaddr);
      }

      if (end_addr - start_addr > size) {
        break;
      }

      i++;
      mmapaddr = PGROUNDUP(p->mmaps[i].virt_addr + p->mmaps[i].size);
    }

    if (mmapaddr + size > KERNBASE) {
      return -1;
    }
  }

  // If the loop didn't return, this means we can place the mmap at the end.
  return setup_mmap_arr(p, size, p->total_mmaps - 1, mmapaddr);
}


// file backed
static int map_file_util(struct proc *p, struct file *f, uint mmapaddr, int protection, int offset, int size)
{
  char *mapped_page = kalloc(); // Allocate a page for mapping
  if (!mapped_page)
  {
    // Kalloc failed
    return -1;
  }
  memset(mapped_page, 0, PGSIZE);

  int remaining_size = size;
  // int page_offset = 0;
  int i = 0;

  while (remaining_size > 0)
  {
    // Calculate the remaining space in the current page and the size to copy
    int curroff = offset % PGSIZE;
    int currsize = PGSIZE - curroff > remaining_size ? remaining_size : PGSIZE - curroff;

    // Check if the offset is beyond the file's size
    if (curroff > f->ip->size)
    {
      break;
    }

    offset -= offset % PGSIZE;
    char* page = kalloc();
    memset(page, 0, PGSIZE);
    readi(f->ip, page, offset, PGSIZE);

    memmove(mapped_page + size - remaining_size, page + curroff, currsize);

    remaining_size -= currsize;
    offset = 0;
    i += 1;
  }

  // Map the page to the user process
  if (mappages(p->pgdir, (void *)mmapaddr, PGSIZE, V2P(mapped_page), protection) < 0)
  {
    // Mapping failed, clean up and return error
    kfree(mapped_page);
    return -1;
  }

  return size;
}

// Main function which does file backed memory mapping
static int map_file_main(struct proc *p, struct file *f, uint mmapaddr, int protection, int offset, int size)
{
  int currsize = 0;
  int mainsize = size;
  for (; currsize < mainsize; currsize += PGSIZE)
  {
    int mapsize = PGSIZE > size ? size : PGSIZE;
    if (map_file_util(p, f, mmapaddr + currsize, protection, offset + currsize, mapsize) < 0)
    {
      return -1;
    }
    size -= PGSIZE;
  }
  return size;
}

static int map_anon_main(struct proc *p, uint start, int protection, int size)
{
  int i = 0;
  int result = size;

  for (; i < size; i += PGSIZE)
  {
    char *mapped_page = kalloc();
    if (!mapped_page)
    {
      return -1;
    }

    memset(mapped_page, 0, PGSIZE);

    if (mappages(p->pgdir, (void *)(start + i), PGSIZE, V2P(mapped_page), protection) < 0)
    {
      // mappages failed, clean up and return error
      deallocuvm(p->pgdir, start + i - PGSIZE, start + i);
      kfree(mapped_page);
      return -1;
    }
  }

  return result;
}

int mmap_store_data(struct proc *p, int addr, int size, int flags, int protection, struct file *f, int offset)
{
  if (!(flags & MAP_ANONYMOUS))
  { // File backed mapping
    if (map_file_main(p, f, addr, protection, offset, size) == -1)
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
void *my_mmap(int addr, int length, int prot, int flags, int fd, int offset)
{
  struct file *f = 0;
  
  int val = argfd(4, &fd, &f);
  if (val < 0) {
    if (!(flags & MAP_ANONYMOUS)) {
      return (void *)-1;
    }
  } else {
    // Duplicate the file
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
  
  struct proc *p = myproc();
  if (p->total_mmaps == 30)
  {
    // Mappings count exceeds
    return (void *)-1;
  }
  // MAP_FIXED flag
  int i = -1;
  if (flags & MAP_FIXED)
  {
    if ((void *)addr != (void *)0)
    {
      // Check if address is within range
      uint rounded_addr = PGROUNDUP(PGROUNDUP(addr) + length);
      if (addr < MMAPBASE || rounded_addr > KERNBASE || addr % PGSIZE != 0)
      {
        return (void *)-1;
      }
      // Check if address overlaps with any existing mappings
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
  // Store mmap info
  p->mmaps[i].flags = flags;
  p->mmaps[i].protection = 0;
  p->mmaps[i].protection = PTE_U | prot;
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
    // zero_mmap_region_struct(&p->mmaps[i]);
    memset(&p->mmaps[i], 0, sizeof(struct mmap_region));
    // Left shift the mmap array
    while (i < 30 && p->mmaps[i + 1].virt_addr)
    {
      p->mmaps[i] = p->mmaps[i + 1];
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
