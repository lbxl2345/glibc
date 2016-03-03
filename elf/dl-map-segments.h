/* Map in a shared object's segments.  Generic version.
   Copyright (C) 1995-2015 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <dl-load.h>

/* This implementation assumes (as does the corresponding implementation
   of _dl_unmap_segments, in dl-unmap-segments.h) that shared objects
   are always laid out with all segments contiguous (or with gaps
   between them small enough that it's preferable to reserve all whole
   pages inside the gaps with PROT_NONE mappings rather than permitting
   other use of those parts of the address space).  */

static __always_inline const char *
_dl_map_segments (struct link_map *l, int fd,
                  const ElfW(Ehdr) *header, int type,
                  const struct loadcmd loadcmds[], size_t nloadcmds,
                  /* lbx const*/ size_t maplength, bool has_holes,
                  struct link_map *loader)
{
  const struct loadcmd *c = loadcmds;

  if (__glibc_likely (type == ET_DYN))
    {
      /* This is a position-independent shared object.  We can let the
         kernel map it anywhere it likes, but we must have space for all
         the segments in their specified positions relative to the first.
         So we map the first segment without MAP_FIXED, but with its
         extent increased to cover all the segments.  Then we remove
         access from excess portion, and there is known sufficient space
         there to remap from the later segments.

         As a refinement, sometimes we have an address that we would
         prefer to map such objects at; but this is only a preference,
         the OS can do whatever it likes. */

      
      ElfW(Addr) mappref
        = (ELF_PREFERRED_ADDRESS (loader, maplength,
                                  c->mapstart & GLRO(dl_use_load_bias))
           - MAP_BASE_ADDR (l));

      /* Remember which part of the address space this object uses.  */
      l->l_map_start = (ElfW(Addr)) __mmap ((void *) mappref, maplength,
                                            c->prot,
                                            MAP_COPY|MAP_FILE,
                                            fd, c->mapoff);
      _dl_dprintf(1, "maplength:%lx\n", (unsigned long) maplength);
      if (__glibc_unlikely ((void *) l->l_map_start == MAP_FAILED))
        return DL_MAP_SEGMENTS_ERROR_MAP_SEGMENT;

      l->l_map_end = l->l_map_start + maplength;
      l->l_addr = l->l_map_start - c->mapstart;

      if (has_holes)
        /* Change protection on the excess portion to disallow all access;
           the portions we do not remap later will be inaccessible as if
           unallocated.  Then jump into the normal segment-mapping loop to
           handle the portion of the segment past the end of the file
           mapping.  */
        __mprotect ((caddr_t) (l->l_addr + c->mapend),
                    loadcmds[nloadcmds - 1].mapstart - c->mapend,
                    PROT_NONE);

      l->l_contiguous = 1;

      goto postmap;
    }

  /* Remember which part of the address space this object uses.  */
  l->l_map_start = c->mapstart + l->l_addr;
  l->l_map_end = l->l_map_start + maplength;
  l->l_contiguous = !has_holes;
uint64_t temp;
  while (c < &loadcmds[nloadcmds])
    {
      if (c->mapend > c->mapstart
          /* Map the segment contents from the file.  */
          && (temp = __mmap ((void *) (l->l_addr + c->mapstart),
                      c->mapend - c->mapstart, c->prot,
                      MAP_FIXED|MAP_COPY|MAP_FILE,
                      fd, c->mapoff)
              == MAP_FAILED))
        return DL_MAP_SEGMENTS_ERROR_MAP_SEGMENT;

    _dl_dprintf(1, "getting addr:%lx\n", (unsigned long)(temp));
     _dl_dprintf(1, "segment l_addr:%lx\n", (unsigned long)(l->l_addr));
    _dl_dprintf(1, "segment address: %lx\n", (unsigned long)(l->l_addr + c->mapstart));
    _dl_dprintf(1, "segment length:%lx\n", (unsigned long)(c->mapend - c->mapstart));
    _dl_dprintf(1, "segment offset: %lx\n", (unsigned long)(c->mapoff));

    postmap:
      _dl_postprocess_loadcmd (l, header, c);

      if (c->allocend > c->dataend)
        {
          /* Extra zero pages should appear at the end of this segment,
             after the data mapped from the file.   */
          ElfW(Addr) zero, zeroend, zeropage;

          zero = l->l_addr + c->dataend;
          zeroend = l->l_addr + c->allocend;
          zeropage = ((zero + GLRO(dl_pagesize) - 1)
                      & ~(GLRO(dl_pagesize) - 1));

          if (zeroend < zeropage)
            /* All the extra data is in the last page of the segment.
               We can just zero it.  */
            zeropage = zeroend;

          if (zeropage > zero)
            {
              /* Zero the final part of the last page of the segment.  */
              if (__glibc_unlikely ((c->prot & PROT_WRITE) == 0))
                {
                  /* Dag nab it.  */
                  if (__mprotect ((caddr_t) (zero
                                             & ~(GLRO(dl_pagesize) - 1)),
                                  GLRO(dl_pagesize), c->prot|PROT_WRITE) < 0)
                    return DL_MAP_SEGMENTS_ERROR_MPROTECT;
                }
              memset ((void *) zero, '\0', zeropage - zero);
              if (__glibc_unlikely ((c->prot & PROT_WRITE) == 0))
                __mprotect ((caddr_t) (zero & ~(GLRO(dl_pagesize) - 1)),
                            GLRO(dl_pagesize), c->prot);
            }

          if (zeroend > zeropage)
            {
              /* Map the remaining zero pages in from the zero fill FD.  */
              caddr_t mapat;
              mapat = __mmap ((caddr_t) zeropage, zeroend - zeropage,
                              c->prot, MAP_ANON|MAP_PRIVATE|MAP_FIXED,
                              -1, 0);
              if (__glibc_unlikely (mapat == MAP_FAILED))
                return DL_MAP_SEGMENTS_ERROR_MAP_ZERO_FILL;
            }
        }
        //lbx addcodes
        if(c == l->data_cmd)
        {
          l->data_info.start = l->l_addr + c->mapstart;
          l->data_info.end = l->l_addr + c->mapend;
        }
        if(c == l->text_cmd)
        {
          l->text_info.start = l->l_addr + c->mapstart;
          l->text_info.end = l->l_addr + c->mapend;
        }

      ++c;
    }

    //lbx add codes here
    //not mapping here
    if(l->l_shared_flag == 0 && l->l_protected_flag == 1)
    {
      _dl_dprintf(1,"------------------------pref_addr:%lx--------------------------\n",(unsigned long)(l->l_jshdr.entry_addr));
     ElfW(Addr) entry_addr = (ElfW(Addr) )__mmap ((void *) (0x602000),
                    0x1000, PROT_EXEC | PROT_READ | PROT_WRITE,
                      MAP_FIXED|MAP_COPY|MAP_FILE,
                      fd, 4096 * 3);
     _dl_dprintf(1, "-----------------------off_addr: %lx--------------------------\n", (unsigned long)(l->l_jshdr.entry_off));
     _dl_dprintf(1, "-----------------------get_addr: %lx--------------------------\n", (unsigned long)(entry_addr));
    }

  /* Notify ELF_PREFERRED_ADDRESS that we have to load this one
     fixed.  */
  ELF_FIXED_ADDRESS (loader, c->mapstart);

  return NULL;
}
