nosecmem
========

This project demonstrates the
[newly-added](https://github.com/torvalds/linux/commit/1507f51255c9)
`memfd_secret` Linux system call, and a kernel module which can dump the
contents of these so-called "secret" memory areas.

# Background
Certain media outlets have [over-hyped the feature](https://lwn.net/Articles/865256/),
claiming that it provides for a secret memory area which is 

> inaccessible to the kernel (and to anybody who might be able to compromise
> the kernel),

While the pages are removed from the kernel direct map (a global 1:1 mapping of
physical memory to virtual memory), it's a bit of a stretch to say that the
memory is completely inaccessible to the kernel — the very thing that
implements the mechanism in question.

The man page is a bit more pragmatic, indicating that `memfd_secret()` mappings
provide

> ...stronger protection than usual RAM-based files and anonymous memory
> mappings.
> The memory areas backing the file created with `memfd_create(2)` are visible
> only to the contexts that have access to the file descriptor These areas are
> removed from the kernel page tables and only the page tables of the processes
> holding the file descriptor map the corresponding physical memory.

David Hildenbrand (a RedHat engineer who
[reviewed](https://lkml.org/lkml/2021/5/14/225) the patchset) correctly
[speculates](https://lwn.net/Articles/865545/):

> I‘d like to note that secretmem does not protect against kernel exploits or
> against root in most setups getting hold of that data. Once you‘re already in
> the kernel, **you might just be able to remap the pages**.

And that is exactly what this project does.

### Disclaimers
Don't use this code on a production machine:
- It delibarately circumvents a kernel security measure!
- It probably has bugs which can crash your machine and/or corrupt your data.

By no means am I discrediting Mike Rapoport or his work — the feature seems to
do exactly what it is intended to do: Provide stronger guarantees about the
protection of the memory. The intent of this project is to ensure that its
limitations are well-understood.

# Usage

### Prerequisites
- You need to be running a v5.14-rc1 or newer kernel.
- You need to boot your kernel with the command-line option `secretmem.enable=1`.
- You need SCons (for the test app), GCC, Make, and kernel headers.

### Build Test App
```
$ cd user/
$ scons
  <or>
$ gcc -Wall -Werror -o testapp testapp.c
```

### Build Kernel Module
```
$ cd kernel/
$ vim Makefile
  <Edit `Makefile` to point `KDIR` at your kernel headers>
$ make
```

### Testing

In one terminal, load the module and watch kernel output:
```
$ sudo insmod kernel/nosecmem.ko
$ sudo dmesg --human --follow
```

In another terminal, run the test app and trigger its inspection:
```
$ user/testapp &
PID: 592
Copied 13 bytes to secret area 0x7f2eab17f000
Waiting...

$ echo $(pidof testapp) > /proc/nosecmem
```

If all goes well you should see this in the `dmesg` output:
```
nosecmem: Write a PID to /proc/nosecmem to see all of the "secret memory" areas for that process.
nosecmem: Inspecting task 592 [testapp]
nosecmem: Found secretmem file size 13 at vma 0x7F2EAB17F000-0x7F2EAB180000
nosecmem:   00000000: 53 65 63 72 65 74 20 64 61 74 61 21 00           Secret data!.
```
