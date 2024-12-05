#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"// Synchronization and Semaphores 

#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/tss.h"
#include <log.h>

#define LOGGING_LEVEL 6

// File structs for stdin, stdout, and stderr
static struct file stdin_file; 
static struct file stdout_file;
static struct file stderr_file;
// Structure to store program name and arguments 
struct args_struct { 
    char *file_name; // Holds the programs file name - executable 
    char *file_args; // Holds the arguments to the program 
};

static thread_func start_process NO_RETURN;
static bool load(char *file_name_ptr, char *file_args, void(**eip) (void), void **esp);
// File descriptor allocation 
int fd_alloc(struct file *file); 

/* Starts a new thread running a user program loaded from
 * FILENAME.  The new thread may be scheduled (and may even exit)
 * before process_execute() returns.  Returns the new process's
 * thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute(const char *cmd) 
{
    log(L_TRACE, "process_execute: Starting with command '%s'", cmd);
    
    char *cmd_copy;  // A copy of the command to avoid race condition
    tid_t tid; // Thread id of the new process 
    struct args_struct args; // Parse the command into filename and args using strtok_r

    log(L_TRACE, "Started process execute: %s", cmd_copy);

    // Allocate memory for cmd_cpy 
    cmd_copy = palloc_get_page(0); 
    if (cmd_copy == NULL) {  // check if memory allocation failed
        log(L_ERROR, "process_execute: Memory allocation failed for cmd_copy"); //TODO : delete when we are finished 
        return TID_ERROR; // Return memory allocation failed 
    }
    
    strlcpy(cmd_copy, cmd, PGSIZE); // Copy the command into cmd copy
    log(L_TRACE, "process_execute: Command copied successfully '%s'", cmd);
    
    // Tokenize the command string into file name and arguments 
    args.file_name = strtok_r(cmd_copy, " ", &args.file_args);

    // Open the executable file 
    struct file *file = filesys_open(args.file_name);
    if(file == NULL) {
        printf("load: %s: open failed\n", args.file_name);
        palloc_free_page(cmd_copy);
        return TID_ERROR;
    }
    // Deny write access to the file 
    file_deny_write(file);
    //save the file reference to the thread 
    struct thread *cur = thread_current();
    cur->exec_file = file; 
    
    
    log(L_TRACE, "process_execute: Parsed file_name='%s', file_args='%s'", args.file_name, args.file_args ? args.file_args : "None");
    // Received help from the ta using threads globally and in regards to semaphores we were using sema_init(&launched, 0) sema_init(&exiting, 0);
    // Create a new thread to execute FILE_NAME for the process
    tid = thread_create(args.file_name, PRI_DEFAULT, start_process, &args);

    if (tid == TID_ERROR) {
        log(L_ERROR, "process_execute: Failed to create thread for command: %s", cmd);// TODO: Delete when we are finished
        file_allow_write(file);
        file_close(file);
        palloc_free_page(cmd_copy); // Free the allocated page if thread creation fails
    }
    // Lookup the thread we just created // Help from the TA regarding sema down and sema wait 
    struct thread *t = get_thread_by_tid(tid); // Get the thread for the child process
    if (t == NULL) { // Check if the thread lookup failed 
        log(L_ERROR, "process_execute: Failed to locate thread for tid=%d", tid);
        palloc_free_page(cmd_copy); // Free the allocated memory 
        return TID_ERROR;
    }
    sema_down(&t->sema_wait); // Wait for the child process to signal it has loaded 

    log(L_TRACE, "process_execute: Child thread %d created by parent %d",
        tid, thread_current()->tid);
    
    // Check if the child successfully loaded its executable 
    if (!t->load_success) {
        // Free cmd_cpy here after the thread is created
        palloc_free_page(cmd_copy);
        return -1; // Return error if loading failed 
    }

    return tid; // Retuns the thread id of the created process
}

/* A thread function that loads a user process and starts it
 * running. */
static void
start_process(void *args_ptr) 
{
    struct args_struct *args = args_ptr; // Cast arguments to args_struct
    struct intr_frame if_; // Interrupt frame for the new process
    bool success;
    struct thread *cur = thread_current(); // Get the current thread

    log(L_TRACE, "start_process()");
     /* Initialize interrupt frame and load executable. */
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    // Load the executable with arguments 
    success = load(args->file_name, args->file_args, &if_.eip, &if_.esp);

    /* If load failed signal the parent and quit. */
    if (!success) {
        log(L_ERROR, "start_process: Failed to load executable for thread %d", cur->tid);
        cur->load_success = false; // Indicates load failure 
        // Help from TA in regards to the process of semaphores 
        sema_up(&cur->sema_wait);// Signal to parent that the loading succeeded
        thread_exit();
    }
    cur->load_success = true; // Help from TA that we need to Mark the process successfully loaded 

    log(L_TRACE, "start_process: Thread %d signaling parent and starting user program", cur->tid);
    
    /* Start the user process by simulating a return from an
     * interrupt, implemented by intr_exit (in
     * threads/intr-stubs.S).  Because intr_exit takes all of its
     * arguments on the stack in the form of a `struct intr_frame',
     * we just point the stack pointer (%esp) to our stack frame
     * and jump to it. */
    asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
    NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait(tid_t child_tid UNUSED)
{
    // Help from the Ta with the following with semaphores and the process of threads with semaphores 

    // Get the current thread and the child thread by TID 
    struct thread *t, *cur;
    t = get_thread_by_tid(child_tid); // Retrieves the thread corresponding to the given tid
    // Handle if thread is not found // TODO: when I add validation syn-write fails
    //if (t == NULL) {
    //    return -1; // Return -2 if the thread is not found 
    //}
    // check if the child process has already been waited on 
    if (t->is_waited_on) {
        return -1; // Process already waited on 
    }
    // Wait for the thread to signal it has exited 
    sema_down(&t->sema_wait); // Wait for the child to finish 
    // Retrieve the exit status of the child thread
    int ret = t->exitStatus; // Store teh childs exit status 
    // Signal the parents acknowledgement of the childs exit 
    sema_up(&t->sema_exit); // Notify the child that the parent is done waiting 
    // Mark the child thread as waiting to prevent race conditions
    t->is_waited_on = true; // Prevents future calls to wait for this thread
    return ret; // Return the childs exit status 
}

/* Free the current process's resources. */
void
process_exit(void)
{   // Completed with the help of the TA explanation of the code with threads and semaphores and init.c 
    struct thread *cur = thread_current(); // Retrieve the current code 
    log(L_TRACE, "process_exit: Thread %d exiting", cur->tid);

    // Notify parent process
    // sema_up(&cur->sema_exit);
    
    uint32_t *pd;

    // Notify parent process - order matters 
    sema_up(&cur->sema_wait); //  Signal to parent that the thread is exiting 
    
    // Wait for the parent to acknowledge the childs termination 
    sema_down(&cur->sema_exit);  // Ensures the parent has finished processing the thread 


    // Allow writes to the executable and close it
    if (cur->exec_file !=NULL) {
        file_allow_write(cur->exec_file); // allow modifications to the file
        file_close(cur->exec_file); // close the file 
        cur->exec_file = NULL; // Clear the reference 
    }
    /* Destroy the current process's page directory and switch back
     * to the kernel-only page directory. */
    pd = cur->pagedir; // Retrieves teh current process page directory 
    if (pd != NULL) {
        /** Correct ordering here is crucial.  
         * We must set cur->pagedir to NULL before switching page directories,
         *      (so that a timer interrupt can't switch back to the process page 
         *        directory. )
         * Activate the base page directory before destroying the process's page
         * directory, or our active page directory will be one
         * that's been freed (and cleared). */
        cur->pagedir = NULL; // NUllify the current threads page directory 
        pagedir_activate(NULL); // Activate the kernel only page directory 
        pagedir_destroy(pd); // Free the memory allocated for the page directory 
    }

    sema_up(&cur->sema_exit); // TODO: per ta exit not launch
    log(L_TRACE, "process_exit: Thread %d cleanup complete", cur->tid);
}

/* Sets up the CPU for running user code in the current
 * thread.
 * This function is called on every context switch. */
void
process_activate(void)
{
    struct thread *t = thread_current();

    /* Activate thread's page tables. */
    pagedir_activate(t->pagedir);

    /* Set thread's kernel stack for use in processing
     * interrupts. */
    tss_update();
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
 * There are e_phnum of these, starting at file offset e_phoff
 * (see [ELF1] 1-6). */
struct Elf32_Phdr {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0          /* Ignore. */
#define PT_LOAD    1          /* Loadable segment. */
#define PT_DYNAMIC 2          /* Dynamic linking info. */
#define PT_INTERP  3          /* Name of dynamic loader. */
#define PT_NOTE    4          /* Auxiliary info. */
#define PT_SHLIB   5          /* Reserved. */
#define PT_PHDR    6          /* Program header table. */
#define PT_STACK   0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(const char *file_name, char *args, void **esp);
static bool validate_segment(const struct Elf32_Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *EIP
 * and its initial stack pointer into *ESP.
 * Returns true if successful, false otherwise. */
bool
load(char *file_name_ptr, char *file_args, void(**eip) (void), void **esp) // changed file_name to cmdstring
{
    log(L_TRACE, "load()");
    struct thread *t = thread_current();
    struct Elf32_Ehdr ehdr;
    struct file *file = NULL;
    off_t file_ofs;
    bool success = false;
    int i;
    char *file_name; // TODO: documentation args.c testcheck to see if I keep this

    //Initialize stdin file struct (fd 0)
    stdin_file.inode = NULL;        //No actual inode
    stdin_file.pos = 0;             //Unused
    stdin_file.deny_write = false;  //Unused

    // Initialize stdout file struct (fd 1)
    stdout_file.inode = NULL;       //No actual inode
    stdout_file.pos = 0;            //Unused
    stdout_file.deny_write = false; //False for stdout

    // Initialize stderr file struct (fd 2)
    stderr_file.inode = NULL;        //No actual inode
    stderr_file.pos = 0;             //Unused
    stderr_file.deny_write = false;  //False for stderr

    //initialize fdtable for created thread
    t->fd_table = palloc_get_page(0);
    if(t->fd_table == NULL){
        printf("Error: Memory allocation for fd_table failed\n");
        thread_exit();
    }
    memset(t->fd_table->entries, 0, sizeof(t->fd_table->entries));
    t->fd_table->entries[0] = &stdin_file;
    t->fd_table->entries[1] = &stdout_file;
    t->fd_table->entries[2] = &stderr_file;
    t->next_fd = 3; //Start after stdin/out/err

    /* Allocate and activate page directory. */
    t->pagedir = pagedir_create();
    if (t->pagedir == NULL) {
        goto done;
    }
    process_activate();

    /* Open executable file. */
    // TODO: tokenize cmdstring and get the first token as filename
    file_name = file_name_ptr;//Need to change later //  TODO : documentation added args.c test is this const char ? need to change later 
    file = filesys_open(file_name); // keeping filename because it is a file we are openings. 
    if (file == NULL) {
        printf("load: %s: open failed\n", file_name);
        goto done;
    }

    /* Read and verify executable header. */
    if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr
        || memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7)
        || ehdr.e_type != 2
        || ehdr.e_machine != 3
        || ehdr.e_version != 1
        || ehdr.e_phentsize != sizeof(struct Elf32_Phdr)
        || ehdr.e_phnum > 1024) {
        printf("load: %s: error loading executable\n", file_name);
        goto done;
    }

    /* Read program headers. */
    file_ofs = ehdr.e_phoff;
    for (i = 0; i < ehdr.e_phnum; i++) {
        struct Elf32_Phdr phdr;

        if (file_ofs < 0 || file_ofs > file_length(file)) {
            goto done;
        }
        file_seek(file, file_ofs);

        if (file_read(file, &phdr, sizeof phdr) != sizeof phdr) {
            goto done;
        }
        file_ofs += sizeof phdr;
        switch (phdr.p_type) {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
            /* Ignore this segment. */
            break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
            goto done;
        case PT_LOAD:
            if (validate_segment(&phdr, file)) {
                bool writable = (phdr.p_flags & PF_W) != 0;
                uint32_t file_page = phdr.p_offset & ~PGMASK;
                uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
                uint32_t page_offset = phdr.p_vaddr & PGMASK;
                uint32_t read_bytes, zero_bytes;
                if (phdr.p_filesz > 0) {
                    /* Normal segment.
                     * Read initial part from disk and zero the rest. */
                    read_bytes = page_offset + phdr.p_filesz;
                    zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE)
                        - read_bytes);
                } else {
                    /* Entirely zero.
                     * Don't read anything from disk. */
                    read_bytes = 0;
                    zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
                }
                if (!load_segment(file, file_page, (void *)mem_page,
                    read_bytes, zero_bytes, writable)) {
                    goto done;
                }
            } else {
                goto done;
            }
            break;
        }
    }

    /* Set up stack. */
    if (!setup_stack(file_name_ptr, file_args, esp)) {
        goto done;
    }
    /* Start address. */
    *eip = (void (*)(void))ehdr.e_entry;
    log(L_TRACE, "load: Executable loaded at entry point %p, stack pointer %p", *eip, *esp);
    success = true;

done:
    /* We arrive here whether the load is successful or not. */
    file_close(file);
    return success;
}

/* load() helpers. */

static bool install_page(void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment(const struct Elf32_Phdr *phdr, struct file *file)
{
    /* p_offset and p_vaddr must have the same page offset. */
    if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) {
        return false;
    }

    /* p_offset must point within FILE. */
    if (phdr->p_offset > (Elf32_Off)file_length(file)) {
        return false;
    }

    /* p_memsz must be at least as big as p_filesz. */
    if (phdr->p_memsz < phdr->p_filesz) {
        return false;
    }

    /* The segment must not be empty. */
    if (phdr->p_memsz == 0) {
        return false;
    }

    /* The virtual memory region must both start and end within the
     * user address space range. */
    if (!is_user_vaddr((void *)phdr->p_vaddr)) {
        return false;
    }
    if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz))) {
        return false;
    }

    /* The region cannot "wrap around" across the kernel virtual
     * address space. */
    if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr) {
        return false;
    }

    /* Disallow mapping page 0.
     * Not only is it a bad idea to map page 0, but if we allowed
     * it then user code that passed a null pointer to system calls
     * could quite likely panic the kernel by way of null pointer
     * assertions in memcpy(), etc. */
    if (phdr->p_vaddr < PGSIZE) {
        return false;
    }

    /* It's okay. */
    return true;
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 *      - READ_BYTES bytes at UPAGE must be read from FILE
 *        starting at offset OFS.
 *
 *      - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
    uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(ofs % PGSIZE == 0);

    log(L_TRACE, "load_segment()");

    file_seek(file, ofs);
    while (read_bytes > 0 || zero_bytes > 0) {
        /* Calculate how to fill this page.
         * We will read PAGE_READ_BYTES bytes from FILE
         * and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* Get a page of memory. */
        uint8_t *kpage = palloc_get_page(PAL_USER);
        if (kpage == NULL) {
            return false;
        }

        /* Load this page. */
        if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
            palloc_free_page(kpage);
            return false;
        }
        memset(kpage + page_read_bytes, 0, page_zero_bytes);

        /* Add the page to the process's address space. */
        if (!install_page(upage, kpage, writable)) {
            palloc_free_page(kpage);
            return false;
        }

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
    }
    return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
 * user virtual memory. 
 * add a char cmdstring if a command string update the protype char *cmd
 * go to setup called, it is called in load file name. change it to char *cmdstring 
 * make note to self tokenize cmdstring and get the first token as file name
 * when we open a file we are not going to open the whole string
 */
static bool
setup_stack(const char *file_name, char *args, void **esp)
{
    uint8_t *kpage; // Kernel page for the stack 
    bool success = false;
    char *argv[128]; //Array of argument to store pointers 
    int argc; // Argument count 
    const char *arg; // Current argument 
    int i;
    size_t len;

    log(L_TRACE, "setup_stack()");    
    
    kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    // Allocate a zeroed page for the stack 
    if (kpage != NULL) {
        success = install_page(((uint8_t *)PHYS_BASE) - PGSIZE, kpage, true);
        if (success) {
            log(L_TRACE, "setup_stack: argc=%d, argv[0]=%p, argv[1]=%p", argc, argv[0], argc > 1 ? argv[1] : NULL);
            *esp = PHYS_BASE; // Set the stack pointer to the top of user memory 
            //hex_dump((uintptr_t)*esp, *esp, PHYS_BASE - *esp, true);
            argc = 0; // Set the argument count to zero. 
            arg = file_name; // Start with file name 
            // printf("From setup_stack, filename is %s; args are %s\n", file_name, args);
            i = 0;
            // Push each argument onto the stack 
            while (arg != NULL){
                len = strlen(arg) + 1;  //  Includes null terminator 
                argv[i] = arg;          
                *esp -= len;            // Move the stack pointer 
                memcpy(*esp, arg, len); // Copy the argument to the stack
                argv[i] = *esp;         
                i++;                    // Note to self we can add argv[argc++] = *esp 
                argc++;
                arg = strtok_r(NULL, " ", &args); // TODO: Need to add if statement for validation 
            }
            argv[i] = NULL;
            // printf("argc = %d\n", argc); // TODO: Delete for clean up
            
            // Push arguments onto the stack in reverse order
            for(i = argc - 1; i >= 0; i--){
                *esp -= strlen(argv[i]) + 1; // Move the stack pointer down
                memcpy(*esp, argv[i], strlen(argv[i]) + 1); // Copy argument to the stack
                argv[i] = *esp; // Save the address of the argument
            }
            // Word- align the stack (align to 4 byte boundary)
            while((uintptr_t)*esp % 4 != 0){
                *esp -= 1;
                *(uint8_t *)*esp = 0;
            }

            // Push the addresses of argv
            *esp -= sizeof(char *);
            *(char **)*esp = NULL;

            for(i = argc - 1; i >= 0; i--){
                *esp -= sizeof(char *);
                *(char **)*esp = argv[i];//push each arguments address
            }

            // Push argv the address argv[]
            char **argv_ptr = *esp;
            *esp -= sizeof(char **);
            *(char ***)*esp = argv_ptr;

            // push argc
            *esp -= sizeof(char **);
            *(int *)*esp = argc;

            // push a fake return address
            *esp -= sizeof(void *);
            *(void **)*esp = 0;

            // palloc_free_page(cmd_copy); // TODO: Delete Clean up

        } else {
            palloc_free_page(kpage);
        }

        // Debug stack contents
        //hex_dump(*(int *)esp, *esp, PHYS_BASE - *esp, true);
    }

    return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page(void *upage, void *kpage, bool writable)
{
    struct thread *t = thread_current();

    /* Verify that there's not already a page at that virtual
     * address, then map our page there. */
    return pagedir_get_page(t->pagedir, upage) == NULL
           && pagedir_set_page(t->pagedir, upage, kpage, writable);
}

/*Assigns next available file descriptor to passed file*/
int fd_alloc(struct file *file) {
    struct thread *t = thread_current();
    if(t->fd_table == NULL){
        thread_exit();
    }
    // file_length(file);
    // printf("fd_alloc: file length shows as %lld\n", (long long)file_length(file));
    for (int i = 3; i < MAX_OPEN_FILES; i++) {  //Start after 0, 1, 2 (stdin, stdout, stderr)
        if (t->fd_table->entries[i] == NULL) {
            t->fd_table->entries[i] = file;
            t->next_fd = i + 1; //Start after stdin/out/err
            return i;//Return the file descriptor number
        }
    }

    return -1;//No available file descriptor
}

// struct thread *get_thread_by_tid(tid_t tid)
// {
//     struct list_elem * e; 
//     // iterate through the global all list to find the thread with matching tid
//     for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e)){
//         struct  thread *t = list_entry(e, struct thread, allelem);
//         if (t->tid == tid) {
//             return t; 
//         }
//     }
//     return NULL; // Return null if no thread matches 

// }


