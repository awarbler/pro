#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/syscall.h"

// TODO: Documentation Added for shutdown for sys_halt
#include "devices/shutdown.h"
// TODO: document added for Input device, used for syst_read input_getc 
#include "devices/input.h"
// TODO: document Virtual address checking 
#include "threads/vaddr.h"
// TODO: adocument Page directory access 
#include "userprog/pagedir.h"
// For using filesys commands (e.g., filesys_open)
#include <filesys/filesys.h>
#include <filesys/file.h>
// For using functions created for fdtable implementation
#include <userprog/process.h>

static void syscall_handler(struct intr_frame *);
void sys_halt(void);
void sys_exit(int status);
bool sys_create(const char *file_name, off_t initial_size);
int sys_open(const char *file_name) ;
int sys_filesize(int fd);
int sys_write(int fd, const void *buffer, unsigned size);
int sys_read(int fd, void *buffer, unsigned size);
void sys_seek(int fd, unsigned position);
bool sys_remove (const char *file_name);
tid_t sys_exec (const char *cmd_line);
int sys_wait(tid_t tid);
static int get_user (const uint8_t *uaddr); // TODO: Read user memory safely
static bool put_user (uint8_t *udst, uint8_t byte); // TODO: Wriet user memory safely
static void validate_user_pointer(const void *ptr) ;

//  TODO: confirm we want to do the following 
// function to extract system call arguments from the stack 
// static int fetch_arguement(void *esp, int arg_index);

void 
syscall_init(void) 
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// System call handler for processing all syscall requests 
static void 
syscall_handler(struct intr_frame *f UNUSED) 
{
    /* Remove these when implementing syscalls */
    int * usp = f->esp;
    // TODO document Validate user pointer to avoid accessing invalid memory 
    validate_user_pointer(usp); // Validate the stack pointer

    //printf("Callno = %d\n" , *usp);
    int callno = *usp;
    
    switch (callno) {
        case SYS_HALT: 
        sys_halt();
        break;
        case SYS_EXIT:
            if (!is_user_vaddr(usp + 1) || get_user((uint8_t *)usp + 1) == -1) {
                sys_exit(-1); // Invalid argument
            }
            sys_exit(*(usp + 1));
            break;
        case SYS_EXEC:
            //f->eax = sys_exec((const char *)*(usp + 1));
            break;
        case SYS_WAIT:
            //f->eax = sys_wait(*(usp + 1));
            break;
        case SYS_CREATE:
            f->eax = sys_create((const char *)*(usp + 1), *(usp + 2));
            break;
        case SYS_REMOVE:
            {
                const char *file_name = (const char *) *(usp + 1);
                // call sys_remove and store the result in eax
                f->eax = sys_remove(file_name);
            }
            //f->eax = sys_remove((const char *)*(usp + 1));
            break;
        case SYS_OPEN:
            {
                const char *file_name = (const char *)*(usp+1);

                f->eax = sys_open(file_name);
            }
            //f->eax = sys_open((const char *)*(usp + 1));
            break;
        case SYS_FILESIZE:
            f->eax = sys_filesize(*(usp + 1));
            break;
        case SYS_READ:
            f->eax = sys_read(*(usp + 1), (void *)*(usp + 2), *(usp + 3));
            break;
        case SYS_WRITE:
            f->eax = sys_write(*(usp + 1), (const void *)*(usp + 2), *(usp + 3));
            break;
        case SYS_SEEK:
            if (!is_user_vaddr(usp + 1) || !is_user_vaddr(usp + 2)) {
                sys_exit(-1); // Invalid memory access
            }
            sys_seek(*(usp + 1), *(usp + 2));
            break;
        case SYS_TELL:      /* Report current position in a file. */
                break;
        case SYS_CLOSE:     /* Close a file. */
                break;
        default:
            // handle unknow system calls 
            // not sure if I want to do thins 
            sys_exit(-1);
            break;
    }
}
/* 
Terminates Pintos by calling shutdown_power_off() (declared 
in “threads/init.h”). This should be seldom used, because you 
lose some information about possible deadlock situations, etc.
*/
void sys_halt(void) {
    shutdown_power_off();
}
/**Opens the file called file. Returns a nonnegative integer handle called 
 * a "file descriptor" (fd), or -1 if the file could not be opened. File 
 * descriptors numbered 0 and 1 are reserved for the console: fd 0 (STDIN_FILENO) 
 * is standard input, fd 1 (STDOUT_FILENO) is standard output. The open system 
 * call will never return either of these file descriptors, which are valid as 
 * system call arguments only as explicitly described below. Each process has
 * an independent set of file descriptors. File descriptors are not inherited 
 * by child processes.When a single file is opened more than once, whether by 
 * a single process or different processes, each open returns a new file d
 * escriptor. Different file descriptors for a single file are closed independently
 * in separate calls to close and they do not share a file position.*/
int sys_open(const char *file_name) {

    if(pagedir_get_page(thread_current()->pagedir, file_name) == NULL)
    {
        sys_exit(-1);//Exit status if pointer is invalid ===validate arguments
    }
    validate_user_pointer(file_name); // Ensure file_name is a valid user pointer

    if(strcmp(file_name, "") == 0){
        return -1;
    }    
    struct file *file = filesys_open(file_name);
    if(file == NULL) {
        return -1;
    }
    file_length(file);
    // printf("sys_open: file length shows as %lld\n", (long long)file_length(file));
    // printf("file size is: %lld\n", (long long)file->inode->data.length);
    int fd = fd_alloc(file);
    if(fd == -1){
        file_close(file);
        return -1;
    }
    // printf("sys_open: returning fd %d\n", fd);
    return fd;

}
/* 
Terminates the current user program, returning status to 
the kernel. If the process's parent waits for it (see below), 
this is the status that will be returned. Conventionally, 
a status of 0 indicates success and nonzero values indicate 
errors.
*/
void sys_exit(int status){
    struct thread *cur = thread_current();// Get the current thread 
    cur->exitStatus = status;// Set the exit status for the current process

    printf("%s: exit(%d)\n", cur->name, status); // LOG progress of exit status 
    // where do we get args-none m where do we find the name every process has to have a name 
    thread_exit(); // Terminate the thread 
    //process_exit();
}
/*Creates a new file called file initially initial_size bytes in size. 
Returns true if successful, false otherwise. Creating a new file does not open it:
opening the new file is a separate operation which would require a open system call.*/
bool sys_create(const char *file_name, off_t initial_size){
    validate_user_pointer(file_name); // Ensure file_name is a valid user pointer
    if(filesys_create(file_name, initial_size) == 1){
        return true;
    }
    else{
        return false;
    }
}
/*Returns the size, in bytes, of the file open as fd.*/
int sys_filesize(int fd){
    //Get current thread/process
    struct thread *t = thread_current();
    
    //Validate file descriptor range
    if (fd < 3 || fd >= t->next_fd) {
        return -1;  //Invliad file descriptor
        printf("Error: invalid fd\n");
    }

    //Get file struct from the fdtable using fd
    struct file *file = t->fd_table->entries[fd];
    if (file == NULL) {
        return -1;  //File descriptor not associated with an open file
    }
    return (int)file_length(file);
}
/*  Writes size bytes from buffer to the open file fd. Returns 
    the number of bytes actually written, which may be less than
    size if some bytes could not be written. 
    
    Writing past end-of-file would normally extend the file, but 
    file growth is not implemented by the basic file system. The 
    expected behavior is to write as many bytes as possible up to 
    end-of-file and return the actual number written, or 0 if no bytes 
    could be written at all. 
    
    Fd 1 writes to the console. Your code to write 
    to the console should write all of buffer in one call to putbuf(), 
    at least as long as size is not bigger than a few hundred bytes. 
    (It is reasonable to break up larger buffers.) Otherwise, 
    lines of text output by different processes may end up 
    interleaved on the console, confusing both human readers and 
    our grading scripts.
*/
int sys_write(int fd, const void *buffer, unsigned size) {
    // Validate buffer address range within user address space 
    validate_user_pointer(buffer); // Validate base pointer
    validate_user_pointer(buffer + size - 1); // Validate end of buffer

    // stdout == fd ==1 fd 1 wries to buffer 
    if (fd == 1) { // Writing to console (stdout)

        putbuf((const char *)buffer, size); // output buffer content to console 
        return size; // Return number of bytes written ---not sure if I want to do this confirm 
    }

    //Get the current thread/process
    struct thread *t = thread_current();

    //Validate file descriptor range
    //if (fd < 2 || fd >= t->next_fd || t->fd_table == NULL){
    //    sys_exit(-1);  //Invalid file descriptor
    //}
    if (fd < 3 || fd >= t->next_fd || t->fd_table == NULL){
        sys_exit(-1);  //Invalid file descriptor
    }

    struct file *file = t->fd_table->entries[fd];

    // Retrieve file struct from the fdtable using fd
    if (file == NULL) {
        return -1;  //File descriptor not associated with an open file
    }

    int bytes_written = file_write(file, buffer, (off_t) size);
    if(bytes_written == -1){//error handling
        return -1;
    }

    return bytes_written;
}
// Reads size bytes from the file open as fd into buffer. 
// Returns the number of bytes actually read (0 at end of file), 
// or -1 if the file could not be read (due to a condition other
// than end of file). Fd 0 reads from the keyboard using input_getc().
int sys_read(int fd, void *buffer, unsigned size) {
    validate_user_pointer(buffer); // Validate base pointer
    validate_user_pointer(buffer + size - 1); // Validate end of buffer

    if (fd == 0) {
        unsigned i;
        for (i = 0; i < size; i++) {
            if (!put_user(((uint8_t *)buffer) + i, input_getc())) {
                sys_exit(-1);
            }
        }
            return size;
    } 
    
     //Get the current thread/process
    struct thread *t = thread_current();

    // printf("FD is %d\n", fd);
    // Validate file descriptor range
    if (fd < 3 || fd >= t->next_fd) {
        return -1;  //Invalid file descriptor
        //printf("Error: invalid fd\n");
    }

    //Get file struct from the fdtable using fd
    struct file *file = t->fd_table->entries[fd];
    if (file == NULL) {
        return -1;  //File descriptor not associated with an open file
    }
    file_length(file);
    // printf("sys_read(): file length shows as %lld\n", (long long)file_length(file));

    //int bytes_read = file_read(file, buffer, size);
    //if(bytes_read == -1){
    //    return -1;
    //}
//
    //return bytes_read;
    return file_read(file, buffer, size);
    

}
tid_t sys_exec (const char *cmd_line) {
    validate_user_pointer(cmd_line); // Ensure cmd_line is a valid user pointer

    // copy cmd_line to kernel space
    char *cmd_copy = palloc_get_page(0);
    if (cmd_copy == NULL) {
        return -1;
    }

    strlcpy(cmd_copy, cmd_line, PGSIZE);

    // Call process_execute 
    tid_t tid = process_execute(cmd_line);

    // free cmd_copy after process_execute 
    palloc_free_page(cmd_copy);

    if (tid == TID_ERROR) {
        return -1;
    }
    return tid;
}
int sys_wait(tid_t tid) {
    return process_wait(tid);
}
/* bool remove (const char *file) Deletes the file called file. 
Returns true if successful, false otherwise. A file may be removed 
regardless of whether it is open or closed, and removing an open 
file does not close it. See Removing an Open File, for details.*/
bool sys_remove (const char *file_name) {
    validate_user_pointer(file_name); // Ensure file_name is a valid user pointer
    return filesys_remove(file_name);
}
void sys_seek(int fd, unsigned position) {
        struct thread *t = thread_current();

    // Validate file descriptor range
    if (fd < 3 || fd >= t->next_fd || t->fd_table == NULL) {
        sys_exit(-1);  // Invalid file descriptor
    }

    // Retrieve the file struct from the fd_table
    struct file *file = t->fd_table->entries[fd];
    if (file == NULL) {
        sys_exit(-1);  // File descriptor not associated with an open file
    }

    // Seek to the specified position
    file_seek(file, position);
}
/* Reads a byte at user virtual address UADDR. UADDR must be below PHYS_BASE. Returns the byte value if successful, -1 if a segfault occurred. */
static int
get_user (const uint8_t *uaddr)
{
    if (!is_user_vaddr(uaddr)) {
        return -1; // Invalid virtual address.
    }
    int result;
    asm ("movl $1f, %0; movzbl %1, %0; 1:": "=&a" (result) : "m" (*uaddr));
    return result;
}

/* Writes BYTE to user address UDST. UDST must be below PHYS_BASE. Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
    int error_code;
    asm ("movl $1f, %0; movb %b2, %1; 1:": "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
}
static void validate_user_pointer(const void *ptr) {
    if (!is_user_vaddr(ptr) || pagedir_get_page(thread_current()->pagedir, ptr) == NULL) {
        sys_exit(-1); // Invalid pointer, terminate process
    }
}
