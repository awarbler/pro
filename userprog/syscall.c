#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"      // Virtual address checking 

#include <userprog/process.h>   // For using functions created for fdtable implementation
#include "userprog/syscall.h"
#include "userprog/pagedir.h"   // Page directory access 

#include <filesys/filesys.h>    // For using filesys commands (e.g., filesys_open)
#include <filesys/file.h>

#include "devices/shutdown.h"   // Shutdown for sys_halt
#include "devices/input.h"      // Input device, used for syst_read input_getc 

// Declarations of system call handling functions.
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

// Helper functions for user memory validation and safe access 
static int get_user (const uint8_t *uaddr); // Safely Read from user memory 
static bool put_user (uint8_t *udst, uint8_t byte); // Safely Write to user memory 
static void validate_user_pointer(const void *ptr); // Ensures the pointer is valid for user memory 


// Initialize system call handler and registering as an interrupt 
void 
syscall_init(void) 
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); // software interrupt of 0x30 system calls 
}

// System call handler for processing all syscall requests based on syscall number 
static void 
syscall_handler(struct intr_frame *f UNUSED) 
{
    // Validate user pointer to avoid accessing invalid memory and ensures it is within the suer address space
    validate_user_pointer(f->esp); 

    int * usp = f->esp;  // Extracts teh user stack pointer from the interrupt frame
    
        // Validate user pointer to avoid accessing invalid memory and ensures it is within the suer address space
    validate_user_pointer(usp);

    // Get the system call number from the stack 
    int callno = *usp;
    // dispatch the appropriate system call handler based on the call number 
    switch (callno) {
        case SYS_HALT: 
        sys_halt(); // System shutdown
        break;
        case SYS_EXIT:
            // Validate the argument / pointer 
            if (!is_user_vaddr(usp + 1) || get_user((uint8_t *)usp + 1) == -1) {
                sys_exit(-1); // Exit with error if validation fails 
            }
            sys_exit(*(usp + 1)); // Exit with provide status 
            break;
        case SYS_EXEC:
            {
                const char *cmd_line = (const char *) *(usp + 1); // Extract the command line argument 
                //Validate the pointer 
                if (!is_user_vaddr(cmd_line) || get_user((uint8_t *)cmd_line) == -1) {
                sys_exit(-1); // Exit with error if validation fails 
                }
                f->eax = sys_exec(cmd_line); // Validation passed call sys exec
            }
            break;
        case SYS_WAIT:
            f->eax = sys_wait(*(usp + 1)); // Wait for a process to finish and return its status 
            break;
        case SYS_CREATE:
            f->eax = sys_create((const char *)*(usp + 1), *(usp + 2)); // Create a new file
            break;
        case SYS_REMOVE:
            {
                const char *file_name = (const char *) *(usp + 1); // Extract the file name 
                f->eax = sys_remove(file_name); // Remove the file and store the results in EAX
            }
            break;
        case SYS_OPEN:
            {
                const char *file_name = (const char *)*(usp+1);// Extract the file name 
                f->eax = sys_open(file_name); //  Open the file and return its file descriptor 
            }
            //f->eax = sys_open((const char *)*(usp + 1));
            break;
        case SYS_FILESIZE:
            f->eax = sys_filesize(*(usp + 1)); // Retrieve the size of an open file 
            break;
        case SYS_READ:
            f->eax = sys_read(*(usp + 1), (void *)*(usp + 2), *(usp + 3)); // Read data from a file
            break;
        case SYS_WRITE:
            f->eax = sys_write(*(usp + 1), (const void *)*(usp + 2), *(usp + 3)); // Write data to a file 
            break;
        case SYS_SEEK:
            if (!is_user_vaddr(usp + 1) || !is_user_vaddr(usp + 2)) {
                sys_exit(-1); // Exit with error if validation fails - Invalid memory access
            }
            sys_seek(*(usp + 1), *(usp + 2)); // Seek a position in a file 
            break;
        case SYS_TELL:      /* Report current position in a file. */
                break;
        case SYS_CLOSE:     /* Close a file. */
                break;
        default:
            sys_exit(-1);
            break;
    }
}
/* 
Terminates Pintos by calling shutdown_power_off() (declared in“threads/init.h”)
This should be seldom used, because you lose some information about possible 
deadlock situations, etc.
*/
void sys_halt(void) {
    shutdown_power_off();
}
/* 
Terminates the current user program, returning status to the kernel. If the 
process's parent waits for it (see below), this is the status that will be 
returned. Conventionally, a status of 0 indicates success and nonzero values 
indicate errors.
*/
void 
sys_exit(int status){
    struct thread *cur = thread_current();// Get the current thread 
    cur->exitStatus = status;// Set the exit status for the current process
    printf("%s: exit(%d)\n", cur->name, status); // LOG progress of exit status 
    thread_exit(); // Terminate the thread
}

tid_t sys_exec (const char *cmd_line) {
    validate_user_pointer(cmd_line); // Ensure cmd_line is a valid user pointer
    // copy cmd_line to kernel space
    char *cmd_copy = palloc_get_page(0);
    if (cmd_copy == NULL) {
        return -1;
    }
    //Copy the command line to the kernel 
    strlcpy(cmd_copy, cmd_line, PGSIZE);
    // Call process_execute  with the copied command line
    tid_t tid = process_execute(cmd_line);
    // free cmd_copy after process_execute 
    palloc_free_page(cmd_copy);
    // Returns -1 if execute process failed 
    //if (tid == TID_ERROR) {
    //    sys_exit(-1);
    //}
    if (tid == TID_ERROR) {
        return -1;
    }
    return tid; // Returns the new process id 
}
int sys_wait(tid_t tid) {
    int status = process_wait(tid);
    return status;
}
/* Creates a new file called file initially initial_size bytes in size. 
Returns true if successful, false otherwise. Creating a new file does not open it:
opening the new file is a separate operation which would require a open system call.*/
bool sys_create(const char *file_name, off_t initial_size){
    validate_user_pointer(file_name); // Ensure file_name is a valid user pointer
    // Create a file and return success or failure
    if(filesys_create(file_name, initial_size) == 1){
        return true;
    }
    else{
        return false;
    }
}
/* bool remove (const char *file) Deletes the file called file. 
Returns true if successful, false otherwise. A file may be removed 
regardless of whether it is open or closed, and removing an open 
file does not close it. See Removing an Open File, for details.*/
bool sys_remove (const char *file_name) {
    validate_user_pointer(file_name); // Ensure file_name is a valid user pointer
    return filesys_remove(file_name);
}
/**Opens the file called file. Returns a nonnegative integer handle called 
 * a "file descriptor" (fd), or -1 if the file could not be opened. File 
 * descriptors numbered 0 and 1 are reserved for the console: fd 0 (STDIN_FILENO) 
 * is standard input, fd 1 (STDOUT_FILENO) is standard output. The open system 
 * call will never return either of these file descriptors, which are valid as 
 * system call arguments only as explicitly described below. Each process has
 * an independent set of file descriptors. File descriptors are not inherited 
 * by child processes.When a single file is opened more than once, whether by 
 * a single process or different processes, each open returns a new file descriptor. 
 * Different file descriptors for a single file are closed independently
 * in separate calls to close and they do not share a file position.*/
int 
sys_open(const char *file_name) {
    if(pagedir_get_page(thread_current()->pagedir, file_name) == NULL)
    {
        sys_exit(-1); //Exit status if pointer is invalid ===validate arguments
    }
    validate_user_pointer(file_name); // Ensure file_name is a valid user pointer
    
    if(strcmp(file_name, "") == 0){ // If file name is an empty string
        return -1;
    }
    // Calls filesys open and returns a pointer 
    struct file *file = filesys_open(file_name);
    // Return an error if the file couldn't be opened 
    if(file == NULL) { // If file cannot be open or doesn't exist
        return -1; // Indicates failure 
    }
    
    file_length(file); // Debugging 
    int fd = fd_alloc(file); // calls fd alloc assign a unique fd to open file 
    if(fd == -1){ //  if fd alloc fails 
        file_close(file); // close file if fd allocation fails
        return -1; // indicates failure 
    }
    return fd;
}
/*Returns the size, in bytes, of the file open as fd.*/
int sys_filesize(int fd){
    struct thread *t = thread_current(); //Get current thread/process
    //Validate file descriptor range
    if (fd < 3 || fd >= t->next_fd) {
        return -1;  //Invalid file descriptor
        printf("Error: invalid fd\n");
    }
    struct file *file = t->fd_table->entries[fd]; // Get the file from the fdtable
     //File descriptor not associated with an open file
    if (file == NULL) {
        return -1; 
    }
    return (int)file_length(file); // Returns the file size or error 
}
// Reads size bytes from the file open as fd into buffer. Returns the number of 
// bytes actually read (0 at end of file), or -1 if the file could not be read
// (due to a condition other than end of file). Fd 0 reads from the keyboard 
// using input_getc().
int sys_read(int fd, void *buffer, unsigned size) {
    validate_user_pointer(buffer); // Validate base pointer
    validate_user_pointer(buffer + size - 1); // Validate end of buffer
    if (fd == 0) { // If reading from stdin
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
    int bytes_read = file_read(file, buffer, size);
    if(bytes_read == -1){
        return -1;
    }
    return bytes_read;
}
/*  
Writes size bytes from buffer to the open file fd. Returns the number of bytes
actually written, which may be less thansize if some bytes could not be written. 

Writing past end-of-file would normally extend the file, but file growth is not 
implemented by the basic file system. The expected behavior is to write as many 
bytes as possible up to end-of-file and return the actual number written, or 0 
if no bytes could be written at all. 
    
Fd 1 writes to the console. Your code to write to the console should write all 
of buffer in one call to putbuf(), at least as long as size is not bigger than 
a few hundred bytes. (It is reasonable to break up larger buffers.) Otherwise, 
lines of text output by different processes may end up interleaved on the console, 
confusing both human readers and our grading scripts.
*/
int sys_write(int fd, const void *buffer, unsigned size) {
    // Validate buffer address range within user address space 
    validate_user_pointer(buffer); // Validate base pointer
    validate_user_pointer(buffer + size - 1); // Validate end of buffer
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
