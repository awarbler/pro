#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);

bool sys_remove (const char *file_name);
int sys_filesize(int fd);
tid_t sys_exec (const char *cmd_line);
int sys_wait(tid_t tid);
#endif /* userprog/syscall.h */
