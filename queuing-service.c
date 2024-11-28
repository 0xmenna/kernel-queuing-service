/*
 *
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 3 of the License, or (at your option) any later
 * version.
 *
 * This module is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 */

#define EXPORT_SYMTAB
#include <asm/apic.h>
#include <asm/cacheflush.h>
#include <asm/io.h>
#include <asm/page.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/time.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include "lib/include/scth.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Emanuele Valzano <emanuele.valzano@proton.me>");
MODULE_DESCRIPTION("basic blocking FIFO queuing service");

#define MODNAME "QUEUINGSERVICE"

#define AUDIT if (1)

unsigned long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0660);

unsigned long the_ni_syscall;

unsigned long new_sys_call_array[] = {0x0, 0x0};
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array) / sizeof(unsigned long))
int restore[HACKED_ENTRIES] = {[0 ...(HACKED_ENTRIES - 1)] - 1};

static DEFINE_SPINLOCK(queue_spinlock);
static LIST_HEAD(the_threads_queue);

unsigned long queue_count;
module_param(queue_count, ulong, 0660);

typedef struct _thread_in_queue {
   struct task_struct *task;
   int pid;
   bool awake;
   struct list_head queue;
} thread_in_queue;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(1, _goto_sleep, int, unused) {
#else
asmlinkage long sys_goto_sleep(int unused) {
#endif

   thread_in_queue data;
   thread_in_queue *queue_elem;
   // here we use a private queue - wakeup is selective via wake_up_process
   DECLARE_WAIT_QUEUE_HEAD(the_queue);

   queue_elem = &data;

   AUDIT
   printk("%s: thread %d is going to sleep until an awake is called and the "
          "thread is at the head of a FIFO queue\n",
          MODNAME, current->pid);

   queue_elem->task = current;
   queue_elem->pid = current->pid;
   queue_elem->awake = false;

   // disable preemption because we want to avoid the release of the cpu while
   // doing accessing a critical section
   preempt_disable();
   // access the critical section to add the current thread to the tail of
   // the queue
   spin_lock(&queue_spinlock);
   // Add `queue_elem` to the queue
   list_add_tail(&queue_elem->queue, &the_threads_queue);
   queue_count++;

   AUDIT
   printk("%s: thread %d has been added to the FIFO queue\n", MODNAME,
          current->pid);

   // Release spinlock
   spin_unlock(&queue_spinlock);
   // Enable preemption
   preempt_enable();
   wait_event_interruptible(the_queue, queue_elem->awake);

   AUDIT
   printk("%s: thread %d exiting sleep\n", MODNAME, current->pid);

   if (!queue_elem->awake) {
      // awaken by a signal
      AUDIT
      printk("%s: thread %d awaken by a signal\n", MODNAME, current->pid);

      preempt_disable();
      spin_lock(&queue_spinlock);
      list_del(&queue_elem->queue);
      queue_count--;
      spin_unlock(&queue_spinlock);
      preempt_enable();

      return -1;
   }

   return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(1, _awake, int, unused) {
#else
asmlinkage long sys_awake(int unused) {
#endif

   // thread in the queue to awake
   thread_in_queue *queue_elem;
   // the task on which to call `wake_up_process`
   struct task_struct *the_task;

   preempt_disable();

   spin_lock(&queue_spinlock);

   if (list_empty(&the_threads_queue)) {
      AUDIT
      printk("%s: there is no thread to awake\n", MODNAME);

      spin_unlock(&queue_spinlock);
      preempt_enable();

      return -1;
   }

   // Get the first element in the queue
   queue_elem = list_first_entry(&the_threads_queue, thread_in_queue, queue);
   // Remove the element from the queue
   list_del(&queue_elem->queue);
   queue_count--;

   AUDIT printk("%s: tread %d is about to be awaken by thread %d", MODNAME,
                queue_elem->pid, current->pid);

   queue_elem->awake = true;
   the_task = queue_elem->task;
   wake_up_process(the_task);

   spin_unlock(&queue_spinlock);
   preempt_enable();

   return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
long sys_goto_sleep = (unsigned long)__x64_sys_goto_sleep;
long sys_awake = (unsigned long)__x64_sys_awake;
#else
#endif

int init_module(void) {
   int i;
   int ret;

   if (the_syscall_table == 0x0) {
      printk("%s: cannot manage sys_call_table address set to 0x0\n", MODNAME);
      return -1;
   }

   AUDIT {
      printk("%s: initializing - hacked entries %d\n", MODNAME, HACKED_ENTRIES);
   }

   new_sys_call_array[0] = (unsigned long)sys_goto_sleep;
   new_sys_call_array[1] = (unsigned long)sys_awake;

   ret = get_entries(restore, HACKED_ENTRIES,
                     (unsigned long *)the_syscall_table, &the_ni_syscall);

   if (ret != HACKED_ENTRIES) {
      printk("%s: could not hack %d entries (just %d)\n", MODNAME,
             HACKED_ENTRIES, ret);
      return -1;
   }

   unprotect_memory();

   for (i = 0; i < HACKED_ENTRIES; i++) {
      ((unsigned long *)the_syscall_table)[restore[i]] =
          (unsigned long)new_sys_call_array[i];
   }

   protect_memory();

   printk("%s: all new system-calls correctly installed on sys-call table\n",
          MODNAME);

   return 0;
}

void cleanup_module(void) {
   int i;

   printk("%s: shutting down\n", MODNAME);

   unprotect_memory();
   for (i = 0; i < HACKED_ENTRIES; i++) {
      ((unsigned long *)the_syscall_table)[restore[i]] = the_ni_syscall;
   }
   protect_memory();
   printk("%s: sys-call table restored to its original content\n", MODNAME);
}
