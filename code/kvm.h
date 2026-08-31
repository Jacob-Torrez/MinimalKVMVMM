#ifndef KVM_H
#define KVM_H

#include <sys/ioctl.h>
#include <linux/kvm.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdint.h>
#include <asm/bootparam.h>
#include <string.h>
#include <stdlib.h>
#include <sys/select.h>
#include <errno.h>
#include <sys/time.h>
#include <signal.h>

struct vm {
    int sys_fd;
    int fd;
    void* mem;
    long long mem_size;
};

struct vcpu {
    int fd;
    int run_size;
    struct kvm_run* run;
};

int vm_init(struct vm* vm, size_t mem_size);
int vcpu_init(struct vm* vm, struct vcpu* vcpu);
int vm_run(struct vm* vm, struct vcpu* vcpu);
int cpuid_init(struct vm* vm, struct vcpu* vcpu);
int load_bzimage(struct vm* vm, const char* filename);
int setup_regs(struct vcpu* vcpu);

#endif