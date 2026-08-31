#include "kvm.h"
#include "console.h"

int main(){
    struct vm vm;
    struct vcpu vcpu;

    if (vm_init(&vm, 1024 * 1024 * 256) == -1){
        return -1;
    }

    if (vcpu_init(&vm, &vcpu) == -1){
        return -1;
    }

    if (load_bzimage(&vm, "bzImage") == -1){
        return -1;
    }
    
    if (setup_regs(&vcpu) == -1){
        return -1;
    }

    if (cpuid_init(&vm, &vcpu) == -1){
        return -1;
    }

    signal(SIGINT, handle_sigint);
    atexit(disable_raw_mode);

    printf("Starting guest console. Press Ctrl-A then X to exit.\r\n");
    fflush(stdout);

    enable_raw_mode();

    if (vm_run(&vm, &vcpu) == -1){
        return -1;
    }

    disable_raw_mode();

    close(vcpu.fd);
    close(vm.fd);
    close(vm.sys_fd);

    if (munmap(vcpu.run, vcpu.run_size) == -1){
        perror("KVM RUN MUNMAP FAILED");
    }
    if (munmap(vm.mem, vm.mem_size) == -1){
        perror("VM MEM MUNMAP FAILED");
    }

    return 0;
}