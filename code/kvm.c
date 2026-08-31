#include "kvm.h"
#include "console.h"

static const char* BZMAGIC = "HdrS";

#define UART_BASE 0x3F8
#define UART_RBR (UART_BASE + 0) /* Receiver Buffer Register (read)                     */
#define UART_THR (UART_BASE + 0) /* Trasmitter Holding Register (write)                 */
#define UART_IER (UART_BASE + 1) /* Interrupt Enable Register                           */
#define UART_IIR (UART_BASE + 2) /* Interrupt Identification Register (read)            */
#define UART_LCR (UART_BASE + 3) /* Line Control Register                               */
#define UART_MCR (UART_BASE + 4) /* Modem Control Register                              */
#define UART_LSR (UART_BASE + 5) /* Line Status Register (read)                         */
#define UART_MSR (UART_BASE + 6) /* Modem Status Register (read)                        */
#define UART_SCR (UART_BASE + 7) /* Sratch Register                                     */

#define UART_IER_RDI 0x01        /* Enable received-data-available interrupt            */
#define UART_IER_THRI 0x02       /* Enable transmitter-holding-register-empty interrupt */

#define UART_IIR_NO_INT 0x01
#define UART_IIR_THRI 0x02       /* Transmitter holding register empty                  */
#define UART_IIR_RDI 0x04        /* Received data available                             */

#define UART_LSR_DR 0x01         /* Data ready                                          */
#define UART_LSR_THRE 0x20       /* Transmitter holding register empty                  */
#define UART_LSR_TEMT 0x40       /* Transmitter empty                                   */

#define UART_MSR_CTS 0x10
#define UART_MSR_DSR 0x20
#define UART_MSR_DCD 0x80

#define SERIAL_IRQ 4

int vm_init(struct vm* vm, size_t mem_size){
    vm->sys_fd = open("/dev/kvm", O_RDWR);
    if (vm->sys_fd == -1){
        printf("Failed to open /dev/kvm\n");
        return -1;
    }


    vm->fd = ioctl(vm->sys_fd, KVM_CREATE_VM, 0);
    if (vm->fd == -1){
        perror("KVM CREATE VM");
        return -1;
    }

    if (ioctl(vm->fd, KVM_CREATE_IRQCHIP, 0) == -1){
        perror("KVM CREATE IRQCHIP");
        return -1;
    }

    struct kvm_pit_config pit_config = { .flags = 0 };
    if (ioctl(vm->fd, KVM_CREATE_PIT2, &pit_config) == -1){
        perror("KVM CREATE PIT2");
        return -1;
    }

    vm->mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (vm->mem == MAP_FAILED){
        printf("VM memory map failed\n");
        return -1;
    }
    vm->mem_size = mem_size;

    struct kvm_userspace_memory_region memreg;
    memreg.slot = 0;
    memreg.flags = 0;
    memreg.guest_phys_addr = 0;
    memreg.memory_size = mem_size;
    memreg.userspace_addr = (uint64_t)vm->mem;
    if (ioctl(vm->fd, KVM_SET_USER_MEMORY_REGION, &memreg) == -1){
        perror("KVM SET USER MEMORY REGION");
        return -1;
    }

    if (ioctl(vm->fd, KVM_SET_TSS_ADDR, 0xffffd000) == -1){
        perror("KVM SET TSS ADDR");
        return -1;
    }

    return 0;
}

int vcpu_init(struct vm* vm, struct vcpu* vcpu){
    vcpu->fd = ioctl(vm->fd, KVM_CREATE_VCPU, 0);
    if (vcpu->fd == -1){
        perror("KVM CREATE VCPU");
        return -1;
    }


    vcpu->run_size = ioctl(vm->sys_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    vcpu->run = mmap(NULL, vcpu->run_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu->fd, 0);
    if (vcpu->run == MAP_FAILED){
        printf("VCPU run map failed\n");
        return -1;
    }

    return 0;
}

int cpuid_init(struct vm* vm, struct vcpu* vcpu){
    struct kvm_cpuid2* cpuid;

    cpuid = calloc(1, sizeof(*cpuid) + 100  * sizeof(*cpuid->entries));
    if (cpuid == NULL){
        perror("CPUID calloc");
        return -1;
    }
    
    cpuid->nent = 100;

    if (ioctl(vm->sys_fd, KVM_GET_SUPPORTED_CPUID, cpuid) == -1){
        perror("KVM GET SUPPORTED CPUID");
        return -1;
    }

    if (ioctl(vcpu->fd, KVM_SET_CPUID2, cpuid) == -1){
        perror("KVM SET CPUID2");
        return -1;
    }

    free(cpuid);
    return 0;
}

static void dump_regs(struct vcpu* vcpu){
    struct kvm_regs regs;

    ioctl(vcpu->fd, KVM_GET_REGS, &regs);

    printf("finished at rip=0x%llx rsp=0x%llx rax=0x%llx rbx=0x%llx rcx=0x%llx rdx=0x%llx rsi=0x%llx rdi=0x%llx\n",
        regs.rip, regs.rsp, regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.rsi, regs.rdi);
}

static void sigalrm_handler(int sig) {
    (void)sig; /* no-op: interrupt blocked KVM_RUN */
}

static int stdin_has_data(void){
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    struct timeval tv = {0, 0};
    return select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) > 0;
}

static void raise_irq4(struct vm* vm){
    struct kvm_irq_level irq_level = { .irq = SERIAL_IRQ, .level = 1 };
    ioctl(vm->fd, KVM_IRQ_LINE, &irq_level);
    irq_level.level = 0;
    ioctl(vm->fd, KVM_IRQ_LINE, &irq_level);
}

#define ESCAPE_KEY 0x01 /* CTRL-A */

/* Reads one byte from stdin for the guest, intercepting the CTRL-A x escape
sequence so the user always has a way out. */
static char read_console_byte(void){
    static int escape_pending = 0;

    for (;;) {
        char c = 0;
        ssize_t n;
        do {
            n = read(STDIN_FILENO, &c, 1);
        } while (n == -1 && errno == EINTR);
        if (n <= 0) return 0;

        if (escape_pending) {
            escape_pending = 0;
            if (c == 'x' || c == 'X') {
                disable_raw_mode();
                printf("\r\n[detached from guest]\r\n");
                exit(0);
            }
            return c;
        }

        if (c == ESCAPE_KEY) {
            escape_pending = 1;
            continue;
        }

        return c;
    }
}

int vm_run(struct vm* vm, struct vcpu* vcpu){
    uint8_t ier, lcr, mcr, scratch;
    ier = lcr = mcr = scratch = 0;

    /* KVM_RUN blocks inside the kernel while the vCPU is halted and waiting 
    for an interrupt. A periodic SIGALRM (delivered w/o SA_RESTART) kicks it
    back out with EINTR so we can poll stdin and, if a byte is waiting and
    the guest has RX interrupts enabled, inject IRQ4 to wake the vCPU back
    up. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigalrm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* no SA_RESTART */
    sigaction(SIGALRM, &sa, NULL);

    struct itimerval timer = {
        .it_value = { .tv_sec = 0, .tv_usec = 10000 },
        .it_interval = { .tv_sec = 0, .tv_usec = 10000 },
    };
    setitimer(ITIMER_REAL, &timer, NULL);

    for(;;){
        if (stdin_has_data() && (ier & UART_IER_RDI)) {
            raise_irq4(vm);
        }

        if (ioctl(vcpu->fd, KVM_RUN, 0) == -1){
            if (errno == EINTR) continue;
            perror("KVM RUN");
            return -1;
        }

        switch (vcpu->run->exit_reason){
            case KVM_EXIT_HLT: {
                continue;
            }

            case KVM_EXIT_IO: {
                uint16_t port = vcpu->run->io.port;
                int is_out = (vcpu->run->io.direction == KVM_EXIT_IO_OUT);    
                uint8_t* data = (uint8_t*)vcpu->run + vcpu->run->io.data_offset;

                if (port == UART_THR && is_out) {
                    fwrite(data, vcpu->run->io.size, 1, stdout);
                    fflush(stdout);
                    if (ier & UART_IER_THRI) {
                        raise_irq4(vm);
                    }
                    continue;
                } 
                else if (port == UART_RBR && !is_out){
                    *data = read_console_byte();
                    continue;
                }
                else if (port == UART_IER) {
                    if (is_out){
                        uint8_t new_ier = *data;
                        /* THR is always empty in this emulation, so enabling
                        THRI needs an immediate kick to get the guest driver
                        started. */
                        if ((new_ier & UART_IER_THRI) && !(ier & UART_IER_THRI)){
                            raise_irq4(vm);
                        }
                        ier = new_ier;
                    } else {
                        *data = ier;
                    }
                    continue;
                }
                else if (port == UART_IIR && !is_out) {
                    uint8_t iir;
                    if (stdin_has_data() && (ier & UART_IER_RDI)){
                        iir = UART_IIR_RDI;
                    }
                    else if (ier & UART_IER_THRI) {
                        iir = UART_IIR_THRI;
                    } else {
                        iir = UART_IIR_NO_INT;
                    }
                    *data = iir;
                    continue;
                }
                else if (port == UART_LCR) {
                    if (is_out) {
                        lcr = *data;
                    } else {
                        *data = lcr;
                    }
                    continue;
                }
                else if (port == UART_MCR){
                    if (is_out) {
                        mcr = *data;
                    } else {
                        *data = mcr;
                    }
                    continue;
                }
                else if (port == UART_LSR && !is_out){
                    uint8_t lsr = UART_LSR_THRE | UART_LSR_TEMT;
                    if (stdin_has_data()){
                        lsr |= UART_LSR_DR;
                    }
                    *data = lsr;
                    continue;
                }
                else if (port == UART_MSR && !is_out){
                    /* Carrier permanently present so userspace opens don't
                    block waiting for DCD. */
                    *data = UART_MSR_DCD | UART_MSR_DSR | UART_MSR_CTS;
                }
                else if (port == UART_SCR){
                    if (is_out){
                        scratch = *data;
                    } else {
                        *data = scratch;
                    }
                    continue;
                }

                /* Unhandled port */
                continue;
            }

            case KVM_EXIT_SHUTDOWN:
                fprintf(stderr, "guest triple-faulted (KVM_EXIT_SHUTDOWN)\n");
                dump_regs(vcpu);
                return -1;

            case KVM_EXIT_FAIL_ENTRY:
                fprintf(stderr, "KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason=0x%llx\n",
                    vcpu->run->fail_entry.hardware_entry_failure_reason);
                dump_regs(vcpu);
                return -1;

            case KVM_EXIT_INTERNAL_ERROR:
                fprintf(stderr, "KVM_EXIT_INTERNAL_ERROR: suberror=0x%x\n",
                    vcpu->run->internal.suberror);
                dump_regs(vcpu);
                return -1;

            case KVM_EXIT_MMIO:
                fprintf(stderr, "unexpected KVM_EXIT_MMIO at phys_addr=0x%llx (is write=%d, len=%u)\n",
                    vcpu->run->mmio.phys_addr, vcpu->run->mmio.is_write, vcpu->run->mmio.len);
                dump_regs(vcpu);
                return -1;
            
            default:
                fprintf(stderr, "unhandled exit_reason=%u\n", vcpu->run->exit_reason);
                dump_regs(vcpu);
                return -1;
        }
    }
}

static int load_initramfs(struct vm* vm, size_t* out_size){
    FILE* initramfs = fopen("initramfs.cpio.gz", "rb");
    if (initramfs == NULL){
        printf("failed to open initramfs\n");
        return -1;
    }

    if (fseek(initramfs, 0, SEEK_END)){
        printf("seek end 0 fail\n");
        fclose(initramfs);
        return -1;
    }

    long initramfs_size = ftell(initramfs);

    if (fseek(initramfs, 0, SEEK_SET)){
        printf("seek set 0 fail\n");
        fclose(initramfs);
        return -1;
    }

    if (fread((char*)vm->mem + 0x4000000, 1, initramfs_size, initramfs) != initramfs_size){
        printf("failed to load initramfs\n");
        fclose(initramfs);
        return -1;
    }

    fclose(initramfs);
    *out_size = (size_t)initramfs_size;
    return 0;
}

/* Loads the bzimage into guest memory AND sets up the boot_params struct */
int load_bzimage(struct vm* vm, const char* filename){
    FILE* bzimage = fopen(filename, "rb");
    if (bzimage == NULL){
        printf("failed to open %s\n", filename);
        return -1;
    }

    struct boot_params boot;

    if (fread(&boot, 1, sizeof(boot), bzimage) != sizeof(boot)){
        printf("failed to read setup header\n");
        fclose(bzimage);
        return -1;
    }

    if (memcmp(&boot.hdr.header, BZMAGIC, strlen(BZMAGIC))){
        printf("setup header missing magic\n");
        fclose(bzimage);
        return -1;
    }

    if (fseek(bzimage, 0, SEEK_END)){
        printf("seek end 0 fail\n");
        fclose(bzimage);
        return -1;
    }

    long bzimage_size = ftell(bzimage);

    if (fseek(bzimage, 0, SEEK_SET)){
        printf("seek set 0 fail\n");
        fclose(bzimage);
        return -1;
    }

    int setup_sects = boot.hdr.setup_sects;

    if (setup_sects == 0){
        setup_sects = 4;
    }

    /* Loads real-mode code at 0x90000 in guest memory */
    if (fread((char*)vm->mem + 0x90000, 1, (setup_sects + 1) * 512, bzimage) != (setup_sects + 1) * 512){
        printf("failed to load real-mode code\n");
        fclose(bzimage);
        return -1;
    }

    /* Loads the protected-mode code at 0x100000 in guest memory */
    if (fread((char*)vm->mem + 0x100000, 1, bzimage_size - (setup_sects + 1) * 512, bzimage) != bzimage_size - (setup_sects + 1) * 512){
        printf("failed to load protected mode code\n");
        fclose(bzimage);
        return -1;
    }

    boot.hdr.vid_mode = 0;

    boot.hdr.type_of_loader = 0xFF;

    /* QUIET_FLAG == 0, CAN_USE_HEAP == 1 */
    boot.hdr.loadflags = ((boot.hdr.loadflags & ~0x20) | 0x80);

    size_t initramfs_size;
    if (load_initramfs(vm, &initramfs_size) == -1){
        printf("failed to load initramfs\n");
        fclose(bzimage);
        return -1;
    }

    boot.hdr.ramdisk_image = 0x4000000;
    boot.hdr.ramdisk_size = initramfs_size;

    /* 0x9800 as suggested by boot.txt */
    boot.hdr.heap_end_ptr = 0x9800 - 0x200;

    boot.hdr.cmd_line_ptr = 0x90000 + 0x9800;
    strcpy((char*)vm->mem + 0x90000 + 0x9800, "console=ttyS0,115200 earlyprintk=ttyS0 ignore_loglevel loglevel=8 nokaslr");

    boot.hdr.hardware_subarch = 0;

    boot.e820_table[0].addr = 0;
    boot.e820_table[0].size = 0x09FC00;
    boot.e820_table[0].type = 1; // E820_RAM

    boot.e820_table[1].addr = 0x09FC00;
    boot.e820_table[1].size = 0x100000 - 0x09FC00;
    boot.e820_table[1].type = 2; // E820_RESERVED

    boot.e820_table[2].addr = 0x100000;
    boot.e820_table[2].size = vm->mem_size - 0x100000;
    boot.e820_table[2].type = 1;

    boot.e820_entries = 3;

    /* Load boot_params at 0x10000 in guest memory */
    memcpy((char*)vm->mem + 0x10000, &boot, sizeof(struct boot_params));

    fclose(bzimage);

    return 0;
}

int setup_regs(struct vcpu* vcpu){
    struct kvm_regs regs;
    struct kvm_sregs sregs;

    if (ioctl(vcpu->fd, KVM_GET_REGS, &regs) == -1){
        perror("KVM GET REGS");
        return -1;
    }
    if (ioctl(vcpu->fd, KVM_GET_SREGS, &sregs) == -1){
        perror("KVM GET SREGS");
        return -1;
    }

    regs.rflags = 0x2;
    regs.rip = 0x100000; // 32-bit kernel entry point
    regs.rsi = 0x10000; // boot_params

    sregs.cs.base = 0; sregs.cs.limit = 0xffffffff; sregs.cs.g = 1;
    sregs.ds.base = 0; sregs.ds.limit = 0xffffffff; sregs.ds.g = 1;
    sregs.es.base = 0; sregs.es.limit = 0xffffffff; sregs.es.g = 1;
    sregs.fs.base = 0; sregs.fs.limit = 0xffffffff; sregs.fs.g = 1;
    sregs.gs.base = 0; sregs.gs.limit = 0xffffffff; sregs.gs.g = 1;
    sregs.ss.base = 0; sregs.ss.limit = 0xffffffff; sregs.ss.g = 1;

    sregs.cs.db = 1;
    sregs.ss.db = 1;
    sregs.cr0 |= 0x1;  // enable protected mode

    if (ioctl(vcpu->fd, KVM_SET_REGS, &regs) == -1){
        perror("KVM SET REGS");
        return -1;
    }
    if (ioctl(vcpu->fd, KVM_SET_SREGS, &sregs) == -1){
        perror("KVM SET SREGS");
        return -1;
    }

    return 0;
}