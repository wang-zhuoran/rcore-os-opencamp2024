# CH4: rcore 进程管理

## 1. 用于进程管理的内核数据结构
本章节我们将task抽象成了process进程这样一个更高级的数据结构。 这样一来```TaskControlBlock```就会有许多变化 (这里的```TaskControlBlock```实际上就是Process Control Block, PCB)：



```rust
/// Task control block structure
///
/// Directly save the contents that will not change during running
pub struct TaskControlBlock {
    // Immutable
    /// Process identifier
    pub pid: PidHandle,

    /// Kernel stack corresponding to PID
    pub kernel_stack: KernelStack,

    /// Mutable
    inner: UPSafeCell<TaskControlBlockInner>,
}

pub struct TaskControlBlockInner {
    /// The physical page number of the frame where the trap context is placed
    pub trap_cx_ppn: PhysPageNum,

    /// Application data can only appear in areas
    /// where the application address space is lower than base_size
    pub base_size: usize,

    /// Save task context
    pub task_cx: TaskContext,

    /// Maintain the execution status of the current process
    pub task_status: TaskStatus,

    /// Application address space
    pub memory_set: MemorySet,

    /// Parent process of the current process.
    /// Weak will not affect the reference count of the parent
    pub parent: Option<Weak<TaskControlBlock>>,

    /// A vector containing TCBs of all child processes of the current process
    pub children: Vec<Arc<TaskControlBlock>>,

    /// It is set when active exit or execution error occurs
    pub exit_code: i32,

    /// Heap bottom
    pub heap_bottom: usize,

    /// Program break
    pub program_brk: usize,
}

```

我们发现TCB的成员变量分成了可变的inner和不可变的pid，内核栈两块。（内核栈在系统调用过程中类似于“内核态的函数调用栈”，用于存储该进程在内核态执行时的调用信息、返回地址、局部变量和状态等。每个进程有自己独立的内核栈，因此可以安全地保存该进程的内核态信息而不受其他进程影响。）

而之前的```TaskControlBlock```是这样：
```rust
/// The task control block (TCB) of a task.
pub struct TaskControlBlock {
    /// Save task context
    pub task_cx: TaskContext,

    /// Maintain the execution status of the current process
    pub task_status: TaskStatus,

    /// Application address space
    pub memory_set: MemorySet,

    /// The phys page number of trap context
    pub trap_cx_ppn: PhysPageNum,

    /// The size(top addr) of program which is loaded from elf file
    pub base_size: usize,

    /// Heap bottom
    pub heap_bottom: usize,

    /// Program break
    pub program_brk: usize,

    /// the task info
    pub task_info: TaskInfo,
}
```

其中PID：
```rust
/// Abstract structure of PID
pub struct PidHandle(pub usize);
```
kernel stack, 一个内核态下的内核空间虚拟地址
```rust
/// Kernel stack for a process(task)
pub struct KernelStack(pub usize);
```

另外我们注意到，相比于原来的TCB，这里的TCB新增了parent和children两个成员变量，用于表示父进程和子进程的相关信息：
```rust
    /// Parent process of the current process.
    /// Weak will not affect the reference count of the parent
    pub parent: Option<Weak<TaskControlBlock>>,

    /// A vector containing TCBs of all child processes of the current process
    pub children: Vec<Arc<TaskControlBlock>>,
```
这里使用Arc和Weak主要是考虑到多线程环境和防止循环引用的问题。Arc<T> 用于在多线程环境中共享数据，通过引用计数来管理对象的生命周期。

在所有对 Arc<T> 的引用计数降到0时，数据会被自动释放。与 Arc 不同，Weak<T> 不会增加对象的引用计数。它可以安全地引用数据而不会影响生命周期，如果数据已被释放，Weak 引用会自动变为 None。

注意引用计数是计算一个对象被引用的数量，也就是有多少个指针指向这个对象。因此一个父进程无论有多少个子进程，其引用计数并不会增加。当父进程被释放时，其子进程的 Weak 指针会自动变为 None，避免悬空指针的风险。

如果父进程创建了子进程并持有 Arc 引用，同时子进程在其他地方也被引用（例如添加到系统的进程表或队列中），那么子进程的引用计数就可能超过 1。
当父进程释放时，只是减少了一个引用，子进程依然有效，且引用计数仍然高于零。

TCB提供了```new()```方法，使得我们可以通过byte slice（字节切片，elf格式）创建一个新的进程控制块：
```rust
    /// Create a new process
    ///
    /// At present, it is only used for the creation of initproc
    pub fn new(elf_data: &[u8]) -> Self {
        // memory_set with elf program headers/trampoline/trap context/user stack
        let (memory_set, user_sp, entry_point) = MemorySet::from_elf(elf_data);
        let trap_cx_ppn = memory_set
            .translate(VirtAddr::from(TRAP_CONTEXT_BASE).into())
            .unwrap()
            .ppn();
        // alloc a pid and a kernel stack in kernel space
        let pid_handle = pid_alloc();
        let kernel_stack = kstack_alloc();
        let kernel_stack_top = kernel_stack.get_top();
        // push a task context which goes to trap_return to the top of kernel stack
        let task_control_block = Self {
            pid: pid_handle,
            kernel_stack,
            inner: unsafe {
                UPSafeCell::new(TaskControlBlockInner {
                    trap_cx_ppn,
                    base_size: user_sp,
                    task_cx: TaskContext::goto_trap_return(kernel_stack_top),
                    task_status: TaskStatus::Ready,
                    memory_set,
                    parent: None,
                    children: Vec::new(),
                    exit_code: 0,
                    heap_bottom: user_sp,
                    program_brk: user_sp,
                })
            },
        };
        // prepare TrapContext in user space
        let trap_cx = task_control_block.inner_exclusive_access().get_trap_cx();
        *trap_cx = TrapContext::app_init_context(
            entry_point,
            user_sp,
            KERNEL_SPACE.exclusive_access().token(),
            kernel_stack_top,
            trap_handler as usize,
        );
        task_control_block
    }
```
首先通过elf文件和```from_elf()```函数创建应用地址空间（```memory_set```）

然后找到trap 上下文所在的位置```trap_cx_ppn```

接下来为新应用（进程）分配pid和内核栈，并且找到栈顶的位置

```task_cx: TaskContext::goto_trap_return(kernel_stack_top)```设置一个初始上下文（TaskContext），以便在发生 trap（陷阱或异常）时，将栈指针（stack pointer，SP）指向内核栈的栈顶（kernel_stack_top）。这样做是为了确保在陷阱发生时，能够从内核栈的正确位置开始处理，并保证数据不会与用户态栈混淆。

最后利用```TrapContext::app_init_context()```函数设置用户态的trap上下文，这包含了用户进程的入口地址```entry_point```，即程序开始执行的指令位置（本质上是一个pc的初始值），
用户栈顶地址（用户态的栈指针）```user_sp```，用于设置用户进程栈的初始位置, trap处理函数的入口位置等等。

TCB通过```new()```函数创建, 目前使用new()函数的只有在创建初始进程的时候：
```rust
lazy_static! {
    /// Creation of initial process
    ///
    /// the name "initproc" may be changed to any other app name like "usertests",
    /// but we have user_shell, so we don't need to change it.
    pub static ref INITPROC: Arc<TaskControlBlock> = Arc::new(TaskControlBlock::new(
        get_app_data_by_name("ch5b_initproc").unwrap()
    ));
}

```
ch5b_initproc：
```rust
fn main() -> i32 {
    if fork() == 0 {
        exec("ch5b_user_shell\0", &[0 as *const u8]);
    } else {
        loop {
            let mut exit_code: i32 = 0;
            let pid = wait(&mut exit_code);
            if pid == -1 {
                yield_();
                continue;
            }
            println!(
                "[initproc] Released a zombie process, pid={}, exit_code={}",
                pid, exit_code,
            );
        }
    }
    0
}
```
这是rcore运行的第一个进程，其作用是创建一个子进程，子进程会执行exec，利用shell进程替换父进程的地址空间、寄存器文件等信息。
而父进程会等待子进程返回一个大于0的pid（子进程进程号）并将已经成为僵尸进程的子进程的相关资源回收；如果在等待时间片用尽依旧没有等到子进程返回的pid，
则主动放弃cpu资源继续等待（继续执行子进程）



## 2. ```fork()```系统调用的实现
```rust
pub fn sys_fork() -> isize {
    trace!("kernel:pid[{}] sys_fork", current_task().unwrap().pid.0);
    let current_task = current_task().unwrap();
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}
```

```rust
impl TaskControlBlock {
    /// parent process fork the child process
    pub fn fork(self: &Arc<Self>) -> Arc<Self> {
        // ---- access parent PCB exclusively
        let mut parent_inner = self.inner_exclusive_access();
        // copy user space(include trap context)
        let memory_set = MemorySet::from_existed_user(&parent_inner.memory_set);
        let trap_cx_ppn = memory_set
            .translate(VirtAddr::from(TRAP_CONTEXT_BASE).into())
            .unwrap()
            .ppn();
        // alloc a pid and a kernel stack in kernel space
        let pid_handle = pid_alloc();
        let kernel_stack = kstack_alloc();
        let kernel_stack_top = kernel_stack.get_top();
        let task_control_block = Arc::new(TaskControlBlock {
            pid: pid_handle,
            kernel_stack,
            inner: unsafe {
                UPSafeCell::new(TaskControlBlockInner {
                    trap_cx_ppn,
                    base_size: parent_inner.base_size,
                    task_cx: TaskContext::goto_trap_return(kernel_stack_top),
                    task_status: TaskStatus::Ready,
                    memory_set,
                    parent: Some(Arc::downgrade(self)),
                    children: Vec::new(),
                    exit_code: 0,
                    heap_bottom: parent_inner.heap_bottom,
                    program_brk: parent_inner.program_brk,
                })
            },
        });
        // add child
        parent_inner.children.push(task_control_block.clone());
        // modify kernel_sp in trap_cx
        // **** access child PCB exclusively
        let trap_cx = task_control_block.inner_exclusive_access().get_trap_cx();
        trap_cx.kernel_sp = kernel_stack_top;
        // return
        task_control_block
        // **** release child PCB
        // ---- release parent PCB
    }
}
```

## 3. ```exec()```系统调用的实现
```rust
pub fn sys_exec(path: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_exec", current_task().unwrap().pid.0);
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(data) = get_app_data_by_name(path.as_str()) {
        let task = current_task().unwrap();
        task.exec(data);
        0
    } else {
        -1
    }
}
```

```rust
impl TaskControlBlock {
    /// Load a new elf to replace the original application address space and start execution
    pub fn exec(&self, elf_data: &[u8]) {
        // memory_set with elf program headers/trampoline/trap context/user stack
        let (memory_set, user_sp, entry_point) = MemorySet::from_elf(elf_data);
        let trap_cx_ppn = memory_set
            .translate(VirtAddr::from(TRAP_CONTEXT_BASE).into())
            .unwrap()
            .ppn();

        // **** access current TCB exclusively
        let mut inner = self.inner_exclusive_access();
        // substitute memory_set
        inner.memory_set = memory_set;
        // update trap_cx ppn
        inner.trap_cx_ppn = trap_cx_ppn;
        // initialize base_size
        inner.base_size = user_sp;
        // initialize trap_cx
        let trap_cx = inner.get_trap_cx();
        *trap_cx = TrapContext::app_init_context(
            entry_point,
            user_sp,
            KERNEL_SPACE.exclusive_access().token(),
            self.kernel_stack.get_top(),
            trap_handler as usize,
        );
        // **** release inner automatically
    }
}
```



## 4. 进程调度


## 5. Lab5 实现

### (1) ```spawn()```系统调用


### (2) stride调度算法


