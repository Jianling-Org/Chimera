# 自动迁移 BPF 触发器

`sched_migrate_trigger.bpf.c` 挂接 `sched:sched_migrate_task`，调用内核的 Chimera kfunc。触发器与应用注册使用同一个 `uprobe_info_map`；需要单独编译并加载触发器，才能建立该路径。

## 编译

在目标板上，从本目录执行。先读取运行内核的 BTF，生成头文件，再编译 BPF 对象：

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpf -D__TARGET_ARCH_riscv -I . \
    -c sched_migrate_trigger.bpf.c -o sched_migrate_trigger.bpf.o
```

当前内核 BTF 使用 `struct chimera_migration_target_info` 表示 176 字节的 map 值，布局为 `inode + offsets[20] + offset_cnt + is_attached`。源码应使用该类型名；旧名 `struct uprobe_info` 不匹配当前 BTF。生成的 `vmlinux.h` 和 `.o` 保留在构建目录。

## 加载与注册

加载需要 BPF 权限。内核在重启前保留首次登记的 `uprobe_info_map`；重新加载触发器时复用同一个已 pin 的 map 对象：

```sh
bpftool prog load sched_migrate_trigger.bpf.o \
    /sys/fs/bpf/chimera_trigger autoattach \
    map name uprobe_info_map pinned /sys/fs/bpf/pid_uprobe_map
```

加载后，在目标机设置已安装 Workspace 和应用路径，验证环境并注册应用：

```sh
WORKSPACE=/absolute/path/to/installed/workspace
ELF=/absolute/path/to/application
chimera-user verify --workspace "$WORKSPACE"
chimera-user register --workspace "$WORKSPACE" --input "$ELF"
```

核对触发器使用的内核 BTF、注册路径和 map 对象一致。启动与迁移请求见[在目标机运行应用](../../../docs/user/README.md)。
