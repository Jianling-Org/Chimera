# ==============================================================================
# vlen-escape: fully self-contained Docker image
#
#   docker build -t vlen-escape vlen-escape/
#   docker run --rm vlen-escape                 # 打印 llama.cpp 检测报告
#   docker run --rm -it vlen-escape bash        # 交互排查
#
# 镜像内完成：LLVM21+Z3 构建 svf-vlenesc → 克隆 llama.cpp → RVV 交叉编译拦截
# → vlen 逃逸分析 → /opt/vlen-escape/out/report.md
# ==============================================================================
# 注：docker.1ms.run 是 Docker Hub 镜像源（本机直连 registry-1.docker.io 超时）；
# 网络可达 Docker Hub 时可改回 ubuntu:22.04
FROM docker.1ms.run/library/ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# 基础工具 + riscv64 交叉 sysroot + Z3
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates wget gnupg cmake make python3 git \
        gcc-riscv64-linux-gnu g++-riscv64-linux-gnu \
        libz3-dev z3 \
    && rm -rf /var/lib/apt/lists/*

# LLVM/Clang 21（apt.llvm.org）：RVV bitcode 发射 + SVF 构建共用一套
# （手写 repo 源，避免 llvm.sh 对 lsb_release 的依赖）
RUN wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor -o /usr/share/keyrings/llvm-snapshot.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/llvm-snapshot.gpg] http://apt.llvm.org/jammy/ llvm-toolchain-jammy-21 main" \
       > /etc/apt/sources.list.d/llvm21.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends clang-21 llvm-21 llvm-21-dev libclang-rt-21-dev \
    && rm -rf /var/lib/apt/lists/*

# Z3 布局适配 SVF FindZ3（需要 <root>/include/z3++.h + <root>/lib 下的 libz3）
RUN mkdir -p /opt/z3/include /opt/z3/lib \
    && ln -s /usr/include/z3*.h /opt/z3/include/ \
    && ln -s /usr/lib/x86_64-linux-gnu/libz3.so* /opt/z3/lib/

# 统一工具链布局：脚本期望 $DIR/bin/clang、$DIR/lib/libLLVM*；Z3 期望 include/z3++.h + lib
ENV RVV_LLVM_DIR=/usr/lib/llvm-21 \
    LLVM21_DIR=/usr/lib/llvm-21 \
    Z3_DIR=/opt/z3
ENV PATH=/usr/lib/llvm-21/bin:$PATH \
    LD_LIBRARY_PATH=/usr/lib/llvm-21/lib

# ---- 构建分析器（自包含源码：src/ + svf_src/） --------------------------------
WORKDIR /opt/vlen-escape
COPY . .
RUN bash build.sh

# ---- 获取 llama.cpp 并做 RVV 拦截编译（收集 bitcode） --------------------------
RUN git clone --depth 1 https://github.com/ggml-org/llama.cpp /opt/llamacpp
RUN bash scripts/intercept_build.sh /opt/llamacpp -- \
        cmake -B build-docker \
              -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=riscv64 \
              -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY -DBUILD_SHARED_LIBS=OFF \
              -DGGML_NATIVE=OFF -DGGML_RVV=ON \
              -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF \
              -DLLAMA_BUILD_TOOLS=OFF -DLLAMA_BUILD_SERVER=OFF \
    ; bash scripts/intercept_build.sh /opt/llamacpp -- \
        cmake --build build-docker --target ggml-cpu -- -k -j"$(nproc)" \
    ; true   # 部分 TU 真实 .o 编译失败（旧式 vsetivli）属预期，bitcode 已收集

# ---- 逃逸分析 + 报告 ----------------------------------------------------------
# 个别模块分析失败不阻断镜像构建（日志在 out/logs/，报告含实际覆盖范围）
RUN bash run.sh /opt/llamacpp --skip-build || \
    echo "WARNING: analysis had failing modules, see /opt/vlen-escape/out/logs/"

CMD ["bash", "-c", "cat /opt/vlen-escape/out/report.md; echo; echo '--- escapes.jsonl ---'; cat /opt/vlen-escape/out/escapes.jsonl"]
