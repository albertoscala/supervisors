SRC = src/
INCLUDE = include/
BIN = bin/

MODULE_DIR = module/
LOADER_DIR = loader/

create_kernel_type_definition: 
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(MODULE_DIR)$(INCLUDE)vmlinux.h

compile_module: create_kernel_type_definition
	clang -g -O2 -target bpf -c $(MODULE_DIR)$(SRC)module.bpf.c -o $(MODULE_DIR)$(BIN)module.bpf.o

# generate skeleton
generate_skeleton: compile_module
	bpftool gen skeleton $(MODULE_DIR)$(BIN)module.bpf.o > $(LOADER_DIR)$(INCLUDE)module.skel.h

# create final program loader linked with blob of the bpf 
build: generate_skeleton
	clang -O2 $(LOADER_DIR)$(SRC)loader.c -lbpf -lelf -lz -o $(LOADER_DIR)$(BIN)loader

run:
	sudo ./$(LOADER_DIR)$(BIN)loader