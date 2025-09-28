# Define KERN_DIR for your current running kernel
KERN_DIR="/lib/modules/$(uname -r)/build"

# Verify KERN_DIR exists and contains headers
if [ ! -d "$KERN_DIR" ]; then
    echo "Error: Kernel build directory $KERN_DIR does not exist."
    echo "Please ensure 'linux-headers-$(uname -r)' (Ubuntu/Debian) or 'kernel-devel-$(uname -r)' (Fedora/RHEL) is fully installed."
    exit 1
fi

# Compile with verbose include paths
clang -O2 -target bpf -g \
-I$KERN_DIR/include/uapi \
-I$KERN_DIR/include/generated/uapi \
-I$KERN_DIR/include \
-I$KERN_DIR/arch/x86/include \
-I$KERN_DIR/arch/x86/include/generated \
-D DROP_PORT=8000 \
-c drop_tcp_port.c -o drop_tcp_port.o

#Load the xdp code 
sudo ip -force link set dev lo xdp obj drop_tcp_port.o sec xdp

#Verify the program is loaded 
ip link show dev lo
