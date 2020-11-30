#ifndef RTL8139_IOCTL_H
#define RTL8139_IOCTL_H

#include <linux/ioctl.h>

#define RX_BUF_LEN_SHIFT 2
#define RX_BUF_LEN (8192 << RX_BUF_LEN_SHIFT)
#define RX_BUF_PAD 16
#define RX_BUF_WRAP_PAD 2048
#define RX_BUF_TOT_LEN (RX_BUF_LEN + RX_BUF_PAD + RX_BUF_WRAP_PAD)

// #ifndef __KERNEL__
#define PCI_VENDOR_ID_ALTERA			0x1172
#define PCI_DEVICE_ID_ALTERA_INTERNAL	0xe004
#define PCI_DEVICE_ID_ALTERA_EXTERNAL	0xe003

#define PCI_VENDOR_ID_XILINX			0x10ee
#define PCI_DEVICE_ID_XILINX_SerialDemo	0x903f
// #endif

#define DMAMASK 64

#ifndef __KERNEL__
typedef uint64_t dma_addr_t;
#endif

struct dma_buffer {
	dma_addr_t dma_addr; /* bus address */	//DMA区域物理地址，FPGA使用
	void *virtual_addr; /* kernel virtual address */	//DMA区域虚拟地址，kernel空间
	void *mmap_addr; /* user virtual address */			//DMA区域虚拟地址，user空间
	size_t size;
};

#define IOCTL_DMA_BUFFER _IOR('d', 1, struct dma_buffer)

#endif /* RTL8139_IOCTL_H */
