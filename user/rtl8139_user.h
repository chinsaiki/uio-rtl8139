#ifndef RTL8139_USER_H
#define RTL8139_USER_H
#include <unistd.h>

#ifndef __KERNEL__
typedef uint64_t dma_addr_t;
#endif

#define MAX_IOS	6

///////////////////////////////////////////////////////////////
/* desc bar */
#define AVALON_DMA_DESC_BAR 0
#define DESC_CTRLLER_BASE               0x0000

#define ALTERA_LITE_DMA_RD_RC_LOW_SRC_ADDR      0x0000	//base address of the read status and descriptor table in the RootComplex memory
#define ALTERA_LITE_DMA_RD_RC_HIGH_SRC_ADDR     0x0004
#define ALTERA_LITE_DMA_RD_DESC_FIFO_LOW_DEST_ADDR   0x0008	//base address of the read descriptor FIFO in Endpoint memory (ALTERA_LITE_DMA_RD_CTLR_LOW_DEST_ADDR)
#define ALTERA_LITE_DMA_RD_DESC_FIFO_HIGH_DEST_ADDR  0x000C
#define ALTERA_LITE_DMA_RD_LAST_PTR             0x0010

#define ALTERA_LITE_DMA_WR_RC_LOW_SRC_ADDR      0x0100
#define ALTERA_LITE_DMA_WR_RC_HIGH_SRC_ADDR     0x0104
#define ALTERA_LITE_DMA_WR_DESC_FIFO_LOW_DEST_ADDR   0x0108
#define ALTERA_LITE_DMA_WR_DESC_FIFO_HIGH_DEST_ADDR  0x010C
#define ALTERA_LITE_DMA_WR_LAST_PTR             0x0110


#define RD_DESC_FIFO_BASE_LOW		0x01000000	// (RD_CTRL_BUF_BASE_LOW) [rd_dts_slave]
#define RD_DESC_FIFO_BASE_HI			0x01001FFF
#define WR_DESC_FIFO_BASE_LOW		0x01002000	// (WR_CTRL_BUF_BASE_LOW) [wr_dts_slave]
#define WR_DESC_FIFO_BASE_HI			0x01003FFF

/* user bar */
#define AVALON_USER_BAR		2

/* dma bar */
#define AVALON_DMA_MEM_BAR	4
#define AVALON_DMA_MEM_BASE 0x00000000



#define ALTERA_DMA_DESCRIPTOR_NUM 128

struct dma_descriptor {	//32 Bytes
    uint32_t src_addr_ldw;
    uint32_t src_addr_udw;
    uint32_t dest_addr_ldw;
    uint32_t dest_addr_udw;
    uint32_t ctl_dma_len;
    uint32_t reserved[3];
} __attribute__ ((packed));

struct lite_dma_header {//4 Bytes
    volatile uint32_t flags[128];
} __attribute__ ((packed));

struct lite_dma_desc_table {	//4*128 + 32 * 128 = 4608 Bytes
    struct lite_dma_header header;
    struct dma_descriptor descriptors[ALTERA_DMA_DESCRIPTOR_NUM];
} __attribute__ ((packed));

struct alt_dma_cache_t{
	struct lite_dma_desc_table *lite_table_rd_cpu_virt_addr;
	struct lite_dma_desc_table *lite_table_wr_cpu_virt_addr;
	void *cpu_data_virt_addr;

	dma_addr_t lite_table_rd_bus_addr;
	dma_addr_t lite_table_wr_bus_addr;
	dma_addr_t cpu_data_bus_addr;

	int nb;
	int num_dwords;
};

///////////////////////////////////////////////////////////////
struct iomem_resource {
	// char name[32];
	uint64_t addr;
	char* mmapaddr; /* return by mmap */
	uint64_t offset;
	uint64_t size;
};

struct rtl8139_dev {
	char uio_device_name[32]; /* /dev/uio%d */
	char uio_device_resource_folder[256]; /* /sys/class/uio/ui%d/device */
	int fd; /* handle on /dev/uio%d */

	struct iomem_resource bar[MAX_IOS];	//BAR0~5
	void *base_addr;

	struct dma_buffer rx_ring;
	int rx_idx; /* current read index */
	int rx_ring_fd;

	struct alt_dma_cache_t dma;
};

#endif /* RTL8139_USER_H */
