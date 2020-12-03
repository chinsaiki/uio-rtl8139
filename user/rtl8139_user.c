#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "dma.h"
#include "rtl8139_ioctl.h"
#include "rtl8139_reg.h"
#include "rtl8139_user.h"
#include "sysfs.h"

static int map_resource(struct iomem_resource *io, char *uio_filename)
{
	int fd;

	fd = open(uio_filename, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "open %s failed: %s\n", uio_filename, strerror(errno));
		return -1;
	}

	io->mmapaddr = mmap(NULL, io->size, PROT_READ | PROT_WRITE,
			MAP_SHARED, fd, io->offset);

	if (io->mmapaddr == MAP_FAILED ) {
		fprintf(stderr, "mmap(addr=0x%lx, size=0x%lx, offset=0x%lx, fd=%d, uio_filename=%s) failed: %s\n", io->addr, io->size, io->offset, fd, uio_filename, strerror(errno));
		close(fd);
		return -1;
	}

	close(fd);

	return 1;
}

static void unmap_resource(struct iomem_resource *io)
{
	int r;

	r = munmap(io->mmapaddr, io->size);
	if (r < 0)
		fprintf(stderr, "munmap failed: %s\n", strerror(errno));
}

int pci_resources_map(struct rtl8139_dev *nic, char *directory)
{
	DIR *dir;
	int i;
	char name[32];
	char path[2048];
	char filename[2048];
	int r;
	int barno;

	memset(nic->bar, 0, sizeof(nic->bar));
	for (i = 0; i < MAX_IOS; i++) {
		snprintf(path, sizeof(path), "%s/maps/map%d", directory, i);

		r = access(path, F_OK);
		if (r != 0){
			// perror("access");
			continue;
		}

		snprintf(filename, sizeof(filename), "%s/name", path);
		r = parse_sysfs_string(filename, name, sizeof(name));
		if (r <= 0){
			fprintf(stderr, "parse_sysfs_string %s fail!\n", filename);
			return -1;
		}

		if (strlen(name)!=4 || strncmp("BAR", name, 3) != 0){
			fprintf(stderr, "No map for non-BAR : %s\n", name);
			continue;
		}
		barno = strtol(name+3, NULL, 10);

		snprintf(filename, sizeof(filename), "%s/addr", path);
		r = parse_sysfs_int(filename, &nic->bar[barno].addr);
		if (r <= 0){
			fprintf(stderr, "parse_sysfs_int %s fail!\n", filename);
			return -1;
		}

		snprintf(filename, sizeof(filename), "%s/offset", path);
		r = parse_sysfs_int(filename, &nic->bar[barno].offset);
		if (r <= 0){
			fprintf(stderr, "parse_sysfs_int %s fail!\n", filename);
			return -1;
		}

		snprintf(filename, sizeof(filename), "%s/size", path);
		r = parse_sysfs_int(filename, &nic->bar[barno].size);
		if (r <= 0){
			fprintf(stderr, "parse_sysfs_int %s fail!\n", filename);
			return -1;
		}

		snprintf(filename, sizeof(filename), "%s/resource%d", nic->uio_device_resource_folder, barno);
		r = map_resource(&nic->bar[barno], filename);
		if (r <= 0){
			fprintf(stderr, "map_resource %d fail!\n", i);
			return -1;
		}

		fprintf(stderr, "bar[%d] addr: %lx offset: %lx size: %lx mmap'ed at %p\n",
				barno,nic->bar[barno].addr,
				nic->bar[barno].offset, nic->bar[barno].size,
				nic->bar[barno].mmapaddr);
	}

	return 1;
}

void pci_resources_unmap(struct rtl8139_dev *nic)
{
	int i;

	for (i = 0; i < MAX_IOS; i++){
		if (nic->bar[i].size)
			unmap_resource(&nic->bar[i]);
	}
}

int uio_device_find(struct rtl8139_dev *nic,
		char *sysfs_pci_path,
		char *directory, size_t directory_len)
{
	DIR *dir;
	struct dirent *e;
	char *endptr;
	unsigned long n;
	char uio_path[1024];

	strncpy(uio_path, sysfs_pci_path, 1024);
	strncat(uio_path, "/uio/", 1024 - strlen(uio_path));

	dir = opendir(uio_path);
	if (dir == NULL)
		return -1;

	while ((e = readdir(dir)) != NULL) {
		if (strncmp("uio", e->d_name, 3) != 0)
			continue;

		errno = 0;
		endptr = NULL;
		n = strtoul(e->d_name + 3, &endptr, 10);
		if (errno != 0 || endptr == NULL || *endptr) {
			fprintf(stderr, "strtoul failed\n");
		 continue;	
		}

		snprintf(nic->uio_device_name, sizeof(nic->uio_device_name),
				"/dev/uio%d", n);
		snprintf(nic->uio_device_resource_folder, sizeof(nic->uio_device_resource_folder),
				"/sys/class/uio/uio%d/device", n);
		strncpy(directory, uio_path, directory_len);
		snprintf(directory + strlen(directory),
				directory_len - strlen(directory),
				"/uio%d", n);
		break;
	}

	closedir(dir);

	return 1;
}

void rtl8139_print_mac_addr(struct rtl8139_dev *nic)
{
	int i;
	uint8_t v;
	uint32_t low;
	uint32_t high;

	for (i = 0; i < 6; i++) {
		v = ioread8(nic->base_addr + i);
		fprintf(stderr, "%02x", v);
		if (i != 5)
			fprintf(stderr, ":");
	}
	fprintf(stderr, "\n");
}

void rtl8139_init(struct rtl8139_dev *nic)
{
	uint32_t r;

	/* software reset */
	r = register_read8(nic, R_CR);
	register_write8(nic, R_CR, r | (1 << RST));
	do {
		/* memory barrier */
		__asm__ __volatile__("" : : : "memory");
		r = register_read8(nic, R_CR);
	} while (r & (1 << RST));

	register_write8(nic, R_CR, r | (1 << RE));

	register_write32(nic, R_RCR, 
			/* (1 << AB) | (1 << AM) | (1 << APM) | */
			(1 << AAP) |
			(1 << WRAP) |
			RX_BUFFER_LEN_32k |
			MXDMA_UNLIMITED);

	register_write32(nic, R_RBSTART, htole32((uint32_t)nic->rx_ring.dma_addr));

	register_write32(nic, R_MPC, 0);

	/* no early-rx interrupts */
	r = register_read16(nic, R_MISR);
	register_write16(nic, R_MISR, r & 0xf000);

	r = register_read32(nic, R_TCR);
	fprintf(stderr, "hardware version id: 0x%02x\n", ((r >> 22) & 0x03) | ((r >> 24) & 0x7c));

	/* enable all known interrupts */
	register_write16(nic, R_IMR, INT_MASK);
}

static int rtl8139_interrupt_enable(struct rtl8139_dev *nic)
{
	int r;
	int value;

	value = 1;
	r = write(nic->fd, &value, sizeof(value));
	if (r != sizeof(value)) {
		fprintf(stderr, "write failed: %s\n", strerror(errno));
		return -1;
	}

	return 1;
}

int packet_header_check(uint16_t pkt_hdr)
{
	if (!(pkt_hdr & (1 << ROK)) ||
			(pkt_hdr & (1 << RUNT)) ||
			(pkt_hdr & (1 << LONG)) ||
			(pkt_hdr & (1 << CRCE)) ||
			(pkt_hdr & (1 << FAE))) {
		return -1;
	}

	return 1;
}

static void rtl8139_reset_rx(struct rtl8139_dev *nic)
{
	uint8_t tmp;

	tmp = register_read8(nic, R_CR);
	register_write8(nic, R_CR, tmp & (0 << RE));
	register_write8(nic, R_CR, tmp);

	register_write32(nic, R_RCR, 
			(1 << AAP) |
			(1 << WRAP) |
			RX_BUFFER_LEN_32k |
			MXDMA_UNLIMITED);

	nic->rx_idx = 0;
}

static void recv_callback(uint8_t *payload, uint16_t len)
{
	int i;

	fprintf(stderr, "Packet length: 0x%04x\n", len);

	for (i = 0; i < len; i++)
		fprintf(stderr, "0x%02x ", payload[i]);
	fprintf(stderr, "\n");
}

static int rtl8139_receive_packets(struct rtl8139_dev *nic)
{
	uint8_t *rx_ring;
	int recvd;
	int r;

#define RECV_PKT_MAX 64 
	rx_ring = (uint8_t *) nic->rx_ring.mmap_addr;
	recvd = 0;

	while (recvd < RECV_PKT_MAX) {
		uint8_t cmd;
		uint16_t pkt_len;

		/* rx buffer empty ? */
		cmd = register_read8(nic, R_CR);
		if (cmd & (1 << BUFE)) {
			fprintf(stderr, "buffer empty (BUFE)\n");
			break;
		}

		r = packet_header_check(le16toh(*((uint16_t *) &rx_ring[nic->rx_idx])));
		if (r <= 0) {
			fprintf(stderr, "invalid packet, dropping it, and resetting Rx\n");
			rtl8139_reset_rx(nic);
			return 0;
		}

		pkt_len = le16toh(*((uint16_t *) &rx_ring[nic->rx_idx + 2]));

		recv_callback(&rx_ring[nic->rx_idx + 4], pkt_len);

		recvd++;

		/* update read pointer */
		nic->rx_idx = (nic->rx_idx + pkt_len + 4 + 3) & (~3);
		register_write16(nic, R_CAPR, nic->rx_idx - 0x10);

		nic->rx_idx %= RX_BUF_TOT_LEN;
	}

	return recvd;
}

static void rtl8139_interrupt(struct rtl8139_dev *nic)
{
	uint16_t isr;

	isr = register_read16(nic, R_ISR);
	/* clear ISR to acknowledge irq */
	register_write16(nic, R_ISR, 0xffff);

	if (isr == 0)
		goto out;

	if (isr & (1 << ROK))
		rtl8139_receive_packets(nic);

out:
	/* re-enable low level pci interrupts that has been disabled
	 * by the UIO driver */
	rtl8139_interrupt_enable(nic);
}

void handle_interrupt(int fd, struct rtl8139_dev *nic)
{
	struct epoll_event ev;
	struct epoll_event events[10];
	int epfd;
	int r;
	int i;

	epfd = epoll_create(10);

	ev.events = EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP;
	ev.data.fd = fd;
	r = epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
	if (r < 0) {
		fprintf(stderr, "epoll_ctl failed: %s\n", strerror(errno));
		return;
	}

	while (1) {
		int nfds;
		int n;

		nfds = epoll_wait(epfd, events, 10, -1);
		if (nfds < 0) {
			fprintf(stderr, "epoll_wait failed: %s\n", strerror(errno));
			return;
		}

		for (i = 0; i < nfds; i++) {
			read(events[i].data.fd, &n, sizeof(n));
			rtl8139_interrupt(nic);
		}
	}

	close(epfd);
}


static
void dump_mem(char* pMem, size_t len, const char* file) {
	int fd = open(file, O_RDWR | O_CREAT | O_TRUNC);
	if (fd < 0) {
		perror("error open:");
		return;
	}
	if (len == 0)
		return;
	size_t row_nb = (len - 1) / 16 + 1;
	unsigned pos;
	size_t bufSize = 16 * 6 + 16 * 6 + 1;
	char *p = (char*)malloc(bufSize);
	unsigned j;
	unsigned i;
	for (i = 0; i < row_nb; i++) {
		memset(p, 0, bufSize);
		//raw
		for (j = 0; j < 16; ++j) {
			pos = i * 16 + j;
			if (pos < len) {
				sprintf(p + strlen(p), "0x%02X, ", *((unsigned char*)pMem + pos));
			}
			else {
				sprintf(p + strlen(p), "      ");
			}
		}
		//ascii
		sprintf(p + strlen(p), "//");
		for (j = 0; j < 16; ++j) {
			pos = i * 16 + j;
			if (pos < len) {
				if (*((unsigned char*)pMem + pos) >= 32 && *((unsigned char*)pMem + pos) <= 126)
					sprintf(p + strlen(p), "%c", *((unsigned char*)pMem + pos));
				else
					sprintf(p + strlen(p), ".");
			}
		}
		sprintf(p + strlen(p), "\n");
		write(fd, p, strlen(p));
	}
	free(p);

	close(fd);
}


static 
int set_lite_table_header(struct lite_dma_header *header)
{
    int i;
    for (i = 0; i < 128; i++)
        header->flags[i] = htole32(0x0); 
    return 0;
}

static 
int set_read_desc(struct dma_descriptor *rd_desc, dma_addr_t source, uint64_t dest, uint32_t ctl_dma_len, uint32_t id)
{
    rd_desc->src_addr_ldw = htole32(source & 0xffffffffUL);
    rd_desc->src_addr_udw = htole32((source >> 32));
    rd_desc->dest_addr_ldw = htole32(dest & 0xffffffffUL);
    rd_desc->dest_addr_udw = htole32((dest >> 32));
    rd_desc->ctl_dma_len = htole32(ctl_dma_len | (id << 18));
    rd_desc->reserved[0] = htole32(0x0);
    rd_desc->reserved[1] = htole32(0x0);
    rd_desc->reserved[2] = htole32(0x0);
    return 0;
}
static 
int set_write_desc(struct dma_descriptor *wr_desc, uint64_t source, dma_addr_t dest, uint32_t ctl_dma_len, uint32_t id)
{
    wr_desc->src_addr_ldw = htole32(source & 0xffffffffUL);
    wr_desc->src_addr_udw = htole32((source >> 32));
    wr_desc->dest_addr_ldw = htole32(dest & 0xffffffffUL);
    wr_desc->dest_addr_udw = htole32((dest >> 32));
    wr_desc->ctl_dma_len = htole32(ctl_dma_len | (id << 18));
    wr_desc->reserved[0] = htole32(0x0);
    wr_desc->reserved[1] = htole32(0x0);
    wr_desc->reserved[2] = htole32(0x0);
    return 0;
}

static
int alt_dma_desc_init(struct rtl8139_dev * nic)
{
    int i;
	printf("alt_dma_desc_init nb=%d", nic->dma.nb);
	size_t dma_page_size = nic->dma.num_dwords * 4;
	size_t dma_tot_size = dma_page_size * nic->dma.nb;

	//DMA key address
	nic->dma.lite_table_rd_cpu_virt_addr = nic->rx_ring.mmap_addr;
	nic->dma.lite_table_wr_cpu_virt_addr = nic->rx_ring.mmap_addr + sizeof(struct lite_dma_desc_table);
	nic->dma.cpu_data_virt_addr = nic->rx_ring.mmap_addr + sizeof(struct lite_dma_desc_table) * 2;

	nic->dma.lite_table_rd_bus_addr = nic->rx_ring.dma_addr;
	nic->dma.lite_table_wr_bus_addr = nic->rx_ring.dma_addr + sizeof(struct lite_dma_desc_table);
	nic->dma.cpu_data_bus_addr = nic->rx_ring.dma_addr + sizeof(struct lite_dma_desc_table) * 2;

	if (nic->rx_ring.size < sizeof(struct lite_dma_desc_table)*2 + dma_tot_size){
        fprintf (stderr, "  error: nic->rx_ring.size =%lu < sizeof(lite_dma_desc_table) = %lu *2 + num_dwords(=%d) *4 *%d\n", nic->rx_ring.size, sizeof(struct lite_dma_desc_table), nic->dma.num_dwords, nic->dma.nb);
		return -1;
	}

	if (nic->bar[AVALON_DMA_MEM_BAR].size < dma_tot_size){
        fprintf (stderr, "  error: nic->bar[AVALON_DMA_MEM_BAR].size(%lu) < dma_tot_size(%lu)\n", nic->bar[AVALON_DMA_MEM_BAR].size, dma_tot_size);
		return -1;
	}

	set_lite_table_header(&nic->dma.lite_table_rd_cpu_virt_addr->header);
	set_lite_table_header(&nic->dma.lite_table_wr_cpu_virt_addr->header);

	for(i=0; i < 128; ++i){
		set_read_desc(&nic->dma.lite_table_rd_cpu_virt_addr->descriptors[i], nic->dma.cpu_data_bus_addr + dma_page_size*i, (uint64_t)AVALON_DMA_MEM_BASE + dma_page_size*i, nic->dma.num_dwords, i);
		set_write_desc(&nic->dma.lite_table_wr_cpu_virt_addr->descriptors[i], (uint64_t)AVALON_DMA_MEM_BASE + dma_page_size*i, nic->dma.cpu_data_bus_addr + dma_page_size*i, nic->dma.num_dwords, i);
	}

	/* memory barrier */
	__asm__ __volatile__("" : : : "memory");

	return 0;
}

static
int alt_dma_mem_init(struct rtl8139_dev * nic, int v, const char*pre, const char* after)
{
    int i;
	size_t dma_page_size = nic->dma.num_dwords * 4;
	size_t dma_tot_size = dma_page_size * nic->dma.nb;

	// char* cpu_data_virt_addr = nic->rx_ring.mmap_addr + sizeof(struct lite_dma_desc_table) * 2;

	dump_mem((char*)nic->dma.cpu_data_virt_addr, dma_tot_size, pre);
	memset((char*)nic->dma.cpu_data_virt_addr, v, dma_tot_size);
	dump_mem((char*)nic->dma.cpu_data_virt_addr, dma_tot_size, after);


	/* memory barrier */
	__asm__ __volatile__("" : : : "memory");

	return 0;
}

static
int alt_dma_write_desc(struct rtl8139_dev * nic, int isRD)
{
	uint32_t last_id;
	int write_127;
	int r;
	if (isRD){
		last_id = ioread32(nic->bar[AVALON_DMA_DESC_BAR].mmapaddr + DESC_CTRLLER_BASE + ALTERA_LITE_DMA_RD_LAST_PTR);
	}else{
		last_id = ioread32(nic->bar[AVALON_DMA_DESC_BAR].mmapaddr + DESC_CTRLLER_BASE + ALTERA_LITE_DMA_WR_LAST_PTR);
	}
	fprintf(stderr, "DMA isRD=%d, last_id = %d\n", isRD, last_id);
	write_127 = 0;

	// dma_addr_t lite_table_rd_bus_addr = nic->rx_ring.dma_addr;
	// dma_addr_t lite_table_wr_bus_addr = nic->rx_ring.dma_addr + sizeof(struct lite_dma_desc_table);

	/*write desc table base addr*/
	if (isRD){//RD
		r = iowrite32chk(nic->bar[AVALON_DMA_DESC_BAR].mmapaddr + DESC_CTRLLER_BASE + ALTERA_LITE_DMA_RD_RC_HIGH_SRC_ADDR, (nic->dma.lite_table_rd_bus_addr >> 32));
		r = iowrite32chk(nic->bar[AVALON_DMA_DESC_BAR].mmapaddr + DESC_CTRLLER_BASE + ALTERA_LITE_DMA_RD_RC_LOW_SRC_ADDR, nic->dma.lite_table_rd_bus_addr);
	}else{//WR
		r = iowrite32chk(nic->bar[AVALON_DMA_DESC_BAR].mmapaddr + DESC_CTRLLER_BASE + ALTERA_LITE_DMA_WR_RC_HIGH_SRC_ADDR, (nic->dma.lite_table_wr_bus_addr >> 32));
		r = iowrite32chk(nic->bar[AVALON_DMA_DESC_BAR].mmapaddr + DESC_CTRLLER_BASE + ALTERA_LITE_DMA_WR_RC_LOW_SRC_ADDR, nic->dma.lite_table_wr_bus_addr);
	}
	
	if(last_id == 0xFF){	//init desc fifo addr
		if (isRD){
			r = iowrite32chk(nic->bar[AVALON_DMA_DESC_BAR].mmapaddr + DESC_CTRLLER_BASE + ALTERA_LITE_DMA_RD_DESC_FIFO_HIGH_DEST_ADDR, RD_DESC_FIFO_BASE_HI);
			r = iowrite32chk(nic->bar[AVALON_DMA_DESC_BAR].mmapaddr + DESC_CTRLLER_BASE + ALTERA_LITE_DMA_RD_DESC_FIFO_LOW_DEST_ADDR, RD_DESC_FIFO_BASE_LOW);
		}else{
			r = iowrite32chk(nic->bar[AVALON_DMA_DESC_BAR].mmapaddr + DESC_CTRLLER_BASE + ALTERA_LITE_DMA_WR_DESC_FIFO_HIGH_DEST_ADDR, WR_DESC_FIFO_BASE_HI);
			r = iowrite32chk(nic->bar[AVALON_DMA_DESC_BAR].mmapaddr + DESC_CTRLLER_BASE + ALTERA_LITE_DMA_WR_DESC_FIFO_LOW_DEST_ADDR, WR_DESC_FIFO_BASE_LOW);
		}
	}
	/* memory barrier */
	__asm__ __volatile__("" : : : "memory");

	//id wrap
	if(last_id == 0xFF) last_id = 127;
	
	last_id = last_id + nic->dma.nb;

	if(last_id > 127){
		last_id = last_id - 128;
		if((nic->dma.nb > 1) && (last_id != 127)) write_127 = 1;
	}
        
	//last_ptr = trigger DMA
	if (write_127) iowrite32chk(nic->bar[AVALON_DMA_DESC_BAR].mmapaddr + DESC_CTRLLER_BASE + ALTERA_LITE_DMA_RD_LAST_PTR, 127);

	r = iowrite32chk(nic->bar[AVALON_DMA_DESC_BAR].mmapaddr + DESC_CTRLLER_BASE + ALTERA_LITE_DMA_RD_LAST_PTR, last_id);

	//waiting for DMA done
	int timeout = 2000;//2s
	while (1) {
		if (nic->dma.lite_table_rd_cpu_virt_addr->header.flags[last_id]) {
			fprintf(stderr, "DMA isRD=%d done OK, last_id = %d\n", isRD, last_id);
			break;
		}
		
		if(timeout == 0){
			fprintf(stderr, "DMA times out\n");
			// bk_ptr->dma_status.read_eplast_timeout = 1;
			fprintf(stderr, "DWORD = %08x\n", nic->dma.num_dwords);
			fprintf(stderr, "Desc = %08x\n", nic->dma.nb);
			dump_mem((char*)nic->dma.lite_table_rd_cpu_virt_addr, sizeof(struct lite_dma_desc_table), "rd_table.txt");
			dump_mem((char*)nic->dma.lite_table_wr_cpu_virt_addr, sizeof(struct lite_dma_desc_table), "wr_table.txt");
			return -1;
		}

		timeout--;
		// cpu_relax();
		usleep(1000);//ms
	}
	return 0;
}

int main(int argc, char *argv[])
{
	if (argc < 4){
        fprintf (stderr, "error: %s need 5 args, current=%d\n", argv[0], argc);
        fprintf (stderr, "read:  %s r <bar> <addr>\n", argv[0]);
        fprintf (stderr, "write: %s w <bar> <addr> <value>\n", argv[0]);
        fprintf (stderr, "dump:  %s d <bar> <addr> <num>\n", argv[0]);
		return -1;
    }

	struct rtl8139_dev nic;
	int r;
	char sysfs_pci_path[1024];
	char resources_directory[1024];

	memset(&nic, 0, sizeof(nic));

	/* 遍历 /sys/bus/pci/devices/xxxx:xx:xx.x 匹配ID */
	int fi;
	int found_dev = 0;
	for (fi = 0; fi < 3; ++fi){
		if (fi == 0){
			r = find_sysfs_device(PCI_VENDOR_ID_ALTERA, PCI_DEVICE_ID_ALTERA_INTERNAL,
					sysfs_pci_path, 1024, 0);
		}else if (fi==1){
			r = find_sysfs_device(PCI_VENDOR_ID_ALTERA, PCI_DEVICE_ID_ALTERA_EXTERNAL,
					sysfs_pci_path, 1024, 0);
		}else{
			r = find_sysfs_device(PCI_VENDOR_ID_XILINX, PCI_DEVICE_ID_XILINX_SerialDemo,
					sysfs_pci_path, 1024, 0);
		}
		if (r>=0){
			fprintf(stdout, "Found dev fi=%d\n", fi);
			found_dev = 1;
			break;
		}
		
	}
	if (!found_dev) {
		fprintf(stderr, "rtl8139 PCI device (0x%x:0x%x) or (0x%x:0x%x) or (0x%x:0x%x) not found\n",
				PCI_VENDOR_ID_ALTERA, PCI_DEVICE_ID_ALTERA_INTERNAL,
				PCI_VENDOR_ID_ALTERA, PCI_DEVICE_ID_ALTERA_EXTERNAL,
				PCI_VENDOR_ID_XILINX, PCI_DEVICE_ID_XILINX_SerialDemo
				);
		return 1;
	}

	/* 存储资源所在目录： /sys/bus/pci/devices/xxxx:xx:xx.x/uid/uidY */
	r = uio_device_find(&nic, sysfs_pci_path, resources_directory, 1024);
	if (r < 0) {
		fprintf(stderr, "uio device not found\n");
		return 1;
	}

	fprintf(stderr, "resources_directory: %s\n", resources_directory);

	/* 根据资源目录中mapZ中的name(BAR%d)/addr/len/offset，打开/sys/class/uio/uiY/device/resource%d作为bar的mmap空间 */
	if (pci_resources_map(&nic, resources_directory) < 0){
		fprintf(stderr, "pci_resources_map fail!\n");
		goto out;
	}

	/* prevent from being swapped out */
	if (mlockall(MCL_CURRENT | MCL_FUTURE)!=0){
		perror("mlockall fail!");
		goto out_mlock;
	}
	

    if (argv[1][0] == 'w' || argv[1][0] == 'W'){
		int cmd_bar = strtol(argv[2], NULL, 10);
		int cmd_offset = strtol(argv[3], NULL, 16);
		int cmd_value = strtol(argv[4], NULL, 16);
        printf("write bar=%d  offset=0x%08lx  value=0x%08lx\n", cmd_bar, cmd_offset, cmd_value);
		iowrite32(nic.bar[cmd_bar].mmapaddr+cmd_offset, cmd_value);
    }else if (argv[1][0] == 'r' || argv[1][0] == 'R'){
		int cmd_bar = strtol(argv[2], NULL, 10);
		int cmd_offset = strtol(argv[3], NULL, 16);
		int cmd_value;
        printf("read bar=%d  offset=0x%08lx\n", cmd_bar, cmd_offset); 
        cmd_value = ioread32(nic.bar[cmd_bar].mmapaddr+cmd_offset);
        printf("read value=0x%08lx\n", cmd_value); 
    }else if(argv[1][0] == 'd' || argv[1][0] == 'D'){	//dump
		int cmd_bar = strtol(argv[2], NULL, 10);
		int cmd_offset = strtol(argv[3], NULL, 16);
		int cmd_scope = strtol(argv[4], NULL, 16);
		int cmd_value;
		int i;
        printf("read bar=%d  begin offset=0x%08lx num=%d:\n", cmd_bar, cmd_offset, cmd_scope); 
		if (cmd_offset&3!=0){
			fprintf(stderr, "offset=0x%08lx illegal: not DWORD align!\n", cmd_offset);
			goto out_mlock;	//deprecated
		}
		for (i=0; i<cmd_scope; ++i){
			cmd_value = ioread32(nic.bar[cmd_bar].mmapaddr+cmd_offset);
        	printf("A=0x%08lx  V=0x%08lx\n", cmd_offset, cmd_value); 
			cmd_offset += 4;
		}
	}else{
		fprintf(stderr, "command %s not support!\n", argv[1]);
		goto out_mlock;	//deprecated
	}

out_mlock:
	munlockall();
out:
	pci_resources_unmap(&nic);

	return 0;	
}
