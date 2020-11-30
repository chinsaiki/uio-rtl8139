#include <linux/cdev.h>
#include <linux/dma-mapping.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/pci.h>
#include <linux/uio_driver.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/version.h>
#include <asm/uaccess.h>

#include "rtl8139_ioctl.h"

#ifdef DEBUG_RTL8139
#define DBG(args...) printk("uio_rtl8139: " args)
#else
#define DBG(arg...)
#endif

#define INFO(args...) printk(KERN_INFO "uio_rtl8139: " args)
#define ERR(args...) printk(KERN_ERR "uio_rtl8139: " args)

#define CHARDEV_NAME "dma_rtl8139"
#define CHARDEV_PATH "/dev/" CHARDEV_NAME

struct uio_rtl8139_dev {
	struct uio_info info;		//uio 通用結構

	struct pci_dev *dev;		//pci設備描述結構
	struct dma_buffer rx_ring;	

	struct cdev cdev;			//
	struct class *cls;
	dev_t devno;
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 3, 0)
static bool pci_check_and_mask_intx(struct pci_dev *pdev)
{
	bool pending;
	uint32_t status;

	pci_block_user_cfg_access(pdev);
	pci_read_config_dword(pdev, PCI_COMMAND, &status);

	/* interrupt is not ours, goes to out */
	pending = (((status >> 16) & PCI_STATUS_INTERRUPT) != 0);
	if (pending) {
		uint16_t old, new;

		old = status;
		if (status != 0)
			new = old & (~PCI_COMMAND_INTX_DISABLE);
		else
			new = old | PCI_COMMAND_INTX_DISABLE;

		if (old != new)
			pci_write_config_word(pdev, PCI_COMMAND, new);
	}
	pci_unblock_user_cfg_access(pdev);

	return pending;
}
#endif

static irqreturn_t uio_rtl8139_irq_handler(int irq, struct uio_info *dev)
{
	struct uio_rtl8139_dev *uio_dev;
	bool pending;

	uio_dev = container_of(dev, struct uio_rtl8139_dev, info);

	/* Read the status register in pci configuration space to
	 * see wether an interrupt occured or not.
	 *
	 * We do this interrupt status check at the pci low level,
	 * in order to let the userspace manage the interrupt handling by
	 * reading the nic register (ISR). Because issuing a read on the register (ISR)
	 * clear all interrupts. So if it was done here, the userspace would be aware of
	 * interrupts happening by reading /dev/uio%d, but would'nt be able to read
	 * the ISR */
	pending = pci_check_and_mask_intx(uio_dev->dev);
	if (!pending)
		return IRQ_NONE;

	return IRQ_HANDLED;
}

/* called when user write in /dev/uio%d device, requesting to enable or
 * disable irq */
static int uio_rtl8139_irqcontrol(struct uio_info *dev, s32 irq_on)
{
	struct uio_rtl8139_dev *uio_dev;

	uio_dev = container_of(dev, struct uio_rtl8139_dev, info);

	DBG("irqcontrol %s\n", irq_on ? "on" : "off");
	pci_intx(uio_dev->dev, irq_on);

	return 0;
}

static int uio_rtl8139_register_iomem(struct uio_rtl8139_dev *uio_dev,
		int n, const char *name, unsigned long start, unsigned long end,
		unsigned long len)
{
	void *internal_addr;

	if (start == 0 || end == 0)
		return -EINVAL;

	internal_addr = ioremap(start, len);	////用mmap映射一个设备意味着使用户空间的一段地址关联到设备内存上，这使得只要程序在分配的地址范围内进行读取或写入，实际上就是对设备的访问。用iounmap取消映射。
	if (internal_addr == NULL) {
		DBG("ioremap(%lx, %lx) failed\n", start, len);
		return -1;
	}

	DBG("register iomem %s start: %lx end: %lx len: %lx internal_addr: %p\n",
			name, start, end, len, internal_addr);

	uio_dev->info.mem[n].name = name;
	uio_dev->info.mem[n].addr = start;
	uio_dev->info.mem[n].size = len;
	uio_dev->info.mem[n].internal_addr = internal_addr;
	uio_dev->info.mem[n].memtype = UIO_MEM_PHYS;

	return 0;
}

static int uio_rtl8139_register_ioport(struct uio_rtl8139_dev *uio_dev,
		int n, const char *name, unsigned long start, unsigned long len)
{
	if (start == 0 || len == 0)
		return -EINVAL;

	DBG("register ioport %s start: %lx len: %lx\n", name, start, len);

	uio_dev->info.port[n].name = name;
	uio_dev->info.port[n].start = start;
	uio_dev->info.port[n].size = len;
	uio_dev->info.port[n].porttype = UIO_PORT_X86;

	return 0;
}

/* 重新映射I/O和內存 */
static int uio_rtl8139_register_io_resources(struct pci_dev *dev,
		struct uio_rtl8139_dev *uio_dev)
{
	int i;
	int r;
	int iom;
	int iop;
	const char *io_names[] = {
		"BAR0", "BAR1", "BAR2", "BAR3",
		"BAR4", "BAR5",
	};

	iom = 0;
	iop = 0;

	for (i = 0; i < 6; i++) {
		unsigned long start;
		unsigned long end;
		unsigned long len;
		unsigned long flags;

		start = pci_resource_start(dev, i);
		end = pci_resource_end(dev, i);
		len = pci_resource_len(dev, i);
		flags = pci_resource_flags(dev, i);

		if (flags & IORESOURCE_MEM) {
			r = uio_rtl8139_register_iomem(uio_dev, iom, io_names[i], start, end, len);
			if (r != 0)
				return -1;
			iom++;
		} else if (flags & IORESOURCE_IO) {
			r = uio_rtl8139_register_ioport(uio_dev, iop, io_names[i], start, len);
			if (r != 0)
				return -1;
			iop++;
		}
	}

	return 0;
}

static void uio_rtl8139_unregister_io_resources(struct uio_rtl8139_dev *uio_dev)
{
	int i;

	for (i = 0; i < 6; i++) {
		if (uio_dev->info.mem[i].internal_addr != 0)
			iounmap(uio_dev->info.mem[i].internal_addr);
	}
}

int dma_mmap(struct file *filep, struct vm_area_struct *vma)
{
	int r;
	unsigned long pfn;
	unsigned long offset;
	unsigned long len;
	struct uio_rtl8139_dev *uio_dev;

	uio_dev = (struct uio_rtl8139_dev *) filep->private_data;

	offset = vma->vm_pgoff << PAGE_SHIFT;
	len = vma->vm_end - vma->vm_start;

	DBG("mmapping vm_pgoff: %lx vma->vm_start: %lx vma->vm_end: %lx\n",
			offset, vma->vm_start, vma->vm_end);

	if (offset != 0)
		return -EINVAL;

	if (len < RX_BUF_TOT_LEN)
		return -EINVAL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
	vma->vm_flags |= VM_RESERVED;	// <3.7.0
#else
	vma->vm_flags |= (VM_DONTEXPAND | VM_DONTDUMP);
#endif

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	pfn = virt_to_phys(uio_dev->rx_ring.virtual_addr + offset) >> PAGE_SHIFT;

	r = remap_pfn_range(vma, vma->vm_start, pfn, len, vma->vm_page_prot);
	if (r != 0)
		return -EAGAIN;

	return 0;
}

int dma_open(struct inode *inode, struct file *filp)
{
	struct uio_rtl8139_dev *uio_dev;

	DBG("dma_open\n");

	uio_dev = container_of(inode->i_cdev, struct uio_rtl8139_dev, cdev);
	filp->private_data = uio_dev;

	return 0;
}

int dma_close(struct inode *inode, struct file *filp)
{
	DBG("dma_release\n");

	return 0;
}

long dma_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int r;
	struct dma_buffer dma;
	struct uio_rtl8139_dev *uio_dev;

	uio_dev = (struct uio_rtl8139_dev *) filp->private_data;

	switch (cmd) {
		case IOCTL_DMA_BUFFER:	//返回DMA参数
			dma.dma_addr = uio_dev->rx_ring.dma_addr;
			dma.virtual_addr = uio_dev->rx_ring.virtual_addr;
			dma.size = uio_dev->rx_ring.size;

			r = copy_to_user((struct dma_buffer *) arg, &dma, sizeof(dma));
			if (r != 0)
				return -EFAULT;

			break;

		default:
			return -EINVAL;
	}

	return 0;
}

static struct file_operations dma_mmap_ops = {
	.open = dma_open,
	.release = dma_close,
	.mmap = dma_mmap,
	.unlocked_ioctl = dma_ioctl
};

static void mmap_chardev_remove(struct uio_rtl8139_dev *uio_dev)
{
	if (uio_dev->cls != NULL) {
		device_destroy(uio_dev->cls, uio_dev->devno);
		class_destroy(uio_dev->cls);
	}

	unregister_chrdev(MAJOR(uio_dev->devno), CHARDEV_NAME);
}

static int mmap_chardev_setup(struct uio_rtl8139_dev *uio_dev)
{
	int r;
	dev_t dev;
	struct device *d;

	dev = 0;
	r = alloc_chrdev_region(&dev, 0, 1, CHARDEV_NAME);
	if (r < 0) {
		ERR("alloc_chrdev_region failed\n");
		return r;
	}

	uio_dev->devno = dev;

	cdev_init(&uio_dev->cdev, &dma_mmap_ops);
	uio_dev->cdev.owner = THIS_MODULE;
	uio_dev->cdev.ops = &dma_mmap_ops;
	r = cdev_add(&uio_dev->cdev, dev, 1);
	if (r < 0) {
		ERR("cdev_add failed\n");
		return r;
	}

	/* make udev/mdev creating an entry in the /dev directory */
	uio_dev->cls = class_create(THIS_MODULE, CHARDEV_NAME);
	if (uio_dev->cls == NULL) {
		return -1;
	}

	d = device_create(uio_dev->cls, NULL, dev, NULL, CHARDEV_NAME);

	if (IS_ERR(d)){
		ERR("device_create fail!\n");
		return -1;
	}
	DBG("chardev setup OK:%s\n", CHARDEV_NAME);

	return 0;
}

static int uio_rtl8139_pci_probe(struct pci_dev *dev,
		const struct pci_device_id *id)
{
	int r;
	struct uio_rtl8139_dev *uio_dev;

	uio_dev = kzalloc(sizeof(struct uio_rtl8139_dev), GFP_KERNEL);
	if (uio_dev == NULL)
		return -ENOMEM;

	r = pci_enable_device(dev);
	if (r != 0) {
		ERR("Can't enable PCI device\n");
		goto err_free;
	}

	r = pci_set_dma_mask(dev, DMA_BIT_MASK(DMAMASK));	//FPGA可访问的总线地址位宽
	if (r != 0) {
		ERR("Can't set dma mask\n");
		goto err_free;
	}

	r = pci_request_regions(dev, "uio_rtl8139");		//Reserved PCI I/O and memory resources Synopsis，设置FPGA resource name
	if (r != 0) {
		ERR("Can't request region\n");
		goto err_disable;
	}

	pci_set_master(dev);	//设定设备工作在总线主设备模式

	r = uio_rtl8139_register_io_resources(dev, uio_dev);
	if (r != 0) {
		ERR("Can't register io resources\n");
		goto err_regions;
	}

  	r = mmap_chardev_setup(uio_dev);	//cdev 是用于在用户态获取DMA参数
	if (r != 0) {
		ERR("Can't create chardev\n");
		goto err_io_resources;
	}

	uio_dev->info.name = "uio_rtl8139";
	uio_dev->info.version = "0.1";
	uio_dev->info.handler = uio_rtl8139_irq_handler;
	uio_dev->info.irq = dev->irq;
	uio_dev->info.irq_flags = IRQF_SHARED;
	uio_dev->info.irqcontrol = uio_rtl8139_irqcontrol;
	r = uio_register_device(&dev->dev, &uio_dev->info);
	if (r != 0) {
		ERR("Can't register uio device device\n");
		goto err_chardev;
	}

	uio_dev->dev = dev;
	uio_dev->rx_ring.virtual_addr = pci_alloc_consistent(dev, RX_BUF_TOT_LEN,
			&uio_dev->rx_ring.dma_addr);	//分配DMA空间，返回kernel的虚拟地址，参数3得到fpga侧用来读写host内存的物理地址

	DBG("dma alloc: virtual_addr=0x%p  dma_addr=0x%lx  size=%x\n", uio_dev->rx_ring.virtual_addr, (u64)uio_dev->rx_ring.dma_addr, RX_BUF_TOT_LEN);

	memset(uio_dev->rx_ring.virtual_addr, 0, RX_BUF_TOT_LEN);

	uio_dev->rx_ring.size = RX_BUF_TOT_LEN;

	pci_set_drvdata(dev, uio_dev);

	return 0;

err_chardev:
	mmap_chardev_remove(uio_dev);
err_io_resources:
	uio_rtl8139_unregister_io_resources(uio_dev);
err_regions:
	pci_release_regions(dev);
err_disable:
	pci_disable_device(dev);
err_free:
	kfree(uio_dev);

	return r;
}

static void uio_rtl8139_pci_remove(struct pci_dev *dev)
{
	struct uio_rtl8139_dev *uio_dev;

	uio_dev = pci_get_drvdata(dev);
	uio_rtl8139_unregister_io_resources(uio_dev);
	uio_unregister_device(&uio_dev->info);

	mmap_chardev_remove(uio_dev);

	pci_free_consistent(dev, RX_BUF_TOT_LEN, uio_dev->rx_ring.virtual_addr, uio_dev->rx_ring.dma_addr);
	pci_release_regions(dev);
	pci_disable_device(dev);
	pci_set_drvdata(dev, NULL);

	kfree(uio_dev);
}

static struct pci_device_id ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_ALTERA, PCI_DEVICE_ID_ALTERA_INTERNAL) },
	{ PCI_DEVICE(PCI_VENDOR_ID_ALTERA, PCI_DEVICE_ID_ALTERA_EXTERNAL) },
	{ PCI_DEVICE(PCI_VENDOR_ID_XILINX, PCI_DEVICE_ID_XILINX_SerialDemo) },
	{ 0, }
};

static struct pci_driver uio_rtl8139_pci_driver = {
	.name = "uio_rtl8139",
	.id_table = ids,
	.probe = uio_rtl8139_pci_probe,
	.remove = uio_rtl8139_pci_remove
};

static int __init uio_rtl8139_init(void)
{
	int r;

	r = pci_register_driver(&uio_rtl8139_pci_driver);
	if (r != 0) {
		ERR("Can't register pci driver uio_rtl8139");
		return r;
	}

	return 0;
}

static void __exit uio_rtl8139_exit(void)
{
	pci_unregister_driver(&uio_rtl8139_pci_driver);
}

module_init(uio_rtl8139_init);
module_exit(uio_rtl8139_exit);

MODULE_LICENSE("GPL");
