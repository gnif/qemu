/*
 * QEMU porthole PCI device
 *
 * Copyright (c) 2019 Geoffrey McRae
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

/*
    This device implements a means of direct memory communication between the
    host and guest. It is intended for use where live memory inspection of the
    guest is required by a third party application allowing for zero copy
    communications.

    While zero copy is possible via vhost, the goals of vhost do not align with
    the requirements of some projects, such as Looking Glass. The idea here is
    to share memory with another application by means of virtual to physical
    guest address lookup, providing access to the pages of data directly. This
    is useful in cases where the data of interest is not user allocated but has
    been allocated by vendor code such as a driver, or an OS subsystem.

    To be clear, this is not another IVSHMEM type device, instead of allocating
    a shared block of RAM, this allows an external application to access the
    guest's RAM directly. Communication is performed by means of the message
    registers which provide the physical address of the page of guest locked
    RAM with the payload.

    Since this device may be used for other projects it is possible to
    configure the subsystem_vendor_id and subsystem_id for correct device
    identification in the guest.

    Registered Subsystem IDs:

        0x4b56:64d4  KVMFR (KVM Frame Relay, ie Looking Glass)

        0xff00:0000  Reserved range for development use
                     If you wish to register an ID please make a request
                     If not these ranges are reseved for private usage.
*/

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qapi/error.h"
#include "hw/pci/pci.h"
#include "hw/qdev-properties.h"
#include "qom/object.h"
#include "chardev/char-fe.h"

#define INTRO(obj) OBJECT_CHECK(PHState, obj, "porthole")

/*
  Register defines

  SW = Software
  HW = Hardware
  S  = Set
  C  = Clear
*/

#define PH_REG_CR_START       (1 << 1) // SW=S, HW=C, start of a mapping
#define PH_REG_CR_ADD_SEGMENT (1 << 2) // SW=S, HW=C, add a segment to mapping
#define PH_REG_CR_FINISH      (1 << 3) // SW=S, HW=C, end of segments
#define PH_REG_CR_UNMAP       (1 << 4) // SW=S, HW=C, unmap a segment

#define PH_REG_CR_TIMEOUT     (1 << 5) // HW=S, HW=C, timeout occured
#define PH_REG_CR_BADADDR     (1 << 6) // HW=S, HW=C, bad address specified
#define PH_REG_CR_NOCONN      (1 << 7) // HW=S, HW=C, no client connection
#define PH_REG_CR_NORES       (1 << 8) // HW=S, HW=C, no resources left
#define PH_REG_CR_DEVERR      (1 << 9) // HW=S, HW=C, invalid device usage

#define PH_REG_CR_WRITE_MASK ( \
    PH_REG_CR_START       | \
    PH_REG_CR_ADD_SEGMENT | \
    PH_REG_CR_FINISH      | \
    PH_REG_CR_UNMAP       | \
    0x0 \
)

#define PH_REG_CR_CLEAR_MASK ( \
    PH_REG_CR_TIMEOUT | \
    PH_REG_CR_BADADDR | \
    PH_REG_CR_NOCONN  | \
    PH_REG_CR_NORES   | \
    PH_REG_CR_DEVERR  | \
    0x0 \
)

#define PH_REG_CR_SET_ERR(clear, set) \
  ph->regs.cr = (ph->regs.cr & ~((clear) & PH_REG_CR_WRITE_MASK)) | \
      ((set) & PH_REG_CR_CLEAR_MASK)

/*
  Socket communication defines
*/

typedef struct {
  uint32_t id;    // the ID of the FD
} __attribute__ ((packed)) PHMsgFd;

typedef struct {
  uint32_t fd_id; // the ID of the FD for this segment
  uint32_t size;  // the size of this segment
  uint64_t addr;  // the base address of this segment
} __attribute__ ((packed)) PHMsgSegment;

typedef struct {
  uint32_t type; // the application defined type
  uint32_t id;   // the ID of the new mapping
} __attribute__ ((packed)) PHMsgFinish;

typedef struct {
  uint32_t id;   // the mapping ID
} __attribute__ ((packed)) PHMsgUnmap;

typedef struct {
  uint32_t msg;
  union
  {
    PHMsgFd      fd;
    PHMsgSegment segment;
    PHMsgFinish  finish;
    PHMsgUnmap   unmap;
  } u;
} __attribute__ ((packed)) PHMsg;

#define PH_MSG_MAP     0x1 // start of a map sequence
#define PH_MSG_FD      0x2 // file descriptor
#define PH_MSG_SEGMENT 0x3 // map segment
#define PH_MSG_FINISH  0x4 // finish of map sequence
#define PH_MSG_UNMAP   0x5 // unmap a previous map

#define PH_MSG_MAP_SIZE     (sizeof(uint32_t))
#define PH_MSG_FD_SIZE      (sizeof(uint32_t) + sizeof(PHMsgFd))
#define PH_MSG_SEGMENT_SIZE (sizeof(uint32_t) + sizeof(PHMsgSegment))
#define PH_MSG_FINISH_SIZE  (sizeof(uint32_t) + sizeof(PHMsgFinish))
#define PH_MSG_UNMAP_SIZE   (sizeof(uint32_t) + sizeof(PHMsgUnmap))

// all registers are 32-bit
enum IntoRegs {
    // registers are readonly while any of REG_STATUS_CR_WRITE_MASK is set
    PH_REG_CR = 0,
    PH_REG_MSG_TYPE,
    PH_REG_MSG_ADDR_L,
    PH_REG_MSG_ADDR_H,
    PH_REG_MSG_SIZE,

    // pow2 padding
    PH_REG_RESERVED1,
    PH_REG_RESERVED2,
    PH_REG_RESERVED3,

    PH_REG_LAST
};

typedef struct {
    uint32_t cr;
    uint32_t type;
    hwaddr   addr;
    uint32_t size;
} PHRegs;

#define MAX_FDS  16
#define MAX_MAPS 32

typedef struct {
    PCIDevice    pdev;
    MemoryRegion mmio;

    // used to identify a specific interface
    // when multiple devices are attached
    uint32_t subsystem_id;

    // the socket for host/guest comms
    CharBackend chardev;
    uint8_t     buffer[1024];
    int         buffer_pos;
    int         watch;

    int         sent_fds[MAX_FDS];
    uint32_t    fd_ids[MAX_FDS];
    uint32_t    last_fd_id;

    // mapping state tracking
    bool        finished;
    int         segments;
    int         map_count;
    bool        map_used[MAX_MAPS];
    int         pending_unmap;

    // registers
    PHRegs regs;

} PHState;

// forwards
static void porthole_handle_start(PHState *ph);
static void porthole_handle_add_segment(PHState *ph);
static void porthole_handle_finish(PHState *ph);
static void porthole_handle_unmap(PHState *ph);

static uint64_t porthole_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    PHState *ph = opaque;

    switch(addr >> 2)
    {
        case PH_REG_CR:
            return ph->regs.cr;

        case PH_REG_MSG_ADDR_L:
            return ph->regs.addr & 0xFFFFFFFF;

        case PH_REG_MSG_ADDR_H:
            return (ph->regs.addr >> 32) & 0xFFFFFFFF;

        case PH_REG_MSG_SIZE:
            return ph->regs.size;

        default:
            return 0xFFFFFFFF;
    }
}

static void porthole_mmio_write(void *opaque, hwaddr addr, uint64_t val,
                unsigned size)
{
    PHState *ph = opaque;

    switch(addr >> 2)
    {
        case PH_REG_CR:
        {
            uint32_t old = ph->regs.cr;
            ph->regs.cr = (old & ~PH_REG_CR_CLEAR_MASK) |
                (val & PH_REG_CR_WRITE_MASK);

            if (!(old & PH_REG_CR_START) &&
                (val & PH_REG_CR_START))
                porthole_handle_start(ph);

            if (!(old & PH_REG_CR_ADD_SEGMENT) &&
                (val & PH_REG_CR_ADD_SEGMENT))
                porthole_handle_add_segment(ph);

            if (!(old & PH_REG_CR_FINISH) &&
                (val & PH_REG_CR_FINISH))
                porthole_handle_finish(ph);

            if (!(old & PH_REG_CR_UNMAP) &&
                (val & PH_REG_CR_UNMAP))
                porthole_handle_unmap(ph);

            break;
        }

        case PH_REG_MSG_TYPE:
            if (ph->regs.cr & PH_REG_CR_WRITE_MASK)
                return;

            ph->regs.type = val;
            break;

        case PH_REG_MSG_ADDR_L:
            if (ph->regs.cr & PH_REG_CR_WRITE_MASK)
                return;

            ph->regs.addr = (ph->regs.addr & 0xffffffff00000000) |
                    (val & 0xFFFFFFFF);
            break;

        case PH_REG_MSG_ADDR_H:
            if (ph->regs.cr & PH_REG_CR_WRITE_MASK)
                return;

            ph->regs.addr = (ph->regs.addr & 0xffffffff) |
                    ((val & 0xFFFFFFFF) << 32);
            break;

        case PH_REG_MSG_SIZE:
            if (ph->regs.size & PH_REG_CR_WRITE_MASK)
                return;

            ph->regs.size = val;
            break;
    }
}

static const MemoryRegionOps porthole_mmio_ops = {
    .read       = porthole_mmio_read,
    .write      = porthole_mmio_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4
    }
};

static void porthole_handle_start(PHState *ph)
{
    // check for a chardev connection
    if (!qemu_chr_fe_backend_open(&ph->chardev)) {
        PH_REG_CR_SET_ERR(PH_REG_CR_START, PH_REG_CR_NOCONN);
        return;
    }

    // check if we are out of map slots
    if (ph->map_count == MAX_MAPS) {
        PH_REG_CR_SET_ERR(PH_REG_CR_START, PH_REG_CR_NORES);
        return;
    }

    // send a segment reset message
    PHMsg msg = { .msg = PH_MSG_MAP };
    if (qemu_chr_fe_write_all(&ph->chardev, (const uint8_t *)&msg,
        PH_MSG_MAP_SIZE) != PH_MSG_MAP_SIZE) {
        PH_REG_CR_SET_ERR(PH_REG_CR_START, PH_REG_CR_NOCONN);
        return;
    }

    ph->finished = false;
    ph->segments = 0;
    ph->regs.cr &= ~PH_REG_CR_START;
}

static void porthole_handle_add_segment(PHState *ph)
{
    // check for a chardev connection
    if (!qemu_chr_fe_backend_open(&ph->chardev)) {
        PH_REG_CR_SET_ERR(PH_REG_CR_ADD_SEGMENT, PH_REG_CR_NOCONN);
        return;
    }

    // ensure that there is a mapping in progress
    if (ph->finished) {
        PH_REG_CR_SET_ERR(PH_REG_CR_ADD_SEGMENT, PH_REG_CR_DEVERR);
        return;
    }

    struct MemoryRegion *sysram = get_system_memory();
    struct MemoryRegionSection mrs;

    // lookup the address
    mrs = memory_region_find(sysram, ph->regs.addr,
            ph->regs.size);

    // ensure it's valid, and it's pointing to system RAM
    if (!mrs.mr || !memory_region_is_ram(mrs.mr)) {
        memory_region_unref(mrs.mr);
        PH_REG_CR_SET_ERR(PH_REG_CR_ADD_SEGMENT, PH_REG_CR_BADADDR);
        return;
    }

    // get the fd for the RAM
    int fd = memory_region_get_fd(mrs.mr);
    if (fd == -1) {
        memory_region_unref(mrs.mr);
        PH_REG_CR_SET_ERR(PH_REG_CR_ADD_SEGMENT, PH_REG_CR_BADADDR);
        return;
    }

    // see if we have already sent the fd to the client for this region
    int fd_index = -1;
    int i;
    for(i = 0; i < MAX_FDS && ph->sent_fds[i] != -1; ++i) {
        if (ph->sent_fds[i] == fd) {
            fd_index = i;
            break;
        }
    }

    // check if not found
    if (fd_index == -1) {
      // check if out of room
      if (i == MAX_FDS) {
        memory_region_unref(mrs.mr);
        PH_REG_CR_SET_ERR(PH_REG_CR_ADD_SEGMENT, PH_REG_CR_NORES);
        return;
      }

      // flag fd as sent and set it's ID
      ph->sent_fds[i] = fd;
      ph->fd_ids[i]   = ph->last_fd_id++;

      // send the fd with the id
      PHMsg msg = {
          .msg     = PH_MSG_FD,
          .u.fd.id = ph->fd_ids[i]
      };

      qemu_chr_fe_set_msgfds(&ph->chardev, &fd, 1);
      if (qemu_chr_fe_write_all(&ph->chardev, (const uint8_t *)&msg,
          PH_MSG_FD_SIZE) != PH_MSG_FD_SIZE) {
          memory_region_unref(mrs.mr);
          PH_REG_CR_SET_ERR(PH_REG_CR_ADD_SEGMENT, PH_REG_CR_NOCONN);
          return;
      }
    }

    // send the segment message
    PHMsg msg = {
        .msg             = PH_MSG_SEGMENT,
        .u.segment.fd_id = ph->fd_ids[i],
        .u.segment.addr  = mrs.offset_within_region,
        .u.segment.size  = ph->regs.size
    };

    // release the memory region
    memory_region_unref(mrs.mr);

    // send the segment info
    if (qemu_chr_fe_write_all(&ph->chardev, (const uint8_t *)&msg,
        PH_MSG_SEGMENT_SIZE) != PH_MSG_SEGMENT_SIZE) {
        PH_REG_CR_SET_ERR(PH_REG_CR_ADD_SEGMENT, PH_REG_CR_NOCONN);
        return;
    }

    ++ph->segments;
    ph->regs.cr &= ~PH_REG_CR_ADD_SEGMENT;
}

static void porthole_handle_finish(PHState *ph) {

    // check for a chardev connection
    if (!qemu_chr_fe_backend_open(&ph->chardev)) {
        PH_REG_CR_SET_ERR(PH_REG_CR_FINISH, PH_REG_CR_NOCONN);
        return;
    }

    // check for a zero segment map
    if (ph->segments == 0) {
        PH_REG_CR_SET_ERR(PH_REG_CR_FINISH, PH_REG_CR_DEVERR);
        return;
    }

    // find a free map id
    int i;
    for(i = 0; i < MAX_MAPS; ++i)
      if (!ph->map_used[i])
      {
        ph->map_used[i] = true;
        ph->regs.addr   = i;
        ++ph->map_count;
        break;
      }

    assert(i < MAX_MAPS);

    // send the finish message
    PHMsg msg = {
        .msg           = PH_MSG_FINISH,
        .u.finish.type = ph->regs.type,
        .u.finish.id   = i
    };

    if (qemu_chr_fe_write_all(&ph->chardev, (const uint8_t *)&msg,
        PH_MSG_FINISH_SIZE) != PH_MSG_FINISH_SIZE) {
        PH_REG_CR_SET_ERR(PH_REG_CR_FINISH, PH_REG_CR_NOCONN);
    }

    ph->finished = true;
    ph->segments = 0;
    ph->regs.cr &= ~PH_REG_CR_FINISH;
}

static void porthole_handle_unmap(PHState *ph) {
    // check for a chardev connection
    if (!qemu_chr_fe_backend_open(&ph->chardev)) {
        PH_REG_CR_SET_ERR(PH_REG_CR_UNMAP, PH_REG_CR_NOCONN);
        return;
    }

    uint32_t index = ph->regs.addr & 0xFFFFFFFF;
    if (index > MAX_MAPS || !ph->map_used[index]) {
        PH_REG_CR_SET_ERR(PH_REG_CR_UNMAP, PH_REG_CR_DEVERR);
        return;
    }

    // send the unmap message
    PHMsg msg = {
        .msg        = PH_MSG_UNMAP,
        .u.unmap.id = index,
    };

    ph->pending_unmap = index;
    if (qemu_chr_fe_write_all(&ph->chardev, (const uint8_t *)&msg,
        PH_MSG_UNMAP_SIZE) != PH_MSG_UNMAP_SIZE) {
      PH_REG_CR_SET_ERR(PH_REG_CR_UNMAP, PH_REG_CR_NOCONN);
      return;
    }

    // this completes in `porthole_chr_read` on PH_MSG_UNMAP
}

static int porthole_chr_can_receive(void *opaque)
{
    PHState *ph = opaque;

    return sizeof(ph->buffer) - ph->buffer_pos;
}

static void porthole_chr_read(void *opaque, const uint8_t *buf, int size)
{
    PHState *ph = opaque;

    memcpy(ph->buffer + ph->buffer_pos, buf, size);
    ph->buffer_pos += size;

    // process messages
    uint32_t *msgs = (uint32_t*)ph->buffer;
    int      left  = ph->buffer_pos;

    while(left >= sizeof(uint32_t))
    {
      switch(le32_to_cpu(*msgs))
      {
        case PH_MSG_UNMAP:
          if (ph->pending_unmap == -1)
            break;

          ph->map_used[ph->pending_unmap] = 0;
          ph->regs.cr &= ~PH_REG_CR_UNMAP;
          break;

        default:
          // invalid messages are just ignored for now
          break;
      }

      ++msgs;
      left -= sizeof(uint32_t);
    }

    if (left > 0)
      memmove(ph->buffer, buf, left);

    ph->buffer_pos = left;
}

static gboolean porthole_chr_hup_watch(GIOChannel *chan, GIOCondition cond,
    void *opaque) {
    PHState *ph = opaque;

    qemu_chr_fe_disconnect(&ph->chardev);

    return true;
}

static void porthole_reset(PHState *ph)
{
    if (ph->watch) {
        g_source_remove(ph->watch);
        ph->watch = 0;
    }

    for(int i = 0; i < MAX_FDS; ++i) {
        ph->sent_fds[i] = -1;
    }

    for(int i = 0; i < MAX_MAPS; ++i) {
        ph->map_used[i] = false;
    }

    ph->regs.cr       = PH_REG_CR_NOCONN;
    ph->finished      = true;
    ph->segments      = 0;
    ph->pending_unmap = -1;
}

static void porthole_chr_event(void *opaque, int event)
{
    PHState *ph = opaque;

    switch(event)
    {
        case CHR_EVENT_OPENED:
          ph->watch = qemu_chr_fe_add_watch(&ph->chardev, G_IO_HUP,
              porthole_chr_hup_watch, ph);
          ph->regs.cr &= ~PH_REG_CR_NOCONN;
          break;

        case CHR_EVENT_CLOSED:
          porthole_reset(ph);
          break;
    }
}

static void pci_porthole_realize(PCIDevice *pdev, Error **errp)
{
    PHState *ph = DO_UPCAST(PHState, pdev, pdev);

    if (!qemu_chr_fe_backend_connected(&ph->chardev)) {
        error_setg(errp, "You must specify a 'chardev'");
        return;
    }

    // set the subsystem ID
    pci_set_word(pdev->config + PCI_SUBSYSTEM_ID,
            (ph->subsystem_id >> 16) & 0xFFFF);
    pci_set_word(pdev->config + PCI_SUBSYSTEM_VENDOR_ID,
            ph->subsystem_id & 0xFFFF);

    // setup the communication registers
    memory_region_init_io(&ph->mmio, OBJECT(ph), &porthole_mmio_ops, ph,
            "ph-mmio", PH_REG_LAST << 2);

    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &ph->mmio);

    porthole_reset(ph);

    // setup the chardev
    qemu_chr_fe_set_handlers(&ph->chardev, porthole_chr_can_receive,
            porthole_chr_read, porthole_chr_event, NULL, ph, NULL, true);
}

static void pci_porthole_uninit(PCIDevice *pdev)
{
    PHState *ph = DO_UPCAST(PHState, pdev, pdev);

    if (qemu_chr_fe_backend_open(&ph->chardev))
      qemu_chr_fe_disconnect(&ph->chardev);

    if (ph->watch) {
        g_source_remove(ph->watch);
        ph->watch = 0;
    }
}

static void porthole_instance_init(Object *obj)
{
    PHState *ph = INTRO(obj);

    memset(&ph->regs, 0, sizeof(ph->regs));
    for(int i = 0; i < MAX_FDS; ++i)
      ph->sent_fds[i] = -1;
}

static Property porthole_properties[] = {
    DEFINE_PROP_UINT32("subsystem_id", PHState, subsystem_id, 0),
    DEFINE_PROP_CHR("chardev", PHState, chardev),
    DEFINE_PROP_END_OF_LIST()
};

static void porthole_class_init(ObjectClass *class, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(class);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(class);

    k->realize   = pci_porthole_realize;
    k->exit      = pci_porthole_uninit;
    k->vendor_id = PCI_VENDOR_ID_QEMU;
    k->device_id = 0x10f5;
    k->revision  = 0x10;
    k->class_id  = PCI_CLASS_OTHERS;
    dc->props    = porthole_properties;
}

static const TypeInfo porthole_info = {
  .name          = "porthole",
  .parent        = TYPE_PCI_DEVICE,
  .instance_size = sizeof(PHState),
  .instance_init = porthole_instance_init,
  .abstract      = false,
  .class_init    = porthole_class_init,
  .interfaces    = (InterfaceInfo[]) {
      { INTERFACE_CONVENTIONAL_PCI_DEVICE },
      { },
  }
};

static void pci_porthole_register_types(void)
{
    type_register_static(&porthole_info);
}
type_init(pci_porthole_register_types)