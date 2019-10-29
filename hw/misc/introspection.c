/*
 * QEMU introspection PCI device
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

#define INTRO(obj) OBJECT_CHECK(IntroState, obj, "introspection")

/*
  Register defines

  SW = Software
  HW = Hardware
  S  = Set
  C  = Clear
*/

#define REG_STATUS_WRITE_MASK (0x0)

#define REG_MSG_CR_RESET       (1 << 1) // SW=S, HW=C
#define REG_MSG_CR_ADD_SEGMENT (1 << 2) // SW=S, HW=C
#define REG_MSG_CR_FINISH      (1 << 3) // SW=S, HW=C
#define REG_MSG_CR_TIMEOUT     (1 << 4) // HW=S, HW=C
#define REG_MSG_CR_BADADDR     (1 << 5) // HW=S, HW=C
#define REG_MSG_CR_NOCONN      (1 << 6) // HW=S, HW=C

#define REG_MSG_CR_WRITE_MASK ( \
    REG_MSG_CR_RESET       | \
    REG_MSG_CR_ADD_SEGMENT | \
    REG_MSG_CR_FINISH      | \
    0x0 \
)

#define REG_MSG_CR_CLEAR_MASK ( \
    REG_MSG_CR_TIMEOUT | \
    REG_MSG_CR_BADADDR | \
    REG_MSG_CR_NOCONN  | \
    0x0 \
)

/*
  Socket communication defines
*/

typedef struct {
  uint64_t id;
} __attribute__ ((packed)) MsgFd;

typedef struct {
  uint64_t fd_id;
  uint64_t addr;
  uint32_t size;
} __attribute__ ((packed)) MsgSegment;

typedef struct {
  uint32_t type;
} __attribute__ ((packed)) MsgFinish;

typedef struct {
  uint32_t msg;
  union
  {
    MsgFd      fd;
    MsgSegment segment;
    MsgFinish  finish;
  } u;
} __attribute__ ((packed)) Msg;

#define INTRO_MSG_RESET   0x1
#define INTRO_MSG_FD      0x2
#define INTRO_MSG_SEGMENT 0x3
#define INTRO_MSG_FINISH  0x4

#define INTRO_MSG_RESET_SIZE   (sizeof(uint32_t))
#define INTRO_MSG_FD_SIZE      (sizeof(uint32_t) + sizeof(MsgFd))
#define INTRO_MSG_SEGMENT_SIZE (sizeof(uint32_t) + sizeof(MsgSegment))
#define INTRO_MSG_FINISH_SIZE  (sizeof(uint32_t) + sizeof(MsgFinish))

// all registers are 32-bit
enum IntoRegs {
    // reserved for possible future use
    INTRO_REG_STATUS = 0,

    // guest to host transfer, maximum one page (4kb)
    // registers are readonly while REG_STATUS_MSG_WRITE is set
    INTRO_REG_MSG_CR,
    INTRO_REG_MSG_TYPE,
    INTRO_REG_MSG_ADDR_L,
    INTRO_REG_MSG_ADDR_H,
    INTRO_REG_MSG_SIZE,

    INTRO_REG_RESERVED1,
    INTRO_REG_RESERVED2,

    INTRO_REG_LAST
};

typedef struct {
    uint32_t cr;
    uint32_t type;
    hwaddr   addr;
    uint32_t size;
} MsgRegs;

#define MAX_FDS 16

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

    // registers
    uint32_t status;
    MsgRegs  msg;

} IntroState;

// forwards
static void intro_handle_reset(IntroState *intro);
static void intro_handle_add_segment(IntroState *intro);
static void intro_handle_finish(IntroState *intro);

static uint64_t intro_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    IntroState *intro = opaque;

    switch(addr >> 2)
    {
        case INTRO_REG_STATUS:
            return intro->status;

        case INTRO_REG_MSG_CR:
            return intro->msg.cr;

        case INTRO_REG_MSG_ADDR_L:
            return intro->msg.addr & 0xFFFFFFFF;

        case INTRO_REG_MSG_ADDR_H:
            return (intro->msg.addr >> 32) & 0xFFFFFFFF;

        case INTRO_REG_MSG_SIZE:
            return intro->msg.size;

        default:
            return 0xFFFFFFFF;
    }
}

static void intro_mmio_write(void *opaque, hwaddr addr, uint64_t val,
                unsigned size)
{
    IntroState *intro = opaque;

    switch(addr >> 2)
    {
        case INTRO_REG_STATUS:
            intro->status |= val & REG_STATUS_WRITE_MASK;
            break;

        case INTRO_REG_MSG_CR:
        {
            uint32_t old = intro->msg.cr;
            intro->msg.cr = (old & ~REG_MSG_CR_CLEAR_MASK) |
                (val & REG_MSG_CR_WRITE_MASK);

            if (!(old & REG_MSG_CR_RESET) && (val & REG_MSG_CR_RESET))
                intro_handle_reset(intro);

            if (!(old & REG_MSG_CR_ADD_SEGMENT) && (val & REG_MSG_CR_ADD_SEGMENT))
                intro_handle_add_segment(intro);

            if (!(old & REG_MSG_CR_FINISH) && (val & REG_MSG_CR_FINISH))
                intro_handle_finish(intro);

            break;
        }

        case INTRO_REG_MSG_TYPE:
            if (intro->msg.cr & REG_STATUS_WRITE_MASK)
                return;

            intro->msg.type = val;
            break;

        case INTRO_REG_MSG_ADDR_L:
            if (intro->msg.cr & REG_STATUS_WRITE_MASK)
                return;

            intro->msg.addr = (intro->msg.addr & 0xffffffff00000000) |
                    (val & 0xFFFFFFFF);
            break;

        case INTRO_REG_MSG_ADDR_H:
            if (intro->msg.cr & REG_STATUS_WRITE_MASK)
                return;

            intro->msg.addr = (intro->msg.addr & 0xffffffff) |
                    ((val & 0xFFFFFFFF) << 32);
            break;

        case INTRO_REG_MSG_SIZE:
            if (intro->msg.size & REG_STATUS_WRITE_MASK)
                return;

            intro->msg.size = val;
            break;
    }
}

static const MemoryRegionOps intro_mmio_ops = {
    .read       = intro_mmio_read,
    .write      = intro_mmio_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4
    }
};

static void intro_handle_reset(IntroState *intro)
{
    // check for a chardev connection
    if (!qemu_chr_fe_backend_open(&intro->chardev)) {
      intro->msg.cr = (intro->msg.cr & ~REG_MSG_CR_RESET) | REG_MSG_CR_NOCONN;
      return;
    }

    // send a segment reset message
    Msg msg = { .msg = INTRO_MSG_RESET };
    if (qemu_chr_fe_write_all(&intro->chardev, (const uint8_t *)&msg,
        INTRO_MSG_RESET_SIZE) != INTRO_MSG_RESET_SIZE) {
      intro->msg.cr |= REG_MSG_CR_NOCONN;
    }

    intro->msg.cr &= ~REG_MSG_CR_RESET;
}

static void intro_handle_add_segment(IntroState *intro)
{
    // check for a chardev connection
    if (!qemu_chr_fe_backend_open(&intro->chardev)) {
      intro->msg.cr = (intro->msg.cr & ~REG_MSG_CR_ADD_SEGMENT) | REG_MSG_CR_NOCONN;
      return;
    }

    struct MemoryRegion *sysram = get_system_memory();
    struct MemoryRegionSection mrs;

    // lookup the address
    mrs = memory_region_find(sysram, intro->msg.addr,
            intro->msg.size);

    // ensure it's valid, and it's pointing to system RAM
    if (!mrs.mr || !memory_region_is_ram(mrs.mr)) {
      memory_region_unref(mrs.mr);
      intro->msg.cr = (intro->msg.cr & ~REG_MSG_CR_ADD_SEGMENT) | REG_MSG_CR_BADADDR;
      return;
    }

    // get the fd for the RAM
    int fd = memory_region_get_fd(mrs.mr);
    if (fd == -1) {
      memory_region_unref(mrs.mr);
      intro->msg.cr = (intro->msg.cr & ~REG_MSG_CR_ADD_SEGMENT) | REG_MSG_CR_BADADDR;
      return;
    }

    // see if we have already sent the fd to the client for this region
    int i;
    int fd_index = -1;
    for(i = 0; i < MAX_FDS && intro->sent_fds[i] != -1; ++i) {
      if (intro->sent_fds[i] == fd) {
        fd_index = i;
        break;
      }
    }

    // check if not found
    if (fd_index == -1) {
      // check if out of room
      if (i == MAX_FDS) {
        memory_region_unref(mrs.mr);
        intro->msg.cr = (intro->msg.cr & ~REG_MSG_CR_ADD_SEGMENT) | REG_MSG_CR_BADADDR;
        return;
      }

      // flag fd as sent
      intro->sent_fds[i] = fd;

      // send the fd with the id
      Msg msg = {
        .msg     = INTRO_MSG_FD,
        .u.fd.id = memory_region_get_ram_addr(mrs.mr)
      };

      qemu_chr_fe_set_msgfds(&intro->chardev, &fd, 1);
      if (qemu_chr_fe_write_all(&intro->chardev, (const uint8_t *)&msg,
          INTRO_MSG_FD_SIZE) != INTRO_MSG_FD_SIZE) {
        memory_region_unref(mrs.mr);
        intro->msg.cr = (intro->msg.cr & ~REG_MSG_CR_ADD_SEGMENT) | REG_MSG_CR_BADADDR;
        return;
      }
    }

    // send the segment message
    Msg msg = {
      .msg            = INTRO_MSG_SEGMENT,
      .u.segment.addr = mrs.offset_within_region,
      .u.segment.size = intro->msg.size
    };

    // release the memory region
    memory_region_unref(mrs.mr);

    // send the segment info
    if (qemu_chr_fe_write_all(&intro->chardev, (const uint8_t *)&msg,
        INTRO_MSG_SEGMENT_SIZE) != INTRO_MSG_SEGMENT_SIZE) {
      intro->msg.cr |= REG_MSG_CR_NOCONN;
    }

    intro->msg.cr &= ~REG_MSG_CR_ADD_SEGMENT;
}

static void intro_handle_finish(IntroState *intro) {

    // check for a chardev connection
    if (!qemu_chr_fe_backend_open(&intro->chardev)) {
      intro->msg.cr = (intro->msg.cr & ~REG_MSG_CR_FINISH) | REG_MSG_CR_NOCONN;
      return;
    }

    // send the finish message
    Msg msg = {
      .msg           = INTRO_MSG_FINISH,
      .u.finish.type = intro->msg.type
    };
    if (qemu_chr_fe_write_all(&intro->chardev, (const uint8_t *)&msg,
        INTRO_MSG_FINISH_SIZE) != INTRO_MSG_FINISH_SIZE) {
      intro->msg.cr |= REG_MSG_CR_NOCONN;
    }

    intro->msg.cr &= ~REG_MSG_CR_FINISH;
}

static int intro_chr_can_receive(void *opaque)
{
    IntroState *intro = opaque;

    return sizeof(intro->buffer) - intro->buffer_pos;
}

static void intro_chr_read(void *opaque, const uint8_t *buf, int size)
{
    IntroState *intro = opaque;

    memcpy(intro->buffer + intro->buffer_pos, buf, size);
    intro->buffer_pos += size;

    // process messages
    uint32_t *msgs = (uint32_t*)intro->buffer;
    int      left  = intro->buffer_pos;

    while(left >= sizeof(uint32_t))
    {
      switch(le32_to_cpu(*msgs))
      {
        default:
          // invalid messages are just ignored for now
          break;
      }

      ++msgs;
      left -= sizeof(uint32_t);
    }

    if (left > 0)
      memmove(intro->buffer, buf, left);

    intro->buffer_pos = left;
}

static gboolean intro_chr_hup_watch(GIOChannel *chan, GIOCondition cond, void *opaque) {
    IntroState *intro = opaque;

    qemu_chr_fe_disconnect(&intro->chardev);

    return true;
}

static void intro_chr_event(void *opaque, int event)
{
    IntroState *intro = opaque;

    switch(event)
    {
        case CHR_EVENT_OPENED:
          intro->watch = qemu_chr_fe_add_watch(&intro->chardev, G_IO_HUP,
              intro_chr_hup_watch, intro);
          break;

        case CHR_EVENT_CLOSED:
          // if there was a message in progress, complete it and set the noconn error flag
          if (intro->msg.cr & REG_MSG_CR_WRITE_MASK)
            intro->msg.cr = (intro->msg.cr & ~REG_MSG_CR_WRITE_MASK) | REG_MSG_CR_NOCONN;

          if (intro->watch) {
              g_source_remove(intro->watch);
              intro->watch = 0;
          }

          for(int i = 0; i < MAX_FDS; ++i)
            intro->sent_fds[i] = -1;

          break;
    }
}

static void pci_intro_realize(PCIDevice *pdev, Error **errp)
{
    IntroState *intro = DO_UPCAST(IntroState, pdev, pdev);

    if (!qemu_chr_fe_backend_connected(&intro->chardev)) {
        error_setg(errp, "You must specify a 'chardev'");
        return;
    }

    // set the subsystem ID
    pci_set_word(pdev->config + PCI_SUBSYSTEM_ID,
            (intro->subsystem_id >> 16) & 0xFFFF);
    pci_set_word(pdev->config + PCI_SUBSYSTEM_VENDOR_ID,
            intro->subsystem_id & 0xFFFF);

    // setup the communication registers
    memory_region_init_io(&intro->mmio, OBJECT(intro), &intro_mmio_ops, intro,
            "intro-mmio", INTRO_REG_LAST << 2);

    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &intro->mmio);

    intro->watch  = 0;
    intro->status = 0x0;
    intro->msg.cr = 0x0;

    // setup the chardev
    qemu_chr_fe_set_handlers(&intro->chardev, intro_chr_can_receive,
            intro_chr_read, intro_chr_event, NULL, intro, NULL, true);
}

static void pci_intro_uninit(PCIDevice *pdev)
{
    IntroState *intro = DO_UPCAST(IntroState, pdev, pdev);

    if (qemu_chr_fe_backend_open(&intro->chardev))
      qemu_chr_fe_disconnect(&intro->chardev);

    if (intro->watch) {
        g_source_remove(intro->watch);
        intro->watch = 0;
    }
}

static void intro_instance_init(Object *obj)
{
    IntroState *intro = INTRO(obj);

    memset(&intro->msg, 0, sizeof(intro->msg));
    for(int i = 0; i < MAX_FDS; ++i)
      intro->sent_fds[i] = -1;
}

static Property intro_properties[] = {
    DEFINE_PROP_UINT32("subsystem_id", IntroState, subsystem_id, 0),
    DEFINE_PROP_CHR("chardev", IntroState, chardev),
    DEFINE_PROP_END_OF_LIST()
};

static void intro_class_init(ObjectClass *class, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(class);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(class);

    k->realize   = pci_intro_realize;
    k->exit      = pci_intro_uninit;
    k->vendor_id = PCI_VENDOR_ID_QEMU;
    k->device_id = 0x10f5;
    k->revision  = 0x10;
    k->class_id  = PCI_CLASS_OTHERS;
    dc->props    = intro_properties;
}

static const TypeInfo intro_info = {
  .name          = "introspection",
  .parent        = TYPE_PCI_DEVICE,
  .instance_size = sizeof(IntroState),
  .instance_init = intro_instance_init,
  .abstract      = false,
  .class_init    = intro_class_init,
  .interfaces    = (InterfaceInfo[]) {
      { INTERFACE_CONVENTIONAL_PCI_DEVICE },
      { },
  }
};

static void pci_intro_register_types(void)
{
    type_register_static(&intro_info);
}
type_init(pci_intro_register_types)