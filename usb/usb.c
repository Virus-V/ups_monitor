/**
 * src/Library/usb/usb.c
 * Copyright (c) 2020 Virus.V <virusv@live.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "common.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "private_usb.h"

static int bulkWrite(USB self, unsigned char *data, int dataLength, int timeout,
                     int *transferred);
static int bulkRead(USB self, unsigned char *data, int dataLength, int timeout,
                    int *transferred);
static int interruptWrite(USB self, unsigned char *data, int dataLength,
                          int timeout, int *transferred);
static int interruptRead(USB self, unsigned char *data, int dataLength,
                         int timeout, int *transferred);
static int unsupportRW(USB self, unsigned char *data, int dataLength,
                       int timeout, int *transferred);

/**
 * 检查设备的序列号与指定序列号是否一致
 */
static int usbStrDescriptorMatch(libusb_device_handle *devHandle,
                                 uint8_t descIndex, const char *snString) {
  int retcode;
  // 描述字符串缓冲区
  char descString[256 + 1]; // XXX 较大的数组在栈中分配！

  if (descIndex == 0)
    return USB_ERR_BAD_PARAMETER;

  retcode = libusb_get_string_descriptor_ascii(devHandle, descIndex,
                                               (unsigned char *)descString,
                                               sizeof(descString) - 1);
  if (retcode < 0) {
    syslog(LOG_ERR, "libusb_get_string_descriptor_ascii() return code:%d",
           retcode);
    return USB_ERR_INTERNAL_ERROR;
  }
  // 截断字符串
  descString[256] = 0;

  if (strncmp(snString, descString, sizeof(descString)) != 0) {
    syslog(
        LOG_WARNING,
        "The device serial number '%s' is different from the specified serial "
        "number '%s'.",
        descString, snString);
    return USB_FAILED;
  } else
    return USB_SUCCESS;
}

/**
 * 根据pid和vid打开USB设备
 */
int USB_Open(USB self, const uint16_t vid, const uint16_t pid,
             const char *serial) {
  assert(self != NULL);

  struct _usb_private *usbObj =
      container_of(self, struct _usb_private, usbInterface);
  int devCount, index;
  libusb_device_handle *devHandle = NULL;

  // 获得USB设备总数
  devCount = libusb_get_device_list(usbObj->libusbContext, &usbObj->devs);
  if (devCount < 0) {
    syslog(LOG_ERR, "libusb_get_device_list() failed. error:%s.",
           libusb_error_name(devCount));
    return USB_ERR_INTERNAL_ERROR;
  } else {
    syslog(LOG_DEBUG, "Found %d usb devices.", devCount);
  }

  for (index = 0; index < devCount; index++) {
    struct libusb_device_descriptor devDesc_tmp;
    int retCode;

    if (libusb_get_device_descriptor(usbObj->devs[index], &devDesc_tmp) != 0)
      continue;

    // 检查该usb设备
    if (devDesc_tmp.idProduct != pid || devDesc_tmp.idVendor != vid)
      continue;

    retCode = libusb_open(usbObj->devs[index], &devHandle);

    if (retCode) {
      syslog(LOG_WARNING, "libusb_open() error:%s,vid:%x,pid:%x.",
             libusb_error_name(retCode), devDesc_tmp.idVendor,
             devDesc_tmp.idProduct);
      continue;
    }
    // 检查设备序列号
    if (serial != NULL &&
        USB_SUCCESS != usbStrDescriptorMatch(
                           devHandle, devDesc_tmp.iSerialNumber, serial)) {
      libusb_close(devHandle);
      continue;
    }
    // FIXME 程序结束后，无法自动连接到内核驱动
    retCode = libusb_set_auto_detach_kernel_driver(devHandle, 1);
    if (LIBUSB_ERROR_NOT_SUPPORTED == retCode) {
      syslog(LOG_WARNING,
             "The current operating system does not support automatic detach "
             "kernel drive.");
    }
    // 获得当前默认的configuration
    retCode = libusb_get_configuration(devHandle, &usbObj->currConfVal);
    if (retCode < 0) {
      syslog(LOG_WARNING, "libusb_get_configuration():%s",
             libusb_error_name(retCode));
    }
    // 找到设备，初始化USB对象
    usbObj->devHandle = devHandle;
    usbObj->Pid = devDesc_tmp.idProduct;
    usbObj->Vid = devDesc_tmp.idVendor;
    usbObj->SerialNum = serial ? strdup(serial) : NULL;

    // 释放设备列表
    libusb_free_device_list(usbObj->devs, 1);
    return USB_SUCCESS;
  }
  return USB_ERR_NOT_FOUND;
}

// 关闭USB
void USB_Close(USB self) {
  assert(self != NULL);
  struct _usb_private *usbObj =
      container_of(self, struct _usb_private, usbInterface);
  assert(usbObj->devHandle != NULL);

  /* 释放interface */
  if (usbObj->clamedIFNum != -1) {
    libusb_release_interface(usbObj->devHandle, usbObj->clamedIFNum);
    usbObj->clamedIFNum = -1;
  }
  /* Close device */
  libusb_close(usbObj->devHandle);
  usbObj->devHandle = NULL;
  // 清除配置
  usbObj->currConfVal = -1;
  // 禁止写入
  usbObj->usbInterface.Read = usbObj->usbInterface.Write = unsupportRW;
}

/**
 * 复位设备
 */
int USB_Reset(USB self) {
  assert(self != NULL);
  struct _usb_private *usbObj =
      container_of(self, struct _usb_private, usbInterface);
  assert(usbObj->devHandle != NULL);
  int retCode = libusb_reset_device(usbObj->devHandle);
  if (retCode == 0) {
    return USB_SUCCESS;
  } else {
    syslog(LOG_ERR, "libusb_reset_device():%s", libusb_error_name(retCode));
    return USB_ERR_INTERNAL_ERROR;
  }
}

/**
 * USB控制传输
 */
int USB_ControlTransfer(USB self, uint8_t requestType, uint8_t request,
                        uint16_t wValue, uint16_t wIndex, unsigned char *data,
                        uint16_t dataLength, unsigned int timeout, int *count) {
  assert(self != NULL);
  struct _usb_private *usbObj =
      container_of(self, struct _usb_private, usbInterface);
  assert(usbObj->devHandle != NULL);

  *count = libusb_control_transfer(usbObj->devHandle, requestType, request,
                                   wValue, wIndex, data, dataLength, timeout);
  if (*count < 0) {
    syslog(LOG_ERR, "libusb_control_transfer():%s", libusb_error_name(*count));
    *count = 0;
    return USB_ERR_INTERNAL_ERROR;
  }
  return USB_SUCCESS;
}

/**
 * 读/写数据块
 */
int USB_BulkTransfer(USB self, uint8_t endpoint, unsigned char *data,
                     int dataLength, int timeout, int *transferred) {
  int retCode;
  assert(self != NULL);
  struct _usb_private *usbObj =
      container_of(self, struct _usb_private, usbInterface);
  assert(usbObj->devHandle != NULL);

  retCode = libusb_bulk_transfer(usbObj->devHandle, endpoint, data, dataLength,
                                 transferred, timeout);
  if (retCode < 0) {
    syslog(LOG_ERR, "libusb_bulk_transfer():%s", libusb_error_name(retCode));
    return USB_ERR_INTERNAL_ERROR;
  }
  return USB_SUCCESS;
}

static int bulkWrite(USB self, unsigned char *data, int dataLength, int timeout,
                     int *transferred) {
  int tmp, result;
  assert(self != NULL);
  struct _usb_private *usbObj =
      container_of(self, struct _usb_private, usbInterface);
  // 向默认写端点发送数据
  result = USB_BulkTransfer(self, usbObj->writeEP, data, dataLength, timeout,
                            transferred);
  if (USB_SUCCESS != result) {
    return result;
  }
  // 如果写入的数据长度正好等于EP Max pack
  // Size的整数倍，则发送0长度告诉对端传输完成
  if (dataLength % usbObj->writeEPMaxPackSize == 0) {
    result = USB_BulkTransfer(self, usbObj->writeEP, data, 0, timeout, &tmp);
    if (USB_SUCCESS != result) {
      return result;
    }
  }
  return USB_SUCCESS;
}

static int bulkRead(USB self, unsigned char *data, int dataLength, int timeout,
                    int *transferred) {
  assert(self != NULL);
  struct _usb_private *usbObj =
      container_of(self, struct _usb_private, usbInterface);
  return USB_BulkTransfer(self, usbObj->readEP, data, dataLength, timeout,
                          transferred);
}

/**
 * 中断传输
 */
int USB_InterruptTransfer(USB self, uint8_t endpoint, unsigned char *data,
                          int dataLength, int timeout, int *transferred) {
  int retCode;
  assert(self != NULL);
  struct _usb_private *usbObj =
      container_of(self, struct _usb_private, usbInterface);
  assert(usbObj->devHandle != NULL);

  retCode = libusb_interrupt_transfer(usbObj->devHandle, endpoint, data,
                                      dataLength, transferred, timeout);
  if (retCode < 0) {
    syslog(LOG_ERR, "libusb_interrupt_transfer():%s",
           libusb_error_name(retCode));
    return USB_ERR_INTERNAL_ERROR;
  }
  return USB_SUCCESS;
}

static int interruptWrite(USB self, unsigned char *data, int dataLength,
                          int timeout, int *transferred) {
  int tmp, result;
  assert(self != NULL);
  struct _usb_private *usbObj =
      container_of(self, struct _usb_private, usbInterface);

  result = USB_InterruptTransfer(self, usbObj->writeEP, data, dataLength,
                                 timeout, transferred);
  if (USB_SUCCESS != result) {
    return result;
  }
  // 如果写入的数据长度正好等于EP Max pack
  // Size的整数倍，则发送0长度告诉对端传输完成
  if (dataLength % usbObj->writeEPMaxPackSize == 0) {
    result = USB_InterruptTransfer(self, usbObj->writeEP, data, 0, timeout,
                                   transferred);
    if (USB_SUCCESS != result) {
      return result;
    }
  }
  return USB_SUCCESS;
}

static int interruptRead(USB self, unsigned char *data, int dataLength,
                         int timeout, int *transferred) {
  assert(self != NULL);
  struct _usb_private *usbObj =
      container_of(self, struct _usb_private, usbInterface);
  return USB_InterruptTransfer(self, usbObj->readEP, data, dataLength, timeout,
                               transferred);
}

static int unsupportRW(USB self, unsigned char *data, int dataLength,
                       int timeout, int *transferred) {
  (void)self;
  (void)data;
  (void)dataLength;
  (void)timeout;
  syslog(
      LOG_WARNING,
      "An endpoint with an unsupported type has been operated or the endpoint "
      "has been shut down.");
  return USB_ERR_UNSUPPORT;
}

/**
 * 设置活跃配置
 * configurationValue: 配置的索引，第一个配置索引为0
 */
int USB_SetConfiguration(USB self, uint8_t configurationIndex) {
  struct libusb_config_descriptor *config = NULL;
  int retCode;
  libusb_device *dev = NULL;
  assert(self != NULL);
  struct _usb_private *usbObj =
      container_of(self, struct _usb_private, usbInterface);

  assert(usbObj->devHandle != NULL);

  // 获得Device
  dev = libusb_get_device(usbObj->devHandle);

  // 获取当前配置
  // output location for the bConfigurationValue of the active configuration
  // (only valid for return code 0)
  retCode = libusb_get_configuration(usbObj->devHandle, &usbObj->currConfVal);
  if (retCode < 0) {
    syslog(LOG_ERR, "libusb_get_configuration():%s",
           libusb_error_name(retCode));
    return USB_ERR_INTERNAL_ERROR;
  }
  // 判断是否已经claim interface，如果claim interface要先release
  if (usbObj->clamedIFNum != -1) {
    syslog(LOG_INFO, "Release declared interface %d.", usbObj->clamedIFNum);
    retCode = libusb_release_interface(usbObj->devHandle, usbObj->clamedIFNum);
    if (retCode < 0) {
      syslog(LOG_ERR, "libusb_release_interface():%s",
             libusb_error_name(retCode));
      return USB_ERR_INTERNAL_ERROR;
    }
    usbObj->clamedIFNum = -1;
  }

  retCode = libusb_get_config_descriptor(dev, configurationIndex, &config);
  if (retCode < 0) {
    syslog(LOG_ERR, "libusb_get_config_descriptor():%s",
           libusb_error_name(retCode));
    return USB_ERR_INTERNAL_ERROR;
  }
  if (usbObj->currConfVal != config->bConfigurationValue) {
    if ((retCode = libusb_set_configuration(usbObj->devHandle,
                                            config->bConfigurationValue)) < 0) {
      syslog(LOG_ERR, "libusb_set_configuration():%s",
             libusb_error_name(retCode));
      libusb_free_config_descriptor(config);
      return USB_ERR_INTERNAL_ERROR;
    }
    usbObj->currConfVal = config->bConfigurationValue;
  } else {
    syslog(
        LOG_INFO,
        "Currently it is configuration indexed by:%d, bConfigurationValue is "
        "%x.",
        configurationIndex, usbObj->currConfVal);
  }
  // 释放
  libusb_free_config_descriptor(config);
  return USB_SUCCESS;
}

/**
 * 声明interface
 */
int USB_ClaimInterface(USB self, uint8_t IFClass, uint8_t IFSubclass,
                       uint8_t IFProtocol, uint8_t transType) {
  struct libusb_device *dev = NULL;
  struct libusb_config_descriptor *config;
  int retCode;

  assert(self != NULL);
  struct _usb_private *usbObj =
      container_of(self, struct _usb_private, usbInterface);

  assert(usbObj->devHandle != NULL);

  if (usbObj->currConfVal == -1) {
    syslog(LOG_ERR, "The active configuration doesn't set.");
    return USB_ERR_BAD_PARAMETER;
  }

  dev = libusb_get_device(usbObj->devHandle);
  retCode =
      libusb_get_config_descriptor_by_value(dev, usbObj->currConfVal, &config);
  if (retCode != 0) {
    syslog(LOG_ERR, "libusb_get_config_descriptor():%s",
           libusb_error_name(retCode));
    return USB_ERR_INTERNAL_ERROR;
  }

  for (int i = 0; i < (int)config->bNumInterfaces; i++) {
    // 获得interface
    const struct libusb_interface *interface = &config->interface[i];
    const struct libusb_interface_descriptor *interfaceDesc =
        &interface->altsetting[0];
    // XXX altsetting的理解或许有问题
    if (interface->num_altsetting > 1) {
      syslog(LOG_INFO, "The interface has more than one settings.");
    }

    // 匹配class
    if (interfaceDesc->bInterfaceClass != IFClass ||
        interfaceDesc->bInterfaceSubClass != IFSubclass ||
        interfaceDesc->bInterfaceProtocol != IFProtocol) {
      continue;
    }
    if (usbObj->clamedIFNum == interfaceDesc->bInterfaceNumber) {
      syslog(LOG_INFO, "Currently it is interface %d.", usbObj->clamedIFNum);
      return USB_SUCCESS;
    }
    // 判断是否已经声明了interface，如果声明了与当前不同的interface，则释放原来的
    if (usbObj->clamedIFNum != -1) {
      syslog(LOG_INFO, "Release declared interface %d.", usbObj->clamedIFNum);
      retCode =
          libusb_release_interface(usbObj->devHandle, usbObj->clamedIFNum);
      if (retCode < 0) {
        syslog(LOG_ERR, "libusb_release_interface():%s",
               libusb_error_name(retCode));
        return USB_ERR_INTERNAL_ERROR;
      }
      usbObj->clamedIFNum = -1;
    }

    for (int k = 0; k < (int)interfaceDesc->bNumEndpoints; k++) {
      uint8_t epNum; // 端点号
      const struct libusb_endpoint_descriptor *epDesc;

      epDesc = &interfaceDesc->endpoint[k];

      if ((epDesc->bmAttributes & 0x3) != transType)
        continue;

      epNum = epDesc->bEndpointAddress;

      if (epNum & 0x80) {
        usbObj->readEP = epNum;
        // 获得传输的包大小
        usbObj->readEPMaxPackSize = epDesc->wMaxPacketSize & 0x7ff;
        INTERFACE_CONST_INIT(uint16_t, usbObj->usbInterface.readMaxPackSize,
                             usbObj->readEPMaxPackSize);
        syslog(LOG_DEBUG,
               "usb end point 'in' 0x%02x, max packet size %d bytes.", epNum,
               usbObj->readEPMaxPackSize);
      } else {
        usbObj->writeEP = epNum;
        usbObj->writeEPMaxPackSize = epDesc->wMaxPacketSize & 0x7ff;
        INTERFACE_CONST_INIT(uint16_t, usbObj->usbInterface.writeMaxPackSize,
                             usbObj->writeEPMaxPackSize);
        syslog(LOG_DEBUG,
               "usb end point 'out' 0x%02x, max packet size %d bytes.", epNum,
               usbObj->writeEPMaxPackSize);
      }

      // XXX 端点0只用做配置传输
      if (usbObj->readEP || usbObj->writeEP) {
        // 写入回调
        switch (transType) {
        case 3: //中断传输
          usbObj->usbInterface.Write =
              usbObj->writeEP ? interruptWrite : unsupportRW;
          usbObj->usbInterface.Read =
              usbObj->readEP ? interruptRead : unsupportRW;
          break;

        case 2: // 批量传输
          usbObj->usbInterface.Write =
              usbObj->writeEP ? bulkWrite : unsupportRW;
          usbObj->usbInterface.Read = usbObj->readEP ? bulkRead : unsupportRW;
          break;
        default:
          usbObj->usbInterface.Write = usbObj->usbInterface.Read = unsupportRW;
          syslog(LOG_INFO, "Unsupported endpoint type.");
        }

        usbObj->clamedIFNum = interfaceDesc->bInterfaceNumber;
        syslog(LOG_DEBUG, "Claiming interface %d",
               (int)interfaceDesc->bInterfaceNumber);
        libusb_claim_interface(usbObj->devHandle,
                               (int)interfaceDesc->bInterfaceNumber);
        libusb_free_config_descriptor(config);
        return USB_SUCCESS;
      }

    } // for (int k = 0; k < (int)interfaceDesc->bNumEndpoints; k++)
  }   // for (int i = 0; i < (int)config->bNumInterfaces; i++)
  libusb_free_config_descriptor(config);

  return USB_ERR_NOT_FOUND;
}

/**
 * 创建USB对象
 */
USB CreateUSB(void) {
  struct _usb_private *usbObj = calloc(1, sizeof(struct _usb_private));
  if (!usbObj) {
    syslog(LOG_ERR, "CreateUSB:Can not create object!");
    return NULL;
  }
  if (libusb_init(&usbObj->libusbContext) < 0) {
    syslog(LOG_ERR, "libusb_init() failed.");
    free(usbObj);
    return NULL;
  }
  // 填入初始接口
  usbObj->usbInterface.Read = usbObj->usbInterface.Write = unsupportRW;
  usbObj->clamedIFNum = usbObj->currConfVal = -1;
  return (USB)&usbObj->usbInterface;
}

/*
 * 销毁USB对象
 */
void DestoryUSB(USB *self) {
  assert(*self != NULL);
  struct _usb_private *usbObj =
      container_of(*self, struct _usb_private, usbInterface);
  assert(usbObj->libusbContext != NULL);
  libusb_exit(usbObj->libusbContext);
  free(usbObj);
  *self = NULL;
}
