#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h> //for sleep

#include "cjson/cJSON.h"
#include "usb/usb.h"

#define USB_ENDPOINT_OUT 0x00
#define USB_TYPE_CLASS (0x01 << 5)
#define USB_RECIP_INTERFACE 0x01

USB usbObj;

//#define DISABLE_MQTT

extern int mqtt_init(void);
extern int mqtt_deinit(void);
extern int report_to_houston(const char *topic, int qos,
                             const unsigned char *data, size_t length);

static int cypress_command(const char *cmd, char *buf, size_t buflen) {
  char tmp[128];
  int ret;
  size_t i;
  int count;

  memset(tmp, 0, sizeof(tmp));
  snprintf(tmp, sizeof(tmp), "%s", cmd);

  for (i = 0; i < strlen(tmp); i += count) {

    /* Write data in 8-byte chunks */
    /* ret = usb->set_report(udev, 0, (unsigned char *)&tmp[i], 8); */
    ret = USB_ControlTransfer(
        usbObj, USB_ENDPOINT_OUT + USB_TYPE_CLASS + USB_RECIP_INTERFACE, 0x09,
        0x200, 0, &tmp[i], 8, 50000, &count);
    if (ret != USB_SUCCESS) {
      syslog(LOG_ERR, "Write control message failed");
      return -1;
    }
  }

  syslog(LOG_DEBUG, "send: %.*s", (int)strcspn(tmp, "\r"), tmp);

  memset(buf, 0, buflen);

  for (i = 0; (i <= buflen - 8) && (strchr(buf, '\r') == NULL); i += count) {

    /* Read data in 8-byte chunks */
    /* ret = usb->get_interrupt(udev, (unsigned char *)&buf[i], 8, 1000); */
    // ret = USB_InterruptTransfer(usbObj, 0x81, &buf[i], 8, 50000, &count);
    ret = usbObj->Read(usbObj, &buf[i], 8, 50000, &count);

    /*
     * Any errors here mean that we are unable to read a reply (which
     * will happen after successfully writing a command to the UPS)
     */
    if (ret != USB_SUCCESS) {
      syslog(LOG_ERR, "Read response failed");
      return -1;
    }
  }

  syslog(LOG_DEBUG, "read: %.*s", (int)strcspn(buf, "\r"), buf);
  return i;
}

#define SF_FLAGS_VAILD (0x1 << 0)
#define SF_FLAGS_UPDATED (0x1 << 1)

enum value_type {
  VTYPE_DOUBLE,
  VTYPE_INT,
};
union value {
  double val_double;
  unsigned long int val_int;
};

static int conv_strtod(const char *str, union value *val) {
  char *last = NULL;
  assert(val != NULL);

  if (strspn(str, "0123456789.") != strlen(str)) {
    return 1;
  }

  val->val_double = strtod(str, &last);
  return 0;
}

static int conv_strtobin(const char *str, union value *val) {
  int i;
  unsigned int bits = 0;
  assert(val != NULL);

  if (strspn(str, "01\r") != strlen(str)) {
    return 1;
  }

  for (i = 0; i < 8; i++) {
    if (str[i] == '1') {
      bits |= 1 << (7 - i);
    }
  }
  val->val_int = bits;
  return 0;
}

/* 状态字段 */
struct ups_field {
  const char *name;
  enum value_type type;
  union value val;
  int (*conv)(const char *, union value *);
  unsigned int flags; // 标志位
};

struct ups_field status_list[] = {
    {"input_voltage", VTYPE_DOUBLE, {0.0}, conv_strtod, 0},
    {"input_voltage_fault", VTYPE_DOUBLE, {0.0}, conv_strtod, 0},
    {"output_voltage", VTYPE_DOUBLE, {0.0}, conv_strtod, 0},
    {"ups_load", VTYPE_DOUBLE, {0.0}, conv_strtod, 0},
    {"input_frequency", VTYPE_DOUBLE, {0.0}, conv_strtod, 0},
    {"battery_voltage", VTYPE_DOUBLE, {0.0}, conv_strtod, 0},
    {"internal_temperature", VTYPE_DOUBLE, {0.0}, conv_strtod, 0},
    {"ups_status", VTYPE_INT, {0.0}, conv_strtobin, 0},
    {NULL, VTYPE_DOUBLE, {0.0}, NULL, 0}};

struct ups_field rating_list[] = {
    {"input_voltage_nominal", VTYPE_DOUBLE, {0.0}, conv_strtod, 0},
    {"input_current_nominal", VTYPE_DOUBLE, {0.0}, conv_strtod, 0},
    {"battery_voltage_nominal", VTYPE_DOUBLE, {0.0}, conv_strtod, 0},
    {"input_frequency_nominal", VTYPE_DOUBLE, {0.0}, conv_strtod, 0},
    {NULL, VTYPE_DOUBLE, {0.0}, NULL, 0}};

static int parse_fields(char *str, const char *sep, struct ups_field *fields) {
  char *tmp_str = str;
  char *curr_field, *last = NULL;
  int i, update_flag_cnt = 0;
  union value val;

  for (i = 0;
       (curr_field = strsep(&tmp_str, " ")) != NULL && fields[i].name != NULL;
       i++) {
    /* get current state value */
    if (fields[i].conv(curr_field, &val)) {
      syslog(LOG_WARNING, "convert value failed: %s:%s.", fields[i].name,
             curr_field);
      continue;
    }

    if ((fields[i].flags & SF_FLAGS_VAILD) == 0) {
      /* this field not init yet, update it immediately */
      fields[i].flags = SF_FLAGS_VAILD | SF_FLAGS_UPDATED;
      fields[i].val = val;
      update_flag_cnt++;
    } else if (memcmp(&fields[i].val, &val, sizeof(union value)) != 0) {
      fields[i].flags |= SF_FLAGS_UPDATED;
      fields[i].val = val;
      update_flag_cnt++;
    }
  }

  return update_flag_cnt;
}

volatile int exit_flag = 0;
static sem_t update_sem;
static pthread_mutex_t fields_mutex;

static void sig_handler(int signum) {
  syslog(LOG_INFO, "exiting..");
  exit_flag = 1;
}

static void *mqtt_thread_fun(void *vargp) {
  int i, ret, cnt = 0;
  cJSON *root;
  char *json_str;

  /* 将变化的数据通过mqtt发布 */
  while (exit_flag == 0) {
    sem_wait(&update_sem);

    root = cJSON_CreateObject();
    if (root == NULL) {
      syslog(LOG_WARNING, "failed to create json object.");
      continue;
    }

    pthread_mutex_lock(&fields_mutex);
    for (i = 0; status_list[i].name != NULL; i++) {
      if ((status_list[i].flags & SF_FLAGS_UPDATED) == 0 && cnt < 100) {
        continue;
      }
      status_list[i].flags &= ~SF_FLAGS_UPDATED;

      if (status_list[i].type == VTYPE_DOUBLE) {
        if (cJSON_AddNumberToObject(root, status_list[i].name,
                                    status_list[i].val.val_double) == NULL) {
          goto end;
        }
      } else {
        if (cJSON_AddNumberToObject(root, status_list[i].name,
                                    status_list[i].val.val_int) == NULL) {
          goto end;
        }
      }
    }

    /* print the json string */
    json_str = cJSON_PrintUnformatted(root);
    if (json_str == NULL) {
      syslog(LOG_ERR, "make json string failed.");
      goto end;
    }

    /* 每间隔100个消息，就更新全部的字段 */
    if (cnt++ >= 100) {
      cnt = 0;
    }

#ifdef DISABLE_MQTT
    printf("update: %s\n", json_str);
#else
    /* publish via mqtt */
    ret = report_to_houston("home/nj/pukou/power/shanke", 0, json_str,
                            strlen(json_str));
    if (ret < 0) {
      syslog(LOG_WARNING, "report ups status failed: %s", json_str);
    }
#endif

    free(json_str);
  end:
    pthread_mutex_unlock(&fields_mutex);
    cJSON_Delete(root);
  }
  return NULL;
}

int main(void) {
  int ret;
  char buf[128];
  pthread_t mqtt_thread;

  openlog("ups_monitord", LOG_PID | LOG_NDELAY | LOG_CONS, LOG_CONSOLE);
  // setlogmask(LOG_UPTO(LOG_ERR));

  /* 初始化更新发布信号量 */
  sem_init(&update_sem, 0, 0);
  pthread_mutex_init(&fields_mutex, NULL);

  signal(SIGINT, sig_handler); // Register signal handler

#ifndef DISABLE_MQTT
  ret = mqtt_init();
  if (ret < 0) {
    syslog(LOG_ERR, "Can't init MQTT.");
    goto _exit_1;
  }
#endif

  usbObj = CreateUSB();
  if (usbObj == NULL) {
    syslog(LOG_ERR, "Create USB object failed!");
    goto _exit_2;
  }

  // 连接vid:pid-> 0x0665, 0x5161
  ret = USB_Open(usbObj, 0x0665, 0x5161, NULL);
  if (ret != USB_SUCCESS) {
    syslog(LOG_ERR, "Cant open USB device");
    goto _exit_3;
  }

  syslog(LOG_INFO, "connect usb success! reseting usb..");
  USB_Reset(usbObj);

  ret = USB_SetConfiguration(usbObj, 0); // 使用第一个configuration
  if (ret != USB_SUCCESS) {
    syslog(LOG_ERR, "cant set configuration");
    goto _exit_3;
  }

  ret = USB_ClaimInterface(usbObj, 3, 0, 0, 3);
  if (ret != USB_SUCCESS) {
    syslog(LOG_ERR, "claim usb interface faild.");
    goto _exit_3;
  }

  /* 获得Rating信息 */
  while (exit_flag == 0) {
    ret = cypress_command("F\r", buf, sizeof(buf));
    if (ret < 0) {
      syslog(LOG_WARNING, "Get UPS rating failed.");
      sleep(1);
      continue;
    }

    if (buf[0] != '#') {
      syslog(LOG_ERR, "bad rating response format!");
      ret = 1;
      goto _exit_3;
    }

    parse_fields(buf + 1, " ", rating_list);
    break;
  }

  // 打开led设备
  int ledfd = open("/dev/led/nanopi:blue:status", O_WRONLY | O_SYNC);
  if (ledfd <= 0) {
    syslog(LOG_ERR, "open led dev failed!.");
    ret = errno;
    goto _exit_3;
  }

  ret = pthread_create(&mqtt_thread, NULL, mqtt_thread_fun, NULL);
  if (ret < 0) {
    syslog(LOG_ERR, "start mqtt thread failed! %m.");
    ret = errno;

    goto _exit_4;
  }

  while (exit_flag == 0) {
    write(ledfd, "1", 1); // led on
    ret = cypress_command("QS\r", buf, sizeof(buf));
    write(ledfd, "0", 1); // led off

    if (ret < 0) {
      syslog(LOG_WARNING, "Get UPS state failed.");
      sleep(1);
      continue;
    }

    if (buf[0] != '(') {
      syslog(LOG_ERR, "bad status response format!");
      ret = 1;
      goto _exit_5;
    }

    /* parse status */
    pthread_mutex_lock(&fields_mutex);
    ret = parse_fields(buf + 1, " ", status_list);
    pthread_mutex_unlock(&fields_mutex);

    if (ret > 0) {
      sem_post(&update_sem);
    }

    sleep(1);
  }

_exit_5:
  exit_flag = 1;
  sem_post(&update_sem);
  pthread_join(mqtt_thread, NULL);

_exit_4:
  close(ledfd);

_exit_3:
  USB_Close(usbObj);
  DestoryUSB(&usbObj);

_exit_2:
#ifndef DISABLE_MQTT
  mqtt_deinit();
#endif

_exit_1:
  sem_close(&update_sem);
  pthread_mutex_destroy(&fields_mutex);

  syslog(LOG_INFO, "monitor exit.");
  closelog();
  return ret;
}
