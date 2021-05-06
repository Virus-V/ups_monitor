#ifndef _COMMON_H_
#define _COMMON_H_

#include <assert.h>
#include <inttypes.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef HAVE_CONFIG
#include "global_config.h"
#endif

// 定义offsetof宏
#ifndef offsetof
#define offsetof(type, member) (size_t) & (((type *)0)->member)
#endif
// 定义container_of宏
#ifndef container_of
#define container_of(ptr, type, member)                                        \
  ({                                                                           \
    const typeof(((type *)0)->member) *__mptr = (ptr);                         \
    (type *)((char *)__mptr - offsetof(type, member));                         \
  })
#endif

// 接口参数属性
#define IN       // 入参
#define OUT      // 出参
#define OPTIONAL // 可选，根据其他参数指定

#define INTERFACE_CONST_INIT(type, obj, val) (*((type *)&(obj)) = (type)(val))

#endif
