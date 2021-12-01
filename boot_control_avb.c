/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <errno.h>
#include <string.h>

#include <cutils/properties.h>

#include <libavb_ab/libavb_ab.h>
#include <libavb_user/libavb_user.h>

#include "boot_control_avb.h"

static AvbOps* ops = NULL;

static void module_init(boot_control_module_t* module) {
  if (ops != NULL) {
    avb_error("AvbOps instance is already exist.\n");
    return;
  }

  ops = avb_ops_user_new();
  if (ops == NULL) {
    avb_error("Unable to allocate AvbOps instance.\n");
  } else {
    avb_error("Success to allocate AvbOps instance.\n");
  }
}

static unsigned int module_getNumberSlots(boot_control_module_t* module) {
  return 2;
}

static unsigned int module_getCurrentSlot(boot_control_module_t* module) {
  char propbuf[PROPERTY_VALUE_MAX];

  if (__system_property_get("ro.boot.slot_suffix", propbuf) < 0) {
    avb_errorv("Unable to read slot suffix in ro.boot.slot_suffix\n", NULL);
    return 0;
  }

  if (strcmp(propbuf, "_a") == 0) {
    return 0;
  } else if (strcmp(propbuf, "_b") == 0) {
    return 1;
  } else {
    avb_errorv("Unexpected slot suffix '", propbuf, "'.\n", NULL);
    return 0;
  }
  return 0;
}

static int module_markBootSuccessful(boot_control_module_t* module) {
  if (avb_ab_mark_slot_successful(ops->ab_ops, module_getCurrentSlot(module)) ==
      AVB_IO_RESULT_OK) {
    return 0;
  } else {
    return -EIO;
  }
}

static int module_setActiveBootSlot(boot_control_module_t* module,
                                    unsigned int slot) {
  if (avb_ab_mark_slot_active(ops->ab_ops, slot) == AVB_IO_RESULT_OK) {
    return 0;
  } else {
    return -EIO;
  }
}

static unsigned int module_getActiveBootSlot(boot_control_module_t* module) {
  return avb_ab_get_active_slot(ops->ab_ops);
}

static int module_setSlotAsUnbootable(struct boot_control_module* module,
                                      unsigned int slot) {
  if (avb_ab_mark_slot_unbootable(ops->ab_ops, slot) == AVB_IO_RESULT_OK) {
    return 0;
  } else {
    return -EIO;
  }
}

static int module_isSlotBootable(struct boot_control_module* module,
                                 unsigned int slot) {
  AvbABData ab_data;
  bool is_bootable;

  //avb_assert(slot < 2);
  if (slot >= 2)
    return -EIO;

  if (avb_ab_data_read(ops->ab_ops, &ab_data) != AVB_IO_RESULT_OK) {
    return -EIO;
  }

  is_bootable = (ab_data.slot_info[slot].priority > 0) &&
                (ab_data.slot_info[slot].successful_boot ||
                 (ab_data.slot_info[slot].tries_remaining > 0));

  return is_bootable ? 1 : 0;
}

static int module_isSlotMarkedSuccessful(struct boot_control_module* module,
                                         unsigned int slot) {
  AvbABData ab_data;
  bool is_marked_successful;

  //avb_assert(slot < 2);
  if (slot >= 2)
    return -EIO;

  if (avb_ab_data_read(ops->ab_ops, &ab_data) != AVB_IO_RESULT_OK) {
    return -EIO;
  }

  is_marked_successful = ab_data.slot_info[slot].successful_boot;

  return is_marked_successful ? 1 : 0;
}

static const char* module_getSuffix(boot_control_module_t* module,
                                    unsigned int slot) {
  static const char* suffix[2] = {"_a", "_b"};
  if (slot >= 2) {
    return NULL;
  }
  return suffix[slot];
}

static bool module_setSnapshotMergeStatus(uint8_t status) {
    if (avb_ab_set_snapshot_merge_status(ops->ab_ops, status) == AVB_IO_RESULT_OK)
        return true;
    else
        return false;
}

static uint8_t module_getSnapshotMergeStatus(void) {
    return avb_ab_get_snapshot_merge_status(ops->ab_ops);
}

static struct hw_module_methods_t module_methods = {
    .open = NULL,
};

private_boot_control_t HAL_MODULE_INFO_SYM = {
    .base = {
        .common =
        {
            .tag = HARDWARE_MODULE_TAG,
            .module_api_version = BOOT_CONTROL_MODULE_API_VERSION_0_1,
            .hal_api_version = HARDWARE_HAL_API_VERSION,
            .id = BOOT_CONTROL_HARDWARE_MODULE_ID,
            .name = "INTEL AVB implementation of boot_control HAL",
            .author = "The Android Open Source Project",
            .methods = &module_methods,
        },
        .init = module_init,
        .getNumberSlots = module_getNumberSlots,
        .getCurrentSlot = module_getCurrentSlot,
        .markBootSuccessful = module_markBootSuccessful,
        .setActiveBootSlot = module_setActiveBootSlot,
        .setSlotAsUnbootable = module_setSlotAsUnbootable,
        .isSlotBootable = module_isSlotBootable,
        .getSuffix = module_getSuffix,
        .isSlotMarkedSuccessful = module_isSlotMarkedSuccessful,
        .getActiveBootSlot = module_getActiveBootSlot,
    },
    .SetSnapshotMergeStatus = module_setSnapshotMergeStatus,
    .GetSnapshotMergeStatus = module_getSnapshotMergeStatus,
};
