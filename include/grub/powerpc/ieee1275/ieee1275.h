/* ieee1275.h - Access the Open Firmware client interface.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2003,2004,2005,2007  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GRUB_IEEE1275_MACHINE_HEADER
#define GRUB_IEEE1275_MACHINE_HEADER	1

#include <grub/types.h>

#define GRUB_IEEE1275_CELL_SIZEOF 4
typedef grub_uint32_t grub_ieee1275_cell_t;

#define PRIxGRUB_IEEE1275_CELL_T	PRIxGRUB_UINT32_T
#define PRIuGRUB_IEEE1275_CELL_T	PRIuGRUB_UINT32_T

#ifdef __powerpc__

extern int
EXPORT_FUNC (grub_ieee1275_test) (const char *name,
                                  grub_ieee1275_cell_t *missing);

extern int
grub_ieee1275_pks_max_object_size (grub_size_t *result);

extern int
grub_ieee1275_pks_read_object (grub_uint8_t consumer, grub_uint8_t *label,
                               grub_size_t label_len, grub_uint8_t *buffer,
                               grub_size_t buffer_len, grub_size_t *data_len,
                               grub_uint32_t *policies);

extern int
grub_ieee1275_pks_read_sbvar (grub_uint8_t sbvarflags, grub_uint8_t sbvartype,
                              grub_uint8_t *buffer, grub_size_t buffer_len,
                              grub_size_t *data_len);
#endif

#endif /* ! GRUB_IEEE1275_MACHINE_HEADER */
