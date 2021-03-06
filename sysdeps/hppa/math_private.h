/* Internal math stuff.  HPPA version.
   Copyright (C) 2013-2015 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#ifndef HPPA_MATH_PRIVATE_H
#define HPPA_MATH_PRIVATE_H 1

/* One of the few architectures where the meaning of the quiet/signaling bit is
   inverse to IEEE 754-2008 (as well as common practice for IEEE 754-1985).  */
#define HIGH_ORDER_BIT_IS_SET_FOR_SNAN

#include_next <math_private.h>

#endif
