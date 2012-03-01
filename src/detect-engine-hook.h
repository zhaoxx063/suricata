/* Copyright (C) 2007-2012 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __DETECT_ENGINE_HOOK_H__
#define __DETECT_ENGINE_HOOK_H__

/* hooks */
#define DETECT_HOOK_MAX 7

#define DETECT_HOOK_ERROR -1
#define DETECT_HOOK_OK 0

typedef struct DetectHook_ {
    /* number of callbacks for this hook */
    int cnt;
#if __WORDSIZE == 64
    int pad;
#endif
    /** array of callback ptrs */
    int (*Callback[DETECT_HOOK_MAX])();
} DetectHook;

/* function prototypes in detect.c */

#endif /* __DETECT_ENGINE_HOOK_H__ */
