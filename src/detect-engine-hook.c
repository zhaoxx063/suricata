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

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"

int DetectHookInit(DetectHook *hook) {
    memset(hook, 0x00, sizeof(hook));
    return DETECT_HOOK_OK;
}

int DetectHookRegister(DetectHook *hook, int (*Callback)(DetectEngineCtx *, DetectEngineThreadCtx *, Packet *)) {
    int i;

    /* allow duplicate registrations */
    for (i = 0; i < hook->cnt; i++) {
        if (Callback == hook->Callback[i]) {
            return DETECT_HOOK_OK;
        }
    }

    if (hook->cnt == DETECT_HOOK_MAX) {
        return DETECT_HOOK_ERROR;
    }

    hook->Callback[hook->cnt++] = Callback;
    return DETECT_HOOK_OK;
}

int DetectHookRun(DetectHook *hook, DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx, Packet *p) {
    int i;
    int r = 0;

    SCLogDebug("running %d Callbacks for hook %p", hook->cnt, hook);

    for (i = 0; i < hook->cnt; i++) {
        r |= hook->Callback[i](de_ctx, det_ctx, p);
    }

    SCLogDebug("ran %d Callbacks for hook %p, retval %d", hook->cnt, hook, r);
    return r;
}
