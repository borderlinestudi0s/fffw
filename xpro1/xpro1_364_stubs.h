/*
 * Fujifilm X-Pro 1, firmware 3.64 - WORK IN PROGRESS stub table.
 *
 * Runtime addresses verified against a live RAM dump (FW 3.64) by
 * decompilation. This is a starting point, not a complete table: the X-Pro 1
 * is heavily mixed ARM/Thumb and most of the platform API is not yet
 * identified. The canonical home for this is fujihack/model/xpro1_364.h; it
 * lives here as notes until the set is large enough to upstream.
 *
 * NOTE: unlike other models, CODE is NOT pure ARM - large regions are Thumb.
 */

#define MODEL_NAME "Fujifilm X-Pro1"
#define FIRMWARE_VERSION "3.64"

/* firmware is MIXED ARM/Thumb; do not assume CODE_ARM everywhere */

#ifdef STUBS
	#include "stub.h"

	/* verified by decompilation (plain byte-copy loop, strcpy(dst, src)) */
	NSTUB(fuji_strcpy, 0x00966a8c)

	/* ARM. Copies a name/string into a small stack buffer, then tail-calls
	 * 0x000412f4. Likely a name/log helper; not yet fully named. */
	/* NSTUB(fuji_name_copy_helper, 0x00041c38) */
#endif

/*
 * Still to identify (interactive Ghidra RE):
 *   fuji_fopen / fuji_fread / fuji_fwrite / fuji_fclose   (file I/O)
 *   fuji_create_task / fuji_wait_task_start / _stop       (RTOS tasks)
 *   sqlite_exec / fuji_init_sqlite                        (SQLite core ~0x1697000)
 *   fuji_press_key                                        (KEY_* input map)
 * See README.md for the memory map and why string-to-function search does not
 * work on this firmware.
 */
