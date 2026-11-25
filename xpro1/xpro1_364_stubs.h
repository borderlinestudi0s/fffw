/*
 * Fujifilm X-Pro 1, firmware 3.64 - stub table (work in progress).
 *
 * All addresses are runtime addresses, verified against a live ff80 RAM dump
 * (FW 3.64) by decompiling in Ghidra with the ARM:LE:32:v7 language.
 *
 * IMPORTANT: this firmware is ARMv7 and builds almost every address with
 * MOVW/MOVT pairs instead of literal pools. Import it as ARM:LE:32:v7. An
 * ARMv5 import (v5t) cannot decode MOVW/MOVT, which turns most code into
 * garbage, hides nearly every string reference and looks like "Thumb" noise.
 *
 * Confidence tags:
 *   [C] confirmed: decompiled, signature and behaviour match the fujihack
 *       definition, plus at least one independent caller that agrees
 *   [P] probable: decompiled and consistent, one line of evidence
 * Where the X-Pro 1 calling convention differs from fujihack's headers it is
 * noted next to the stub.
 */

#define MODEL_NAME "Fujifilm X-Pro1"
#define FIRMWARE_VERSION "3.64"

/* Code is ARM mode in the platform/library areas used below. Thumb-2 exists
 * elsewhere in the image, so do not assume CODE_ARM everywhere. */

/* RTOS service table. 0x40000000 is an uncached mirror of RAM: the pointer
 * lives at 0x40a8d220 (= RAM 0x00a8d220) and holds 0x400c0400, so the table
 * itself is at RAM 0x000c0400. get_task_id / task_sleep / create_task all
 * call through it. (X-A2 equivalent: MEM_RTOS_FUNCTIONS.) */
#define MEM_RTOS_FUNCTIONS_PTR 0x40a8d220
#define MEM_RTOS_FUNCTIONS     0x000c0400

/* Task id of the file system task. Every file call is a message to it. */
#define FUJI_FILE_TASK_ID 0x15

#ifdef STUBS
	#include "stub.h"

	/* ---- libc ------------------------------------------------------- */
	NSTUB(fuji_strcpy, 0x00966a8c)   /* [C] byte copy loop */
	NSTUB(fuji_memcpy, 0x00966f88)   /* [C] (dst, src, n), ~2000 callers */
	NSTUB(fuji_strncmp, 0x009672c8)  /* [P] (a, b, n) == 0 on match */

	/* ---- file I/O ----------------------------------------------------
	 * Each call copies its arguments into a message and posts it to the
	 * file task (0x15) with an event code, then the handler is called back.
	 * The public entries below pass sync=0 to a worker; event codes:
	 *   open 0x2517, read 0x2518, write 0x2519, close 0x251a, seek 0x251c.
	 * Confirmed by the AUTO_ACT script loader (open, fstats, read, close)
	 * and its WT_LOG writer (open, write, close), plus SQLite's VFS xRead. */
	NSTUB(fuji_fopen,  0x009629fc)   /* [C] (handler, path, flag) */
	NSTUB(fuji_fread,  0x00962798)   /* [C] (handler, fp, n, data) */
	NSTUB(fuji_fwrite, 0x009625a8)   /* [C] (handler, fp, n, data) */
	NSTUB(fuji_fclose, 0x009623d0)   /* [C] (handler, fp, x, y) */
	NSTUB(fuji_fseek,  0x0096220c)   /* [C] (handler, fp, pos, a, whence) */
	NSTUB(fuji_fstats, 0x0096197c)   /* [C] (fp, struct FujiStats *); size at +0x34.
	                                  * 2 args here, fujihack's has 3 */
	NSTUB(fuji_drive,  0x00964c8c)   /* [P] returns drive letter, 0 if no card */

	/* ---- tasks / RTOS ------------------------------------------------ */
	NSTUB(fuji_get_task_id, 0x0096a0cc)  /* [C] via RTOS table */
	NSTUB(fuji_task_event,  0x0096ad14)  /* [C] (task_id, struct FujiEventReq *) */
	NSTUB(fuji_task_sleep,  0x0096bf50)  /* [C] (ms); 0 = yield. script "wait" */
	NSTUB(fuji_create_task, 0x0096c8dc)  /* [C] (struct FujiTask *) ONE arg here:
	                                      * {id, name, priority, stack, entry, 0}
	                                      * e.g. "mujin": {0x1b,"mujin",9,0xc00,..} */
	NSTUB(fuji_create_task_queue, 0x0096c4ec) /* [P] (id, {count, msgsize}),
	                                      * called before create_task */
	NSTUB(fuji_wait_task_start, 0x008117f8)  /* [C] (ms, mode, callback, buf)
	                                      * "SoftTimerStart"; 32 slots */
	NSTUB(fuji_wait_task_stop,  0x008116ec)  /* [C] (handle) "SoftTimerStop" */
	NSTUB(fuji_irq_disable, 0x00969c24)  /* [P] returns state; pairs with below */
	NSTUB(fuji_irq_restore, 0x00969d00)  /* [P] (state) */

	/* ---- input -------------------------------------------------------
	 * Different shape from fujihack's fuji_press_key(code, down): the X-Pro 1
	 * takes a pointer to {u32 key, u32 x}, where key = FujiKey code, with
	 * 0x80 OR'd in for release (script table: ON=0, OFF=0x80). It posts the
	 * event to task 1 via fuji_task_event. Key codes match ff_io.h
	 * (EXE_M/OK=1, UP=2, DOWN=3, ...). */
	NSTUB(fuji_key_event, 0x0096f7fc)    /* [C] (struct {u32 key; u32 x} *) */

	/* ---- SQLite 3.6.22 (identified against the upstream source) ------ */
	NSTUB(sqlite_exec,     0x01680340)   /* [C] called from sqlite3InitOne with
	                                      * sqlite3InitCallback @0x01680738 */
	NSTUB(sqlite_mprintf,  0x0165d0f4)   /* [C] sqlite3MPrintf(db, fmt, ...) */
	NSTUB(sqlite_db_free,  0x0165be30)   /* [C] sqlite3DbFree(db, p) */
#endif

/*
 * Other verified landmarks (not stubs):
 *   0x010b5cc8  AUTO_ACT script loader ("A:\DCAA\auto_act.scr")
 *   0x010b5010  "mujin" (unattended script) task init
 *   0x010b5ec0  "mujin" task entry
 *   0x010b5f0c  script keyword table {char name[12]; u32 op}: wait=0x0c,
 *               WAITSET, if, func, LABEL, key=0x11, calc, set, jump,
 *               random, END, WT_LOG=0x17; key names follow at 0x010b5fcc
 *   0x010b51c0  WT_LOG writer (fopen/fwrite/fclose)
 *   0x016551bc  FFDB header builder ("FFDB", "FUJIFILM", "FinePix")
 *   0x00f41b9c+ seg1 file manager: wrappers that store a callback and call
 *               the seg0 file API (find/copy/delete family, events 0x2506-0x251d)
 *
 * Still to identify: fuji_get_error, fuji_file_wait / fuji_file_reset,
 * fuji_init_sqlite, sqlite_snprintf, sqlite_mallocAlarm,
 * SQLITE_MEM_METHODS, fuji_screen_write, MEM_INPUT_MAP.
 */
