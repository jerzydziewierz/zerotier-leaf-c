/* SPDX-License-Identifier: LicenseRef-AllRightsReserved */
/*
 * Interface annotations in the style of C-rusted (Bagnara et al., 2024).
 * They expand to nothing. They state intent for the reader; the properties
 * are checked by the tools in proofs/ (CBMC, Frama-C), not by these macros.
 * Default without annotation: a pointer is not null and refers to
 * initialized memory.
 */
#ifndef ZTL_ANNOT_H
#define ZTL_ANNOT_H

#define ZTL_OPT        /* pointer may be null */
#define ZTL_COUNT(n)   /* refers to n valid elements */
#define ZTL_SHAR       /* shared, read-only reference */
#define ZTL_EXCL       /* exclusive reference: no other usable alias */
#define ZTL_INIT       /* callee writes the whole object and reads none of it */

#endif
