/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2016  Yann E. MORIN <yann.morin.1998@free.fr>. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef __CONNMAN_BACKTRACE_H
#define __CONNMAN_BACKTRACE_H

#ifdef HAVE_EXECINFO_H
void print_backtrace(const char* program_path, const char* program_exec,
		unsigned int offset);
#else
#define print_backtrace(P,E,O)
#endif

#endif /* __CONNMAN_BACKTRACE_H */
