/* A Bison parser, made by GNU Bison 1.875c.  */

/* Skeleton parser for Yacc-like parsing with Bison,
   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     _ERROR_ = 258,
     BEGIN_BLOCK = 259,
     END_BLOCK = 260,
     AFFECTATION = 261,
     END_AFFECT = 262,
     IDENTIFIER = 263,
     KEYVALUE = 264
   };
#endif
#define _ERROR_ 258
#define BEGIN_BLOCK 259
#define END_BLOCK 260
#define AFFECTATION 261
#define END_AFFECT 262
#define IDENTIFIER 263
#define KEYVALUE 264




#if ! defined (YYSTYPE) && ! defined (YYSTYPE_IS_DECLARED)
#line 27 "conf_yacc.y"
typedef union YYSTYPE {
    char str_val[MAXSTRLEN];
    list_block *  listbl;
    type_block  *  block;
    list_affect  *  listaf;
    type_affect * affectation;
} YYSTYPE;
/* Line 1275 of yacc.c.  */
#line 63 "conf_yacc.h"
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE yylval;



