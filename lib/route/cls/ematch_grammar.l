/*
 * lib/route/cls/ematch_grammar.l	ematch expression grammar
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2010 Thomas Graf <tgraf@suug.ch>
 */

%{
 #include <netlink-local.h>
 #include <netlink-tc.h>
 #include <netlink/netlink.h>
 #include <netlink/route/cls/ematch.h>
 #include <netlink/route/cls/ematch/cmp.h>
 #include "ematch_syntax.h"
%}

%option 8bit
%option reentrant
%option warn
%option noyywrap
%option noinput
%option nounput
%option bison-bridge
%option prefix="ematch_"

%x QUOTE

%%

[ \t\r\n]+

\"			{
				NL_DBG(4, "Beginning of quote\n");
				yylval->q.len = 32;
				if (!(yylval->q.data = calloc(1, yylval->q.len)))
					return ERROR;

				yylval->q.index = 0;
				BEGIN(QUOTE);
			}

<QUOTE>[^\\\n\"]+	{
				memcpy(yylval->q.data + yylval->q.index, yytext,
				       strlen(yytext));
				yylval->q.index += strlen(yytext);
			}

<QUOTE>\"		{
				BEGIN(0);
				return QUOTED;
			}


[[:digit:]]+		|
0[xX][[:xdigit:]]+	{
				yylval->i = strtoul(yytext, NULL, 0);
				return NUMBER;
			}

eq			|
"="			return KW_EQ;
gt			|
">"			return KW_GT;
lt			|
"<"			return KW_LT;

[aA][nN][dD]		|
"&&"			{ yylval->i = TCF_EM_REL_AND; return LOGIC; }
[oO][rR]		|
"||"			{ yylval->i = TCF_EM_REL_OR; return LOGIC; }
[nN][oO][tT]		|
"!"			return NOT;

[cC][mM][pP]		{ yylval->i = TCF_EM_CMP; return EMATCH_CMP; }
[pP][aA][tT][tT][eE][rR][nN] { yylval->i = TCF_EM_NBYTE; return EMATCH_NBYTE; }

"("			return KW_OPEN;
")"			return KW_CLOSE;
[mM][aA][sS][kK]	return KW_MASK;
[aA][tT]		return KW_AT;
"+"			return KW_PLUS;

[uU]8			{ yylval->i = TCF_EM_ALIGN_U8; return ALIGN; }
[uU]16			{ yylval->i = TCF_EM_ALIGN_U16; return ALIGN; }
[uU]32			{ yylval->i = TCF_EM_ALIGN_U32; return ALIGN; }

[lL][iI][nN][kK]	|
[eE][tT][hH]		{ yylval->i = TCF_LAYER_LINK; return LAYER; }
[nN][eE][tT]		|
[iI][pP]6		|
[iI][pP]		{ yylval->i = TCF_LAYER_NETWORK; return LAYER; }
[tT][rR][aA][nN][sS][pP][oO][rR][tT] |
[tT][cC][pP]		{ yylval->i = TCF_LAYER_TRANSPORT; return LAYER; }

[^ \t\r\n+()=<>&|\"]+	{
				yylval->s = strdup(yytext);
				if (yylval->s == NULL)
					return ERROR;
				NL_DBG(4, "lex STR=%s\n", yylval->s);
				return STR;
			}
