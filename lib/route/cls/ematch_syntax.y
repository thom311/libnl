/*
 * lib/route/cls/ematch_syntax.y	ematch expression syntax
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
#include <netlink/utils.h>
#include <netlink/route/pktloc.h>
#include <netlink/route/cls/ematch.h>
#include <netlink/route/cls/ematch/cmp.h>
#include <netlink/route/cls/ematch/nbyte.h>
%}

%error-verbose
%define api.pure
%name-prefix "ematch_"

%parse-param {void *scanner}
%parse-param {char **errp}
%parse-param {struct nl_list_head *root}
%lex-param {void *scanner}

%union {
	struct tcf_em_cmp	cmp;
	struct ematch_quoted	q;
	struct rtnl_ematch *	e;
	struct rtnl_pktloc *	loc;
	uint32_t		i;
	char *			s;
}

%{
extern int ematch_lex(YYSTYPE *, void *);

static void yyerror(void *scanner, char **errp, struct nl_list_head *root, const char *msg)
{
	if (msg)
		asprintf(errp, "%s", msg);
}
%}

%token <i> ERROR LOGIC NOT OPERAND NUMBER ALIGN LAYER
%token <i> KW_OPEN "("
%token <i> KW_CLOSE ")"
%token <i> KW_PLUS "+"
%token <i> KW_MASK "mask"
%token <i> KW_AT "at"
%token <i> EMATCH_CMP "cmp"
%token <i> EMATCH_NBYTE "pattern"
%token <i> KW_EQ "="
%token <i> KW_GT ">"
%token <i> KW_LT "<"

%token <s> STR

%token <q> QUOTED

%type <i> mask align operand
%type <e> expr match ematch
%type <cmp> cmp_expr cmp_match
%type <loc> pktloc
%type <q> pattern

%destructor { free($$); NL_DBG(2, "string destructor\n"); } <s>
%destructor { rtnl_pktloc_put($$); NL_DBG(2, "pktloc destructor\n"); } <loc>
%destructor { free($$.data); NL_DBG(2, "quoted destructor\n"); } <q>

%start input

%%

input:
	/* empty */
	| expr
		{
			nl_list_add_tail(root, &$1->e_list);
		}
	;

expr:
	match
		{
			$$ = $1;
		}
	| match LOGIC expr
		{
			rtnl_ematch_set_flags($1, $2);

			/* make ematch new head */
			nl_list_add_tail(&$1->e_list, &$3->e_list);

			$$ = $1;
		}
	;

match:
	NOT ematch
		{
			rtnl_ematch_set_flags($2, TCF_EM_INVERT);
			$$ = $2;
		}
	| ematch
		{
			$$ = $1;
		}
	;

ematch:
	/* CMP */
	cmp_match
		{
			struct rtnl_ematch *e;

			if (!(e = rtnl_ematch_alloc())) {
				asprintf(errp, "Unable to allocate ematch object");
				YYABORT;
			}

			if (rtnl_ematch_set_kind(e, TCF_EM_CMP) < 0)
				BUG();

			rtnl_ematch_cmp_set(e, &$1);
			$$ = e;
		}
	| EMATCH_NBYTE "(" pktloc KW_EQ pattern ")"
		{
			struct rtnl_ematch *e;

			if (!(e = rtnl_ematch_alloc())) {
				asprintf(errp, "Unable to allocate ematch object");
				YYABORT;
			}

			if (rtnl_ematch_set_kind(e, TCF_EM_NBYTE) < 0)
				BUG();

			rtnl_ematch_nbyte_set_offset(e, $3->layer, $3->offset);
			rtnl_ematch_nbyte_set_pattern(e, (uint8_t *) $5.data, $5.index);

			$$ = e;
		}
	/* CONTAINER */
	| "(" expr ")"
		{
			struct rtnl_ematch *e;

			if (!(e = rtnl_ematch_alloc())) {
				asprintf(errp, "Unable to allocate ematch object");
				YYABORT;
			}

			if (rtnl_ematch_set_kind(e, TCF_EM_CONTAINER) < 0)
				BUG();

			/* Make e->childs the list head of a the ematch sequence */
			nl_list_add_tail(&e->e_childs, &$2->e_list);

			$$ = e;
		}
	;

/*
 * CMP match
 *
 * match  := cmp(expr) | expr
 * expr   := pktloc (=|>|<) NUMBER
 * pktloc := alias | definition
 *
 */
cmp_match:
	EMATCH_CMP "(" cmp_expr ")"
		{ $$ = $3; }
	| cmp_expr
		{ $$ = $1; }
	;

cmp_expr:
	pktloc operand NUMBER
		{
			if ($1->align == TCF_EM_ALIGN_U16 ||
			    $1->align == TCF_EM_ALIGN_U32)
				$$.flags = TCF_EM_CMP_TRANS;

			memset(&$$, 0, sizeof($$));

			$$.mask = $1->mask;
			$$.off = $1->offset;
			$$.align = $1->align;
			$$.layer = $1->layer;
			$$.opnd = $2;
			$$.val = $3;
		}
	;

/*
 * pattern
 */
pattern:
	QUOTED
		{
			$$ = $1;
		}
	| STR
		{
			struct nl_addr *addr;

			if (nl_addr_parse($1, AF_UNSPEC, &addr) == 0) {
				$$.len = nl_addr_get_len(addr);

				$$.index = min_t(int, $$.len, nl_addr_get_prefixlen(addr)/8);

				if (!($$.data = calloc(1, $$.len))) {
					nl_addr_put(addr);
					YYABORT;
				}

				memcpy($$.data, nl_addr_get_binary_addr(addr), $$.len);
				nl_addr_put(addr);
			} else {
				asprintf(errp, "invalid pattern \"%s\"", $1);
				YYABORT;
			}
		}
	;

/*
 * packet location
 */

pktloc:
	STR
		{
			struct rtnl_pktloc *loc;

			if (rtnl_pktloc_lookup($1, &loc) < 0) {
				asprintf(errp, "Packet location \"%s\" not found", $1);
				YYABORT;
			}

			$$ = loc;
		}
	| align "at" LAYER "+" NUMBER mask
		{
			struct rtnl_pktloc *loc;

			if (!(loc = rtnl_pktloc_alloc())) {
				asprintf(errp, "Unable to allocate packet location object");
				YYABORT;
			}

			loc->name = strdup("<USER-DEFINED>");
			loc->align = $1;
			loc->layer = $3;
			loc->offset = $5;
			loc->mask = $6;

			$$ = loc;
		}
	;

align:
	ALIGN
		{ $$ = $1; }
	| NUMBER
		{ $$ = $1; }
	;

mask:
	/* empty */
		{ $$ = 0; }
	| "mask" NUMBER
		{ $$ = $2; }
	;

operand:
	KW_EQ
		{ $$ = TCF_EM_OPND_EQ; }
	| KW_GT
		{ $$ = TCF_EM_OPND_GT; }
	| KW_LT
		{ $$ = TCF_EM_OPND_LT; }
	;
