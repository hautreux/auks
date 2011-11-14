%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "analyse.h"
#include "conf_yacc.h"

/* Numero de la ligne courante */
int yylineno;

/* Traitement des messages d'erreur */
void set_error(char * s);

#define ERRLEN 1024
char err_str[ERRLEN]="";

/* Stockage des chaines */
char YY_PARSED_STRING[MAXSTRLEN];

void YY_BUFFER_APPEND(char * s){
    strncat( YY_PARSED_STRING,s, MAXSTRLEN);
}

void YY_BUFFER_RESET(void){
    int i;
    for (i=0;i<MAXSTRLEN;i++){
        YY_PARSED_STRING[i]='\0';
    }
}

/* initialisation du parser */

#define YY_USER_INIT {\
    yylineno=1;\
    BEGIN YY_INIT;\
}

#ifdef _DEBUG_PARSING
#define DEBUG_LEX   printf
#else
#define DEBUG_LEX
#endif


%}


SPACE        [ \t\r\f]
NL           [\n]
VAL_CHAR     [^ \t\r\n\f;"'#]
COMMENTAIRE	 #.*$
/* lettre posant probleme dans une chaine */
STRING_CHAR       [^\n]
/* comment est compose un identifiant */
LETTER          [a-zA-Z_.]
IDENTIFIER_CHAR    [a-zA-Z0-9_.\-:]


%START  YY_INIT BLOC INBLOC AFFECT VALUE ENDVALUE  STRING1 STRING2 ESC1 

%%



<YY_INIT>{LETTER}({IDENTIFIER_CHAR})*     {/* identifier */ DEBUG_LEX("[bloc:%s]\n",yytext); strncpy(yylval.str_val,yytext,MAXSTRLEN); BEGIN BLOC; return IDENTIFIER;}


<BLOC>"{"            {/* identifier */ DEBUG_LEX("BEGIN_BLOCK\n",yytext); BEGIN INBLOC;return BEGIN_BLOCK;}

<INBLOC>{LETTER}({IDENTIFIER_CHAR})*     {/* identifier */ DEBUG_LEX("[id:%s",yytext);strncpy(yylval.str_val,yytext,MAXSTRLEN); BEGIN AFFECT;return IDENTIFIER;}
<INBLOC>"}"          {/* identifier */ DEBUG_LEX("END_BLOCK\n",yytext); BEGIN YY_INIT;return END_BLOCK;}

<AFFECT>"="          {/* identifier */ DEBUG_LEX(" , ",yytext); BEGIN VALUE;return AFFECTATION;}

<VALUE>"\""           {BEGIN STRING1;DEBUG_LEX("value:<");YY_BUFFER_RESET();} /* ouverture string 1 */
<VALUE>"'"            {BEGIN STRING2;DEBUG_LEX("value:<");YY_BUFFER_RESET();} /* ouverture string 2 */
<VALUE>({VAL_CHAR})+  {/* valeur */DEBUG_LEX("value:%s",yytext);BEGIN ENDVALUE;strncpy(yylval.str_val,yytext,MAXSTRLEN); return KEYVALUE;}

<ENDVALUE>";"         {DEBUG_LEX("]\n");BEGIN INBLOC;return END_AFFECT;}

<STRING1>\\     {BEGIN ESC1;}
<STRING1>"\""   {DEBUG_LEX(">");strncpy(yylval.str_val,YY_PARSED_STRING,MAXSTRLEN);BEGIN ENDVALUE;/* chaine finie */ return KEYVALUE;}
<STRING1>\n      {snprintf(err_str,ERRLEN,"line %d: missing closing quote.",yylineno,*yytext); set_error(err_str);yylineno++;return _ERROR_;}
<STRING1>.      {YY_BUFFER_APPEND(yytext); DEBUG_LEX("%c",*yytext);/* caractere de la chaine */}

<ESC1>\n        BEGIN STRING1;yylineno++;/* ignore un saut de ligne echappe*/
<ESC1>.         {DEBUG_LEX("%c",*yytext);YY_BUFFER_APPEND(yytext);BEGIN STRING1;/* caractere de la chaine */}

<STRING2>"'"    {DEBUG_LEX(">");strncpy(yylval.str_val,YY_PARSED_STRING,MAXSTRLEN);BEGIN ENDVALUE;/* chaine finie */ return KEYVALUE;}
<STRING2>\n     {snprintf(err_str,ERRLEN,"line %d: closing quote missing.",yylineno,*yytext); set_error(err_str);yylineno++;return _ERROR_;}
<STRING2>.      {YY_BUFFER_APPEND(yytext);DEBUG_LEX("%c",*yytext);/* caractere de la chaine */}

{COMMENTAIRE}  ;/* ignore */
{SPACE}        ;/* ignore */
{NL}           yylineno++;/* ignore */

. { snprintf(err_str,ERRLEN,"line %d: '%c' unexpected",yylineno,*yytext); set_error(err_str);return _ERROR_;}

%%

int yywrap(void){
    return 1;
}
