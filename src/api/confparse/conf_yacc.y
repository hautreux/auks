%{

#include <stdio.h>
#include <string.h>
#include "analyse.h"


    int yylex(void);
    void yyerror(char*);

    list_block * program_result=NULL;
    
	/* stock le message d'erreur donne par le lexer */
    char local_errormsg[1024]="";
	
	/* stock le message d'erreur complet */
	char extern_errormsg[1024]="";
    
#ifdef _DEBUG_PARSING
#define DEBUG_YACK   config_print_list
#else
#define DEBUG_YACK
#endif

    
%}

%union {
    char str_val[MAXSTRLEN];
    list_block *  listbl;
    type_block  *  block;
    list_affect  *  listaf;
    type_affect * affectation;
};

%token _ERROR_
%token BEGIN_BLOCK
%token END_BLOCK
%token AFFECTATION
%token END_AFFECT
%token <str_val> IDENTIFIER
%token <str_val> KEYVALUE

%type <listbl> listblock
%type <block>   definition
%type <listaf> list_var
%type <affectation> var


%%

program: listblock {DEBUG_YACK(stderr,$1);program_result=$1;}
    ;

listblock:
    definition listblock {config_addblock($2,$1);$$=$2;}
    | {$$=config_createlistblock();}
    ;

definition:
    IDENTIFIER BEGIN_BLOCK list_var END_BLOCK {$$=config_createblock($1,$3);}
    ;

list_var:
    var list_var   {config_adddef($2,$1);$$=$2;}
    |               {$$=config_createlistaffect();}
    ;

var:
    IDENTIFIER AFFECTATION KEYVALUE END_AFFECT {$$=config_createaffect($1,$3);}
    ;

%%

    void yyerror(char *s){
        
		snprintf(extern_errormsg,1024,"%s (%s)",local_errormsg,s);
    
    }
    

    void set_error(char * s){
        strncpy(local_errormsg,s,1024);
    }
