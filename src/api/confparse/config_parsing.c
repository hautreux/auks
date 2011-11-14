/***************************************************************************\
 * config_parsing.c - Configuration file parsing routines
 ***************************************************************************
 * Copyright  CEA/DAM/DIF (2005)
 *
 * Written by Philippe DENIEL <philippe.deniel@cea.fr>
 *            Thomas LEIBOVICI <thomas.leibovici@cea.fr>
 * 
 * This software is a computer program whose purpose is to simplify
 * the addition of kerberos credential support in Batch applications.
 *
 * This software is governed by the CeCILL-C license under French law and
 * abiding by the rules of distribution of free software.  You can  use, 
 * modify and/ or redistribute the software under the terms of the CeCILL-C
 * license as circulated by CEA, CNRS and INRIA at the following URL
 * "http://www.cecill.info". 
 * 
 * As a counterpart to the access to the source code and  rights to copy,
 * modify and redistribute granted by the license, users are provided only
 * with a limited warranty  and the software's author,  the holder of the
 * economic rights,  and the successive licensors  have only  limited
 * liability. 
 * 
 * In this respect, the user's attention is drawn to the risks associated
 * with loading,  using,  modifying and/or developing or reproducing the
 * software by the user in light of its specific status of free software,
 * that may mean  that it is complicated to manipulate,  and  that  also
 * therefore means  that it is reserved for developers  and  experienced
 * professionals having in-depth computer knowledge. Users are therefore
 * encouraged to load and test the software's suitability as regards their
 * requirements in conditions enabling the security of their systems and/or 
 * data to be ensured and,  more generally, to use and operate it in the 
 * same conditions as regards security. 
 * 
 * The fact that you are presently reading this means that you have had
 * knowledge of the CeCILL-C license and that you accept its terms.
 ***************************************************************************
 * Copyright  CEA/DAM/DIF (2009)
 * 
 * Ecrit par Philippe DENIEL <philippe.deniel@cea.fr>
 *           Thomas LEIBOVICI <thomas.leibovici@cea.fr>
 *
 * Ce logiciel est un programme informatique servant à faciliter l'ajout
 * du support des tickets Kerberos aux applications Batch.
 * 
 * Ce logiciel est régi par la licence CeCILL-C soumise au droit français et
 * respectant les principes de diffusion des logiciels libres. Vous pouvez
 * utiliser, modifier et/ou redistribuer ce programme sous les conditions
 * de la licence CeCILL-C telle que diffusée par le CEA, le CNRS et l'INRIA 
 * sur le site "http://www.cecill.info".
 * 
 * En contrepartie de l'accessibilité au code source et des droits de copie,
 * de modification et de redistribution accordés par cette licence, il n'est
 * offert aux utilisateurs qu'une garantie limitée.  Pour les mêmes raisons,
 * seule une responsabilité restreinte pèse sur l'auteur du programme,  le
 * titulaire des droits patrimoniaux et les concédants successifs.
 * 
 * A cet égard  l'attention de l'utilisateur est attirée sur les risques
 * associés au chargement,  à l'utilisation,  à la modification et/ou au
 * développement et à la reproduction du logiciel par l'utilisateur étant 
 * donné sa spécificité de logiciel libre, qui peut le rendre complexe à 
 * manipuler et qui le réserve donc à des développeurs et des professionnels
 * avertis possédant  des  connaissances  informatiques approfondies.  Les
 * utilisateurs sont donc invités à charger  et  tester  l'adéquation  du
 * logiciel à leurs besoins dans des conditions permettant d'assurer la
 * sécurité de leurs systèmes et ou de leurs données et, plus généralement, 
 * à l'utiliser et l'exploiter dans les mêmes conditions de sécurité. 
 * 
 * Le fait que vous puissiez accéder à cet en-tête signifie que vous avez 
 * pris connaissance de la licence CeCILL-C, et que vous en avez accepté les
 * termes. 
\***************************************************************************/
#include "config_parsing.h"
#include "analyse.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>

/* case unsensitivity */
#define STRNCMP   strncasecmp


typedef struct config_struct_t
{
  
  /* Syntax tree */
  
  list_block * syntax_tree ;

  /* cache pour l'optimisation du parcours de la liste */

  /* cache le nombre d'elements */
  int cache_nb_items ;
  
  /* cache pour optimiser l'acces a la liste chainee des items */
  type_block  * last_item_ptr ;
  int           last_item_index ;

} config_struct_t ;



/***************************************
 * ACCES AUX VARIABLES EXTERNES
 ***************************************/
 
/* fichier d'entree du lexer */
extern FILE * yyin;
/* routine de parsing */
extern int yyparse();
/* variable renseignee lors du parsing */
extern list_block * program_result;
/* message d'erreur */
extern char extern_errormsg[1024];


/* config_ParseFile:
 * Reads the content of a configuration file and
 * stores it in a memory structure.
 */   
config_file_t config_ParseFile(  char * file_path ){
  
  FILE * configuration_file;
  config_struct_t * output_struct;
  
  /* Inits error message */
  
  extern_errormsg[0] = '\0';
  
    
  /* Sanity check */
  
  if ( !file_path || !file_path[0] ){
    strcpy( extern_errormsg, "Invalid arguments" );
    return NULL;
  }
    
  
  /* First, opens the file. */
  
  configuration_file = fopen( file_path, "r" );
  
  if ( !configuration_file ){
    strcpy( extern_errormsg, strerror(errno) );
    return NULL;
  }
  
    
  /* Then, parse the file. */
  
  yyin = configuration_file;
  if (yyparse()){
    goto error_exit;
  }  

  /** @todo : yyparse fait exit en cas d'erreur. Remedier au probleme. */
    
  
  /* Finally, build the output struct. */
  
  output_struct = (config_struct_t *)malloc(sizeof(config_struct_t));
  
  if (!output_struct){
    strcpy( extern_errormsg, strerror(errno) );
    goto error_exit;
  }
  
  output_struct->cache_nb_items = -1;
  output_struct->last_item_ptr  = NULL;
  output_struct->last_item_index  = -1;
      
  output_struct->syntax_tree = program_result;
  
  fclose(configuration_file);

  /* converts pointer to pointer */
  return (config_file_t) output_struct;
    
  error_exit :

    fclose(configuration_file);

  return NULL;
}



/* If config_ParseFile returns a NULL pointer,
 * config_GetErrorMsg returns a detailled message
 * to indicate the reason for this error.
 */
char * config_GetErrorMsg(){

  return extern_errormsg;
  
}




/**
 * config_Print:
 * Print the content of the syntax tree
 * to a file.
 */
void config_Print( FILE * output, config_file_t config ){
  
    /* sanity check */
    if (!config) return ;
    
    config_print_list( output, ((config_struct_t *)config)->syntax_tree );
    
  
}






/** 
 * config_Free:
 * Free the memory structure that store the configuration.
 */

void config_Free( config_file_t config ){
  
  config_struct_t * config_struct = (config_struct_t *)config ;
  
  if ( !config_struct ) return;
  
  config_free_list( config_struct->syntax_tree );
  
  free( config_struct );
  
  return ;
  
}




/**
 * config_GetNbBlocks:
 * Indicates how many blocks are defined into the config file.
 */
int config_GetNbBlocks( config_file_t config ){
  
  config_struct_t * config_struct = (config_struct_t *)config ;
  
  if ( !config_struct ) return -EFAULT;
  
  
  /* si le cache est renseigne, on renvoie la valeur */
  if (config_struct->cache_nb_items != -1)
    return config_struct->cache_nb_items;

  /* on regarde si la liste est vide */
  if ( !(config_struct->syntax_tree) ) {
      config_struct->cache_nb_items = 0;
      return 0;
  }
  /* on compte le nombre d'elements */
  else
  {
      /* il y a au moins un element : le premier */
      type_block * curr_block = (*config_struct->syntax_tree);
      int nb = 1;

      /*
       * on en profite pour renseigner le cache
       * des blocks
       */
      config_struct->last_item_ptr = curr_block;
      config_struct->last_item_index  = 0;

      while (curr_block = curr_block->next){nb++;}

      /* on cache le nbr de blocks et on renvoie ce nombre */
      config_struct->cache_nb_items = nb;
      return nb;
  }
    
    
}


/* utilisation interne :
 * charge un element dans le cache.
 * \return <>0 si le'element n'est pas trouve.
 */
static int load_item_into_cache( config_struct_t * config_struct, int item_no )
{
    
    /* Sanity checks */
    if (!config_struct || !config_struct->syntax_tree)
      return -1;
    
    /* On verifie que l'index est correct */
    if ( (item_no<0)
         ||(item_no >= config_GetNbBlocks((config_file_t)config_struct)) )
      return -1;
    
    /* L'element est-il deja dans le cache ? */
    if (item_no == config_struct->last_item_index)
      return 0;
    
    /* L'element n'est pas dans le cache, on le cherche */
    /*else*/{
        /* premier element */
        type_block * curr_block = (*config_struct->syntax_tree);
        int index = 0;
        
        while (index != item_no){
            curr_block=curr_block->next;
            if (!curr_block) return -1; /* on est arrive a la fin ss trouver*/
            index++;
        }
        
        if (index == item_no){
            /* on le memorise ds le cache */
            config_struct->last_item_index = index;
            config_struct->last_item_ptr = curr_block;
            return 0;
        } else {
            /* pas normal du tout*/
            return -1;
        }
    }

}




/**
 * config_GetBlockIndexByName:
 * Returns the index of the block with the specified name.
 */
int config_GetBlockIndexByName( config_file_t config,
                                char * block_name )
{

    config_struct_t * config_struct = (config_struct_t *)config ;
    
    /* L'element est-il deja dans le cache ? */
    
    if ( ( config_struct->last_item_ptr != NULL )
         && !STRNCMP( config_struct->last_item_ptr->name , block_name,MAXSTRLEN ) )
       return config_struct->last_item_index ;
    
    
    /* L'element n'est pas dans le cache, on le cherche */
    /*else*/{
        /* premier element */
        type_block * curr_block = (*config_struct->syntax_tree);
        int index = 0;
        
        while (STRNCMP( curr_block->name , block_name,MAXSTRLEN )){
            curr_block=curr_block->next;
            if (!curr_block) return -1; /* on est arrive a la fin ss trouver*/
            index++;
        }
        
        if (!STRNCMP( curr_block->name , block_name,MAXSTRLEN )){
            /* on le memorise ds le cache */
            config_struct->last_item_index = index;
            config_struct->last_item_ptr = curr_block;
            return index;
        } else {
            /* pas normal du tout*/
            return -1;
        }
    }
      
}




/**
 * config_GetBlockName:
 * Indicates the name of a block (specified with its index).
 */

char * config_GetBlockName( config_file_t config , int block_no )
{
  config_struct_t * config_struct = (config_struct_t *)config ;
  
  /* met l'element dans le cache */
  
  if (load_item_into_cache(config_struct,block_no))
    /* sort en cas d'erreur*/
    return NULL;
  else
    /* renvoie le nom sinon*/
    return config_struct->last_item_ptr->name;
  
}




/**
 * config_GetNbKeys:
 * Indicates how many peers (key-value) are defined in a block
 * (specified with its index).
 */

int config_GetNbKeys( config_file_t config, int block_no )
{
  config_struct_t * config_struct = (config_struct_t *)config ;
  
  /* met l'element dans le cache */
  if (load_item_into_cache(config_struct,block_no))
    return -1; /* sort en cas d'erreur*/
  else
  {
      /* recupere la premiere variable */
      type_affect * curr_def = config_struct->last_item_ptr->list_def;
      int nb_vars = 0;

      while (curr_def){
          nb_vars++;
          curr_def=curr_def->next;
      }
      /* elements trouves */
      return nb_vars;

  }
  
}




/**
 * config_GetKeyValue:
 * Retrieves a key-value peer from the block index and the key index.
 */

int config_GetKeyValue( 
                        config_file_t config,
                        int block_no,
                        int key_no,
                        char ** var_name,
                        char ** var_value
                       )
{

    config_struct_t * config_struct = (config_struct_t *)config ;  

    /* met l'element dans le cache */
    if ( load_item_into_cache( config_struct, block_no ) )
      return -1; /* sort en cas d'erreur*/
    
    /* cherche la variable dont l'index est celui donne en parametre */
    /*else*/
    {
        /* recupere la premiere variable */
        type_affect * curr_def = config_struct->last_item_ptr->list_def;
        int index=0;
        
        if (!curr_def) return -1;
                
        while (index != key_no){
            index++;
            curr_def=curr_def->next;
            if (!curr_def) return -1; /* on est arrives a la fin ss trouver*/
        }
        
        if (index == key_no){
            (*var_name) = curr_def->varname;
            (*var_value) = curr_def->varvalue;
            return 0;
        } else {
            /* pas trouve*/
            return -1;
        }
            
    }
  
}




/**
 * config_GetKeyValueByName:
 * Returns the value of the key with the specified name.
 */

char * config_GetKeyValueByName( config_file_t config,
                                 int block_no,
                                 char * key_name )
{
  
    config_struct_t * config_struct = (config_struct_t *)config ;  

    /* met l'element dans le cache */
    if ( load_item_into_cache( config_struct, block_no ) )
      return NULL; /* sort en cas d'erreur*/
  
    /* cherche la variable dont le nom est celui donne en parametre */
    /*else*/
    {
        /* recupere la premiere variable */
        type_affect * curr_def = config_struct->last_item_ptr->list_def ;
                
        while (curr_def){
            if (!STRNCMP(curr_def->varname,key_name,MAXSTRLEN)){
                return curr_def->varvalue;
            } else {
                curr_def=curr_def->next;
            }
        }
        /* pas d'element trouve */
        return NULL;        
            
    }
    
}







