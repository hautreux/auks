/***************************************************************************\
 * analyse.c - Build the structure that represents a config file
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
#include "analyse.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/**
 *  Creation d'une list de blocks
 */
list_block * config_createlistblock(){

    list_block * new = (list_block *)malloc(sizeof(list_block));
    (*new)=NULL;
    return new;

}

/**
 *  Creation d'un block
 */
type_block * config_createblock(char * blockname,list_affect * list){
    
    type_block * new = (type_block *)malloc(sizeof(type_block));
    strncpy(new->name,blockname,MAXSTRLEN);
    new->list_def=(*list);
    free(list);
    new->next=NULL;
    
    return new;
    
}

/**
 *  Ajout d'un block a une list de blocks
 */
void config_addblock( list_block * list,type_block * block){
    
    if (!(*list)){
        (*list)=block;
    } else {
        block->next=(*list);
        (*list)=block;
    }
    
}


/**
 *  Creation d'une list d'affectations
 */
list_affect * config_createlistaffect(){
    
    list_affect * new = (list_affect *)malloc(sizeof(list_affect));
    (*new)=NULL;
    return new;

}

/**
 *  Creation d'une definition variable=valeur
 */
type_affect * config_createaffect(char * varname,char * varval){
    
    type_affect * new = (type_affect *)malloc(sizeof(type_affect));
    strncpy(new->varname,varname,MAXSTRLEN);
    strncpy(new->varvalue,varval,MAXSTRLEN);
    new->next=NULL;
    
    return new;

}


/**
 *  Ajout d'une definition a une list d'affectations
 */
void config_adddef(list_affect * list,type_affect * affect){
    if (!(*list)){
        (*list)=affect;
    } else {
        affect->next=(*list);
        (*list)=affect;
}

    }


/**
*   Affichage idente du contenu d'une list de blocks.
*/
void config_print_list( FILE * output, list_block * list ){
    
    type_block * curr_block;
    type_affect * curr_aff;
    
    /* sanity check */
    if (!list) return;
    
    curr_block=(*list);
    
    while (curr_block){
        
        fprintf(output,"BLOCK '%s'\n",curr_block->name);
        
        curr_aff=curr_block->list_def;
        
        while (curr_aff){
            
            fprintf(output,"\t KEY : '%s', VALUE : '%s'\n",curr_aff->varname,curr_aff->varvalue);
            
            curr_aff=curr_aff->next;
        }
        
        fprintf(output,"\n");
        
        curr_block=curr_block->next;
    }
    
        
}



static void free_block( type_block * block ){
  
    type_affect * curr_aff;
    type_affect * next_aff;
    
    curr_aff = block->list_def;
    
    while (curr_aff){
      
      next_aff = curr_aff->next;
      free( curr_aff );
      curr_aff = next_aff;
          
    }
    
    free( block );
    
    return ;
  
}



/**
 * config_free_list:
 * libere les ressources utilisees par une liste de blocks.
 */
void config_free_list(list_block * list){
  
    type_block * curr_block;
    type_block * next_block;
    
    curr_block=(*list);
    
    while (curr_block){
      
      next_block = curr_block->next;      
      free_block( curr_block );
      curr_block = next_block;
        
    }
    
    free( list );
    return ;
  
}












