/***************************************************************************\
 * config_parsing.c - Configuration file parsing routines
 * This API is not thread-safe
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
#ifndef _CONFIG_PARSING_H
#define _CONFIG_PARSING_H

#include <stdlib.h>
#include <stdio.h>

/* opaque type */
typedef caddr_t config_file_t;


/* config_ParseFile:
 * Reads the content of a configuration file and
 * stores it in a memory structure.
 * \return NULL on error.
 */   
config_file_t config_ParseFile(  char * file_path );


/* If config_ParseFile returns a NULL pointer,
 * config_GetErrorMsg returns a detailled message
 * to indicate the reason for this error.
 */
char * config_GetErrorMsg();


/**
 * config_Print:
 * Print the content of the syntax tree
 * to a file.
 */
void config_Print( FILE * output, config_file_t config );



/* Free the memory structure that store the configuration. */
void config_Free( config_file_t config );


/* Indicates how many blocks are defined into the config file.
 * \return A positive value if no error.
 *         Else return a negative error code.
 */
int config_GetNbBlocks( config_file_t config );


/* Indicates the name of a block (specified with its index). */
char * config_GetBlockName( config_file_t config , int block_no );


/* Indicates how many peers (key-value) are defined in a block
 * (specified with its index).
 */
int config_GetNbKeys( config_file_t config, int block_no );


/* Retrieves a key-value peer from the block index and the key index. */  
int config_GetKeyValue( 
                        config_file_t config,
                        int block_no,
                        int key_no,
                        char ** var_name,
                        char ** var_value
                       );


/* Returns the block with the specified name. */
int config_GetBlockIndexByName( config_file_t config,
                                char * block_name );


/* Returns the value of the key with the specified name. */
char * config_GetKeyValueByName( config_file_t config,
                                 int block_no,
                                 char * key_name );





        
#endif
