/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file util/test_bio.c
 * @brief testcase for the buffered IO module
 * @author Ji Lu
 */


#include "platform.h"
#include "gnunet_util_lib.h"
#define TESTSTRING "testString"
#define TESTNUMBER64 100000L

int
main (int argc, char *argv[])
{

    char *readResultString;
	int64_t testNumber = (int64_t)TESTNUMBER64;
	int64_t testNum;
	char *msg;
    char file[102400];
    char meta[1024*1024*10];
    int i,j;
    for(i=0;i<102400;i++){
    	file[i]='a';
    }
    for(j=0;j<1024*1024*10;j++){
    	meta[j]='b';
    }
	char* fileName = GNUNET_DISK_mktemp ("gnunet_bio");
	char* fileName2 = GNUNET_DISK_mktemp ("gnunet_zwei_bio");
	char* fileName3 = GNUNET_DISK_mktemp ("gnunet_drei_bio");
	char* fileName4 = GNUNET_DISK_mktemp ("gnunet_vier_bio");

	struct GNUNET_BIO_ReadHandle *fileR,*fileR2,*fileR3,*fileR4;
	struct GNUNET_BIO_WriteHandle *fileW,*fileW2,*fileW3,*fileW4;
	struct GNUNET_CONTAINER_MetaData *metaDataW;
	struct GNUNET_CONTAINER_MetaData *metaDataR;
	struct GNUNET_BIO_ReadHandle *fileRNO;
	struct GNUNET_BIO_WriteHandle *fileWNO;
	struct GNUNET_CONTAINER_MetaData *metaData;
	struct GNUNET_CONTAINER_MetaData *metaDataNO;

	metaData = GNUNET_CONTAINER_meta_data_create();
	metaDataNO = GNUNET_CONTAINER_meta_data_create();
	metaDataR = GNUNET_CONTAINER_meta_data_create();
	metaDataW = GNUNET_CONTAINER_meta_data_create();
	GNUNET_CONTAINER_meta_data_add_publication_date(metaDataW);
	GNUNET_CONTAINER_meta_data_add_publication_date(metaData);
	GNUNET_assert(GNUNET_OK == GNUNET_CONTAINER_meta_data_insert(metaData,EXTRACTOR_COMMENT,meta));

///////////write
	fileW = GNUNET_BIO_write_open(fileName);
	GNUNET_assert(NULL != fileW);
	GNUNET_assert(GNUNET_OK == GNUNET_BIO_write_string(fileW, TESTSTRING));
	GNUNET_assert(GNUNET_OK == GNUNET_BIO_write_meta_data(fileW,metaDataW));
	GNUNET_assert(GNUNET_OK == GNUNET_BIO_write_int64(fileW,testNumber));
	GNUNET_assert(GNUNET_OK == GNUNET_BIO_write_close(fileW));
	fileW2 = GNUNET_BIO_write_open(fileName2);
	GNUNET_assert(NULL != fileW2);
	GNUNET_assert(GNUNET_OK == GNUNET_BIO_write_string(fileW2,NULL));
   	fileWNO = GNUNET_BIO_write_open(file);
   	fileW3 = GNUNET_BIO_write_open(fileName3);
   	GNUNET_assert(NULL != fileW3);
   	GNUNET_assert(GNUNET_OK == GNUNET_BIO_write_meta_data(fileW3,metaData));
   	fileW4 = GNUNET_BIO_write_open(fileName4);
   	GNUNET_assert(NULL != fileW4);
   	GNUNET_assert(GNUNET_OK == GNUNET_BIO_write_string(fileW4,""));
	GNUNET_assert(NULL != fileWNO);
	GNUNET_assert(GNUNET_SYSERR == GNUNET_BIO_write_string(fileWNO, TESTSTRING));
	GNUNET_assert(GNUNET_SYSERR == GNUNET_BIO_write_meta_data(fileWNO,metaDataW));
	GNUNET_assert(GNUNET_SYSERR == GNUNET_BIO_write_close(fileWNO));

////////////read
 	fileRNO = GNUNET_BIO_read_open(file);
	GNUNET_assert(NULL != fileRNO);
	GNUNET_assert(GNUNET_SYSERR == GNUNET_BIO_read_string(fileRNO, "Read string error", &readResultString, 200));
	GNUNET_assert(GNUNET_SYSERR == GNUNET_BIO_read_int64(fileRNO, &testNum));
	GNUNET_assert(GNUNET_SYSERR == GNUNET_BIO_read_meta_data(fileRNO,"Read meta error", &metaDataNO));
	fileR = GNUNET_BIO_read_open(fileName);
	GNUNET_assert(NULL != fileR);
	GNUNET_assert(GNUNET_OK == GNUNET_BIO_read_string(fileR, "Read string error", &readResultString, 200));
	GNUNET_assert(GNUNET_OK == GNUNET_BIO_read_meta_data(fileR, "Read meta error", &metaDataR));
	GNUNET_assert(GNUNET_YES == GNUNET_CONTAINER_meta_data_test_equal(metaDataR,metaDataW));
    GNUNET_assert(GNUNET_OK == GNUNET_BIO_read_int64(fileR, &testNum));
	fileR2 = GNUNET_BIO_read_open(fileName2);
    GNUNET_assert(NULL != fileR2);
    GNUNET_assert(GNUNET_SYSERR == GNUNET_BIO_read_string(fileR2, "Read string error", &readResultString, 200));
	fileR3 = GNUNET_BIO_read_open(fileName3);
    GNUNET_assert(NULL != fileR3);
    GNUNET_assert(GNUNET_SYSERR == GNUNET_BIO_read_meta_data(fileR3, "Read meta error", &metaDataR));
    fileR4 = GNUNET_BIO_read_open(fileName4);
    GNUNET_assert(NULL != fileR4);
    GNUNET_assert(GNUNET_OK == GNUNET_BIO_read_string(fileR4, "Read string error", &readResultString, 200));
    GNUNET_BIO_read_close(fileR,&msg);
    GNUNET_BIO_read_close(fileR2,&msg);
    GNUNET_BIO_read_close(fileR3,&msg);
    GNUNET_BIO_read_close(fileR4,&msg);
	GNUNET_CONTAINER_meta_data_destroy(metaDataW);
	GNUNET_CONTAINER_meta_data_destroy(metaDataNO);
	GNUNET_CONTAINER_meta_data_destroy(metaDataR);
	GNUNET_CONTAINER_meta_data_destroy(metaData);
    GNUNET_free(fileName);
    GNUNET_free(fileName2);
    GNUNET_free(fileName3);
    GNUNET_free(fileName4);


    return 0;

}                               /* end of main */
