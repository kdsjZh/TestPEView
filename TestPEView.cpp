#include <iostream>

using namespace std;

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<windows.h>


void PrintDosInfo(IMAGE_DOS_HEADER dosHeader);
void PrintOptionInfo(IMAGE_OPTIONAL_HEADER64 optionHeader);
void PrintSectionInfo(IMAGE_SECTION_HEADER * sectionHeader,IMAGE_OPTIONAL_HEADER64 optionHeader,DWORD dwNumberOfSection,FILE* fp);
void PrintIAT(DWORD dwFileOffsetIAT,FILE *fp,
			  DWORD dwSectionBeginRVA[20],DWORD dwSectionEndRVA[20],
			  DWORD dwFileBeginOffset[20],DWORD dwFileEndOffset[20]);
DWORD ConvertVAToFOA(DWORD dwRVA,
					 DWORD dwSectionBeginRVA[20],DWORD dwSectionEndRVA[20],
					 DWORD dwFileBeginOffset[20],DWORD dwFileEndOffset[20]);
						//input VirtualAddr return FileOffset 
DWORD ConvertFOAToVA(DWORD dwFileOffset,
					 DWORD dwSectionBeginRVA[20],DWORD dwSectionEndRVA[20],
					 DWORD dwFileBeginOffset[20],DWORD dwFileEndOffset[20]);
						//input FileOffset return VirtualAddr
unsigned char*  GetDataByFOA(DWORD dwFileOffset,FILE *fp,DWORD dwSize);
						//input FileOffset return data in Addr(DWORD) in this Process

DWORD IsStr(unsigned char * str);

DWORD SectionAligment;
DWORD FileAlignment;
DWORD64 ImageBase;
DWORD high,low;

//For 64bit Software

void main(int argc,char ** argv){
	FILE* fp;
//	char  szFilePath[100]="C:\\Users\\Administrator\\Desktop\\notepad.exe";            
						//Test File
	char  szFilePath[100];
						//take care of the buffer size to avoid stackoverflow which will cause error(_checksec func(DEP) in default)
    IMAGE_DOS_HEADER dosHeader;
	WORD wSign;
	DWORD dwNumberOfSection;
	IMAGE_NT_HEADERS64 ntHeader;
	IMAGE_OPTIONAL_HEADER64 optionalHeader;
	IMAGE_SECTION_HEADER sectionHeader[100];
	
	// all the kernel struct above is not pointer	

	if(argc!=2){
        printf("Usage:GetInfo.exe FilePath\n");
        exit(0);
    }
    strcpy(szFilePath,argv[1]);


	fp=fopen(szFilePath,"rb");
    if(fp==NULL){
        printf("Failed Open File %s\n",szFilePath);
        exit(0);
    }
    fread(&dosHeader,sizeof(IMAGE_DOS_HEADER),1,fp);
                    // read the dos header
	wSign=dosHeader.e_magic;
    if(wSign!=(('Z'<<8)|'M')){
        printf("The file is not PE file!\n");
        exit(0);
    }
					//skip the DOS stub
					//after fread,the current pointer is removed(base pointer not)
	fseek(fp,dosHeader.e_lfanew,SEEK_SET);
					//add the offset from head(dosHeader.e_lfanew) to point the nt_header
					//Attention: e_lfanew is not the offset from end of dosHeader but the offset from the begin of file 
	fread(&ntHeader,sizeof(IMAGE_NT_HEADERS64),1,fp);
	optionalHeader=ntHeader.OptionalHeader;
					//OptionalHeader is a part of the ntHeader
	dwNumberOfSection=ntHeader.FileHeader.NumberOfSections;
	fread(&sectionHeader,sizeof(IMAGE_SECTION_HEADER)*dwNumberOfSection,1,fp);
					//SectionHeader Array is next to ntHEADER
	
	ImageBase=optionalHeader.ImageBase;
	high=ImageBase>>32;
	low=ImageBase&0xFFFFFFFF;
	SectionAligment=optionalHeader.SectionAlignment;
	FileAlignment=optionalHeader.FileAlignment;
					//Get the alignment to calulate the VA in memory(Global var)

	PrintDosInfo(dosHeader);
	printf("--------------------------------------------------\n");
	PrintOptionInfo(optionalHeader);
	printf("--------------------------------------------------\n");
	PrintSectionInfo(sectionHeader,optionalHeader,dwNumberOfSection,fp);
	
 }

void PrintDosInfo(IMAGE_DOS_HEADER dosHeader){
	printf("PE File Format checked!\n");
	printf("Size of Dos Stub  :\t\t 0x%X\n",dosHeader.e_lfanew-sizeof(IMAGE_DOS_HEADER));
}

void PrintOptionInfo(IMAGE_OPTIONAL_HEADER64 optionHeader){
	printf("Code size         :\t\t 0x%X\n",optionHeader.SizeOfCode);
	printf("ImageBase(Default):\t\t 0x%X%08X\n",high,low);
					//Attention: size of ImageBase is DWORD64(QWORD)
	printf("OEP(Default)      :\t\t 0x%X%08X\n",high+(low+optionHeader.AddressOfEntryPoint)/0xFFFFFFFF,low+optionHeader.AddressOfEntryPoint);
	printf("FileAlignment     :\t\t 0x%X\n",FileAlignment);
	printf("SectionAlignment  :\t\t 0x%X\n",SectionAligment);
	printf("IAT VA            :\t\t 0x%X%08X\n",high+(low+optionHeader.DataDirectory[1].VirtualAddress)/0xFFFFFFFF,low+optionHeader.DataDirectory[1].VirtualAddress);

}
void PrintSectionInfo(IMAGE_SECTION_HEADER * sectionHeader,IMAGE_OPTIONAL_HEADER64 optionHeader,DWORD dwNumberOfSection ,FILE* fp){
	IMAGE_SECTION_HEADER tmpSectionHeader;
	DWORD tmp_l,tmp_h,tmp_offset;
	DWORD dwSectionBeginRVA[20],dwSectionEndRVA[20];
	DWORD dwFileBeginOffset[20],dwFileEndOffset[20];
	DWORD dwFileOffsetIAT;
	for(int i=0;i<dwNumberOfSection;i++){
		tmpSectionHeader=sectionHeader[i];
		printf("Section Name      :\t\t %s\n",tmpSectionHeader.Name);
		tmp_l=tmpSectionHeader.VirtualAddress+low;tmp_h=high+(tmp_l)/0xFFFFFFFF;
		dwSectionBeginRVA[i]=tmp_l;
		printf("Section Begin VA  :\t\t 0x%X%08X\n",tmp_h,dwSectionBeginRVA[i]);
		tmp_offset=tmpSectionHeader.SizeOfRawData;
		if(tmp_offset%SectionAligment)
			tmp_offset=(tmp_offset/SectionAligment+1)*SectionAligment;
		tmp_l=tmp_l+tmp_offset;tmp_h=high+(tmp_l)/0xFFFFFFFF;
		dwSectionEndRVA[i]=tmp_l;
					//calculate the start VritualAddr and End VirtualAddr(Consider about the FileAlignment)
		printf("Section End VA    :\t\t 0x%X%08X\n",tmp_h,dwSectionEndRVA[i]);

		
		dwFileBeginOffset[i]=tmpSectionHeader.PointerToRawData;
		tmp_offset=tmpSectionHeader.SizeOfRawData;
		if(tmp_offset%FileAlignment)
			tmp_offset=(tmp_offset/FileAlignment+1)*FileAlignment;
		dwFileEndOffset[i]=dwFileBeginOffset[i]+tmp_offset;
		printf("File Begin Offset :\t\t 0x%X\n",dwFileBeginOffset[i]);
		printf("File End Offset   :\t\t 0x%X\n",dwFileEndOffset[i]);

		printf("--------------------------------------------------\n");
	}
	for(i=0;i<dwNumberOfSection;i++)
		if(dwSectionBeginRVA[i]<=optionHeader.DataDirectory[1].VirtualAddress&&
			dwSectionEndRVA[i]>optionHeader.DataDirectory[1].VirtualAddress){
			dwFileOffsetIAT=optionHeader.DataDirectory[1].VirtualAddress-dwSectionBeginRVA[i]+dwFileBeginOffset[i];
			PrintIAT(dwFileOffsetIAT,fp,
				dwSectionBeginRVA,dwSectionEndRVA,
				dwFileBeginOffset,dwFileEndOffset);
					//RVA-SectionAlignment=FOA-FileAlignment
			break;
		}
		
}

void PrintIAT(DWORD dwFileOffsetIAT,FILE *fp,
			  DWORD dwSectionBeginRVA[20],DWORD dwSectionEndRVA[20],
			  DWORD dwFileBeginOffset[20],DWORD dwFileEndOffset[20]){
					//dwImportRVA is the offset from the begin of the section
	IMAGE_IMPORT_DESCRIPTOR imageIAT[100];
					//remember not to use pointer(pointer needs to malloc space)
					//IID's size is not included in PE head
	DWORD nIID;
	IMAGE_THUNK_DATA * pImageThunk;
	IMAGE_THUNK_DATA imageThunk;
	IMAGE_IMPORT_BY_NAME * pImportByName;

	DWORD sizeOfStr,space;
	
	fseek(fp,dwFileOffsetIAT,SEEK_SET);
					//set fp to read the IAT struct
	for(int i=0;i<20;i++){
		fread(&imageIAT[i],sizeof(IMAGE_IMPORT_DESCRIPTOR),1,fp);
		if(imageIAT[i].Characteristics==NULL){
			nIID=i;
					//the last one is the MZ..
			printf("IID number        :\t\t %d\n",nIID);
			break;
		}
	}
	for(i=0;i<nIID;i++){
		printf("DLL Name          :\t\t %s\n",GetDataByFOA(ConvertVAToFOA(imageIAT[i].Name,
															dwSectionBeginRVA,dwSectionEndRVA,
															dwFileBeginOffset,dwFileEndOffset),fp,20));
					//Attention:Here imageName is RVA ,so convert RVA to FOA ,then Get data at the FOA 
					//Read More than len of DLL Name ,the res won't be print(0x00 break)

		pImageThunk=(IMAGE_THUNK_DATA *)GetDataByFOA(ConvertVAToFOA(imageIAT[i].OriginalFirstThunk,
			dwSectionBeginRVA,dwSectionEndRVA,
			dwFileBeginOffset,dwFileEndOffset),fp,sizeof(IMAGE_THUNK_DATA));
		imageThunk=*pImageThunk;
					//ImageThunk store a DWORD size RVA;
		pImportByName=(IMAGE_IMPORT_BY_NAME *)GetDataByFOA(ConvertVAToFOA((DWORD)imageThunk.u1.Function,
			dwSectionBeginRVA,dwSectionEndRVA,
			dwFileBeginOffset,dwFileEndOffset),fp,0x1000);
					//read a large amount of space include all the API in DLL or read it in the while(){}
					//Each DLL's API info is less than 0x1000
		while((*pImportByName).Hint!=0){
					//Attention: IMPORT_BY_NAME.name takes only 2 char(WORD size),which can't store the entire API Name
					//To get the API Name ,we should use (unsigned char *)&importByName.name as a ptr to string
					//and we should read more data than sizeof IMAGE_IMPOR_BY_NAME as well
			printf("\tAPI Name      :\t\t %s\n",(char *)&((*pImportByName).Name[0]));
			printf("\tAPI Hint      :\t\t 0x%X\n",(*pImportByName).Hint);
					//Because part of the API name wasn't in the struct,so we need to analyze the size of the ImportByName struct
			sizeOfStr=strlen((char *)&((*pImportByName).Name[0]));
			space=1;
			if(*(((char *)pImportByName)+sizeOfStr+sizeof(WORD)+1)==0x00)
				space=2;
			pImportByName=(IMAGE_IMPORT_BY_NAME *)(((char *)pImportByName)+sizeOfStr+sizeof(WORD)+space);
			if(!IsStr((unsigned char *)&((*pImportByName).Name[0])))
				break;
					//between two IMAGE_IMPORT_BY_NAME is 2(some is only 1) 0x00',and there is a WORD Hint 
/*
			if(strcmp((char *)&((*pImportByName).Name[0]),"GetFileVersionInfoSizeExW")==NULL){
				_asm int 3;
			}
					// After GetFileV... func error appear
*/
		}
	}

}

DWORD ConvertVAToFOA(DWORD dwRVA,
					 DWORD dwSectionBeginRVA[20],DWORD dwSectionEndRVA[20],
					 DWORD dwFileBeginOffset[20],DWORD dwFileEndOffset[20]){
	for(int i=0;i<20;i++){
		if(dwRVA>=dwSectionBeginRVA[i]&&
			dwRVA<dwSectionEndRVA[i]){
			return(dwRVA-dwSectionBeginRVA[i]+dwFileBeginOffset[i]);
		}
			
	}
	return 0;
}

DWORD ConvertFOAToVA(DWORD dwFileOffset,
					 DWORD dwSectionBeginRVA[20],DWORD dwSectionEndRVA[20],
					 DWORD dwFileBeginOffset[20],DWORD dwFileEndOffset[20]){
	for(int i=0;i<20;i++){
		if(dwFileOffset>=dwFileBeginOffset[i]&&
			dwFileOffset<dwFileEndOffset[i]){
			return(dwFileOffset-dwFileBeginOffset[i]+dwSectionBeginRVA[i]);
		}
	}
	return 0;
}
unsigned char* GetDataByFOA(DWORD dwFileOffset,FILE *fp,DWORD dwSize){
	unsigned char * tmp=(unsigned char *)malloc(dwSize+1);
	fseek(fp,dwFileOffset,SEEK_SET);
	fread(tmp,sizeof(char)*dwSize,1,fp);
	return tmp;
}

DWORD IsStr(unsigned char * str){
	if((str[0]>='A'&&str[0]<='Z')|(str[0]>='a'&&str[0]<='Z'))
		return 1;
	if((str[1]>='A'&&str[1]<='Z')|(str[1]>='a'&&str[1]<='Z'))
		return 1;
			//check 2 byte to avoid offset
	return 0;
}