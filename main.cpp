#include <iostream>

using namespace std;

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<windows.h>

void PrintDosInfo(IMAGE_DOS_HEADER dosHeader);
void PrintOptionInfo(IMAGE_OPTIONAL_HEADER64 optionHeader);
void PrintSectionInfo(IMAGE_SECTION_HEADER * sectionHeader,DWORD dwNumberOfSection);


DWORD SectionAligment;
DWORD FileAlignment;
DWORD64 ImageBase;
DWORD high,low;

//For 64bit Software

void main(int argc,char ** argv){
	FILE* fp;
	char  szFilePath[100]="C:\\Users\\Administrator\\Desktop\\notepad.exe";            
						//take care of the buffer size to avoid stackoverflow which will cause error(_checksec func(DEP) in default)
    IMAGE_DOS_HEADER dosHeader;
	WORD wSign;
	DWORD dwNumberOfSection;
	IMAGE_NT_HEADERS64 ntHeader;
	IMAGE_OPTIONAL_HEADER64 optionalHeader;
	IMAGE_SECTION_HEADER sectionHeader[100];
	
	// all the kernel struct above is not pointer	
/*
	if(argc!=2){
        printf("Usage:GetInfo.exe FilePath\n");
        exit(0);
    }
    strcpy(szFilePath,argv[1]);
*/

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
	PrintSectionInfo(sectionHeader,dwNumberOfSection);
	
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
	printf("IAT VA            :\t\t 0x%X%08X\n",high+(low+optionHeader.DataDirectory[1].VirtualAddress)/0xFFFFFFFF,low+optionHeader.DataDirectory[1].VirtualAddress);

}
void PrintSectionInfo(IMAGE_SECTION_HEADER * sectionHeader,DWORD dwNumberOfSection){
	IMAGE_SECTION_HEADER tmpSectionHeader;
	DWORD tmp_l,tmp_h,tmp_offset;
	for(int i=0;i<dwNumberOfSection;i++){
		tmpSectionHeader=sectionHeader[i];
		printf("Section Name      :\t\t %s\n",tmpSectionHeader.Name);
		tmp_l=tmpSectionHeader.VirtualAddress+low;tmp_h=high+(tmp_l)/0xFFFFFFFF;
		printf("Section Begin VA  :\t\t 0x%X%08X\n",tmp_h,tmp_l);
		tmp_offset=tmpSectionHeader.SizeOfRawData;
		if(tmp_offset%SectionAligment)
			tmp_offset=(tmp_offset/SectionAligment+1)*SectionAligment;
		tmp_l=tmp_l+tmp_offset;tmp_h=high+(tmp_l)/0xFFFFFFFF;
		//calculate the start VritualAddr and End VirtualAddr(Consider about the FileAlignment)
		printf("Section End VA    :\t\t 0x%X%08X\n",tmp_h,tmp_l);
		printf("--------------------------------------------------\n");
	}
		
}
