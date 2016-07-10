import std.stdio;
import core.exception;

alias uint DWORD;
alias ushort WORD;
alias byte BYTE;
alias ulong ULONGLONG;

const IMAGE_NUMBEROF_DIRECTORY_ENTRIES=16;

struct IMAGE_DOS_HEADER {
   WORD  e_magic;      /* 00: MZ Header signature */
   WORD  e_cblp;       /* 02: Bytes on last page of file */
   WORD  e_cp;         /* 04: Pages in file */
   WORD  e_crlc;       /* 06: Relocations */
   WORD  e_cparhdr;    /* 08: Size of header in paragraphs */
   WORD  e_minalloc;   /* 0a: Minimum extra paragraphs needed */
   WORD  e_maxalloc;   /* 0c: Maximum extra paragraphs needed */
   WORD  e_ss;         /* 0e: Initial (relative) SS value */
   WORD  e_sp;         /* 10: Initial SP value */
   WORD  e_csum;       /* 12: Checksum */
   WORD  e_ip;         /* 14: Initial IP value */
   WORD  e_cs;         /* 16: Initial (relative) CS value */
   WORD  e_lfarlc;     /* 18: File address of relocation table */
   WORD  e_ovno;       /* 1a: Overlay number */
   WORD  e_res[4];     /* 1c: Reserved words */
   WORD  e_oemid;      /* 24: OEM identifier (for e_oeminfo) */
   WORD  e_oeminfo;    /* 26: OEM information; e_oemid specific */
   WORD  e_res2[10];   /* 28: Reserved words */
   DWORD e_lfanew;     /* 3c: Offset to extended header */
};

struct IMAGE_NT_HEADERS{
  DWORD                 Signature;
  IMAGE_FILE_HEADER     FileHeader;
}

struct IMAGE_FILE_HEADER {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
};

struct IMAGE_OPTIONAL_HEADER32 {
  WORD                 Magic;
  BYTE                 MajorLinkerVersion;
  BYTE                 MinorLinkerVersion;
  DWORD                SizeOfCode;
  DWORD                SizeOfInitializedData;
  DWORD                SizeOfUninitializedData;
  DWORD                AddressOfEntryPoint;
  DWORD                BaseOfCode;
  DWORD                BaseOfData;
  DWORD                ImageBase;
  DWORD                SectionAlignment;
  DWORD                FileAlignment;
  WORD                 MajorOperatingSystemVersion;
  WORD                 MinorOperatingSystemVersion;
  WORD                 MajorImageVersion;
  WORD                 MinorImageVersion;
  WORD                 MajorSubsystemVersion;
  WORD                 MinorSubsystemVersion;
  DWORD                Win32VersionValue;
  DWORD                SizeOfImage;
  DWORD                SizeOfHeaders;
  DWORD                CheckSum;
  WORD                 Subsystem;
  WORD                 DllCharacteristics;
  DWORD                SizeOfStackReserve;
  DWORD                SizeOfStackCommit;
  DWORD                SizeOfHeapReserve;
  DWORD                SizeOfHeapCommit;
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct IMAGE_OPTIONAL_HEADER64 {
 WORD        Magic;
 BYTE        MajorLinkerVersion;
 BYTE        MinorLinkerVersion;
 DWORD       SizeOfCode;
 DWORD       SizeOfInitializedData;
 DWORD       SizeOfUninitializedData;
 DWORD       AddressOfEntryPoint;
 DWORD       BaseOfCode;
 ULONGLONG   ImageBase;
 DWORD       SectionAlignment;
 DWORD       FileAlignment;
 WORD        MajorOperatingSystemVersion;
 WORD        MinorOperatingSystemVersion;
 WORD        MajorImageVersion;
 WORD        MinorImageVersion;
 WORD        MajorSubsystemVersion;
 WORD        MinorSubsystemVersion;
 DWORD       Win32VersionValue;
 DWORD       SizeOfImage;
 DWORD       SizeOfHeaders;
 DWORD       CheckSum;
 WORD        Subsystem;
 WORD        DllCharacteristics;
 ULONGLONG   SizeOfStackReserve;
 ULONGLONG   SizeOfStackCommit;
 ULONGLONG   SizeOfHeapReserve;
 ULONGLONG   SizeOfHeapCommit;
 DWORD       LoaderFlags;
 DWORD       NumberOfRvaAndSizes;
 IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
}

struct PEFileStatistics{
    ushort Machine;
    ushort Subsystem;
    ushort DllCharacteristics;
    int applicationBits;
    ulong  ImageBase;
    ulong  AddressOfEntryPoint;
    ulong  BaseOfCode;
    ulong  SizeOfCode;
    ulong SizeOfImage;
}

class PEFile{
    static bool initialized = false;
    static string[int] machineTypes;
    File file;
    IMAGE_NT_HEADERS peHeader;
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_OPTIONAL_HEADER64 optHeader64;
    IMAGE_OPTIONAL_HEADER32 optHeader32;
    PEFileStatistics pefileStat;

    public this(){
    }
    public ~this(){
    }

    public this(string fileName){
        openPEFile_sub(fileName);
    }

    public void openPEFile(string fileName){
        if(file.isOpen()!=true){
            openPEFile_sub(fileName);
        }
    }

    private void openPEFile_sub(string file){
        this.file = File(file,"rb");
        this.file.rawRead((&dosHeader)[0..1]);
        if(dosHeader.e_magic!=0x5a4d){  // MZ
            throw new Exception("Invalid MZ Header.");
        }
        this.file.seek(dosHeader.e_lfanew);
        this.file.rawRead((&peHeader)[0..1]);
        if(peHeader.Signature != 0x4550){  // PE
            throw new Exception("Invalid PE Header.");
        }

        pefileStat.Machine=peHeader.FileHeader.Machine;

        switch(peHeader.FileHeader.SizeOfOptionalHeader){
            case IMAGE_OPTIONAL_HEADER64.sizeof:
                PEx64Read();
                break;
            case IMAGE_OPTIONAL_HEADER32.sizeof:
                PEx86Read();
                break;
            default:
                throw new Exception("Invalid image optional header.");
        }
    }
    
    private void PEx64Read(){
        this.file.rawRead((&optHeader64)[0..1]);
        pefileStat.applicationBits = 64;
        pefileStat.ImageBase = optHeader64.ImageBase;
        pefileStat.AddressOfEntryPoint = optHeader64.AddressOfEntryPoint;
        pefileStat.BaseOfCode = optHeader64.BaseOfCode;
        pefileStat.SizeOfCode = optHeader64.SizeOfCode;
        pefileStat.Subsystem = optHeader64.Subsystem;

        pefileStat.DllCharacteristics = optHeader64.DllCharacteristics;
        pefileStat.SizeOfImage = optHeader64.SizeOfImage;
    }
    private void PEx86Read(){
        this.file.rawRead((&optHeader32)[0..1]);
        pefileStat.applicationBits = 32;
        pefileStat.ImageBase = optHeader32.ImageBase;
        pefileStat.AddressOfEntryPoint = optHeader32.AddressOfEntryPoint;
        pefileStat.BaseOfCode = optHeader32.BaseOfCode;
        pefileStat.SizeOfCode = optHeader32.SizeOfCode;
        pefileStat.Subsystem = optHeader32.Subsystem;
        pefileStat.DllCharacteristics = optHeader32.DllCharacteristics;
        pefileStat.SizeOfImage = optHeader32.SizeOfImage;
    }

    public string machineType(){
        if(initialized == false){
            return "not initialize. => Please call PEFile.init();";
        }
        const string* v =  pefileStat.Machine in machineTypes;
        if(v==null){
            return "Other platform.";
        }else{
            return *v;
        }
    }
    const static string[16] peSubsystem=[
        "Unknown","Native","Windows GUI","Windows CUI",
        "Unknown(Reserve)","OS/2 CUI","Unknown(Reserve)","POSIX CUI",
        "Unknown(Reserve)","Windows CE/GUI","EFI Application","EFI Boot Service Driver",
        "EFI Runtime Driver","EFI ROM","XBOX","Windows Boot Application"
    ];
    public string getSubsystem(){
        if( 0 <= pefileStat.Subsystem && pefileStat.Subsystem < peSubsystem.length ){
            return peSubsystem[pefileStat.Subsystem];
        }
        return "Unknown";
    }

    public PEFileStatistics getPEStatistics(){
        return pefileStat;
    }

    static void init(){
        if(machineTypes.length == 0){
            machineTypes=[
                0x0:"UNKNOWN",0x14c:"i386",0x162:"R3000",
                0x166:"R4000",0x168:"R10000",0x184:"ALPHA",
                0x268:"M68K",0x1f0:"POWERPC",0x1a2:"SH3",
                0x1a6:"SH4", 0x1c0:"ARM",0x8664:"x64",
                0x0200:"IA64"
            ];
            initialized = true;
        }
    }
}

void main(string args[]){
    if(args.length < 2){
        writef("missing argument.");
        return;
    }
    PEFile.init();
    try
    {
        PEFile pe = new PEFile(args[1]);
        showPeStat(pe); 
    }
    catch (Exception e)
    {
        writef("%s",e.msg);
    }
}

void showPeStat(PEFile pe){
    auto pefileStat = pe.getPEStatistics();
    writef("Machine: %s\n",pe.machineType());
    writef("applicationBits: %d\n",pefileStat.applicationBits);
    writef("Subsystem: %s\n",pe.getSubsystem());
    writef("ImageBase: 0x%x\n",pefileStat.ImageBase);
    writef("BaseOfCode: 0x%x\n", pefileStat.BaseOfCode);
    writef("SizeOFCode: %d\n",pefileStat.SizeOfCode);
    writef("AddressOfEntryPoint: %x\n",pefileStat.AddressOfEntryPoint);
    writef("Absolute entry point: %x\n",pefileStat.ImageBase + pefileStat.AddressOfEntryPoint);
    writef("SizeOfImage: %d\n",pefileStat.SizeOfImage);
}