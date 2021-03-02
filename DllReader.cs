//****************************************************************************
// Copyright (c) 2005-2015, Coveo Solutions Inc.
//****************************************************************************

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.CompilerServices;

//using Coveo.Cmf;

//************************************************************************
// These classes are used to load a PE (Windows) executable to extract information
// about whether this is a pure C# exec, etc.
//
// For Linux, the header is an ELF (Executable and Linkable Format). No support for it right now.
//************************************************************************
namespace Coveo.Cdf.DllUtil
{
    using BYTE = Byte;
    using WORD = UInt16;
    using USHORT = UInt16;
    using DWORD = UInt32;
    using LONG = Int32;
    using ULONG = UInt32;
    using ULONGLONG = UInt64;

    //************************************************************************
    /// <summary>
    /// Information about an executable file
    /// </summary>
    //************************************************************************
    [Flags]
    public enum FileImageFlags
    {
        IsExe = 0x01,
        IsDll = 0x02,
        Is32Bits = 0x04,
        Is64Bits = 0x08,
        IsClr = 0x10
    }

    //************************************************************************
    /// <summary>
    /// Flags for the extraction of DLL dependencies
    /// </summary>
    //************************************************************************
    [Flags]
    public enum DllFlags
    {
        IsDelayed = 0x01,   // I keep it and compute it only for the flags' ToString
        IsWindows = 0x02,
        IsMsvcrt  = 0x04,
        HasError  = 0x08    // Probably not found
    }

    //************************************************************************
    /// <summary>
    /// Will open a DLL or EXE file and provide different informations on it.
    /// </summary>
    //************************************************************************
    public unsafe class DllReader : IDisposable
    {
        private MmfFile m_Mmf;

        public FileImageFlags Flags { get { return m_Flags; } }
        private FileImageFlags m_Flags;

        /// <summary>
        /// To differentiate Managed C++ DLLs.
        /// </summary>
        public bool IsPureClr {
            get { return pCorHeader != null && (pCorHeader->Flag & (uint)ReplacesCorHdrNumericDefines.COMIMAGE_FLAGS_ILONLY) != 0; }
        }

        private IMAGE_DOS_HEADER* pDos;                 // Ptr on the first part of the file; the DOS header
        private IMAGE_FILE_HEADER* pPe;                 // Ptr on the PE header, also called COFF
        private byte* pPeOpt;                           // Ptr on the optional PE header (byte* because can be either IMAGE_OPTIONAL_HEADER32 or IMAGE_OPTIONAL_HEADER64)
        private IMAGE_DATA_DIRECTORY* pDataDirectory;   // Ptr on the whole DATA_DIRECTORY array
        private IMAGE_SECTION_HEADER* pSection;         // Ptr on the whole SECTION array
        private IMAGE_COR20_HEADER* pCorHeader;         // Ptr on the CLR header; null if not .Net assembly

        public List<DllDependency> DllDependencies { get { SetDllDependencies(); return m_DllDependencies; } }
        private List<DllDependency> m_DllDependencies;

        public List<AssemblyReference> AssemblyReferences { get { SetAssemblyReferences(); return m_AssemblyReferences; } }
        private List<AssemblyReference> m_AssemblyReferences;

        //************************************************************************
        /// <summary>
        /// Ctor
        /// </summary>
        /// <param name="fileName"></param>
        //************************************************************************
        public DllReader(string fileName)
        {
            // Open the file, and compute the minimum flags
            m_Mmf = new MmfFile(fileName);
            m_Flags = 0;
            pDos = (IMAGE_DOS_HEADER*)m_Mmf.GetPtr(0);
            // "MZ"
            if (pDos->e_magic != IMAGE_DOS_HEADER.IMAGE_DOS_SIGNATURE) {
                return;
            }
            pPe = (IMAGE_FILE_HEADER*)m_Mmf.GetPtr((uint)pDos->e_lfanew);
            // "PE"
            if (pPe->Magic != IMAGE_FILE_HEADER.IMAGE_NT_SIGNATURE) {
                return;
            }
            WORD characteristics = pPe->Characteristics;
            bool is32 = (characteristics & IMAGE_FILE_HEADER.IMAGE_FILE_32BIT_MACHINE) != 0;
            pPeOpt = (byte*)(pPe + 1);
            pDataDirectory = null;
            WORD peOptMagic = *(WORD*)pPeOpt;
            // Some files, like Coveo.CES.Interops.dll fail the test below.
            //      But by extracting m_pDataDirectory using "peOptMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC" instead
            //      of using m_Is32 works !
            //if ((is32 && peOptMagic != IMAGE_OPTIONAL_HEADER32.IMAGE_NT_OPTIONAL_HDR32_MAGIC) ||
            //    (!is32 && peOptMagic != IMAGE_OPTIONAL_HEADER32.IMAGE_NT_OPTIONAL_HDR64_MAGIC)) {
            //    throw new Exception("Mismatching magic numbers");
            //}
            pDataDirectory = (peOptMagic == IMAGE_OPTIONAL_HEADER32.IMAGE_NT_OPTIONAL_HDR32_MAGIC
                ? (IMAGE_DATA_DIRECTORY*)((IMAGE_OPTIONAL_HEADER32*)pPeOpt)->DataDirectory
                : (IMAGE_DATA_DIRECTORY*)((IMAGE_OPTIONAL_HEADER64*)pPeOpt)->DataDirectory);
            m_Flags |= ((characteristics & IMAGE_FILE_HEADER.IMAGE_FILE_DLL) == 0 ? FileImageFlags.IsExe : FileImageFlags.IsDll);
            m_Flags |= (is32 ? FileImageFlags.Is32Bits : FileImageFlags.Is64Bits);
            // Compute pSection before calling GetPhysicalFromVirtual
            pSection = (IMAGE_SECTION_HEADER*)((byte*)pPeOpt + pPe->SizeOfOptionalHeader);
            // Also compute pCorHeader
            DWORD cliHdrOff = pDataDirectory[IMAGE_DATA_DIRECTORY.COM_DESCRIPTOR].VirtualAddress;
            if (cliHdrOff != 0) {
                m_Flags |= FileImageFlags.IsClr;
                pCorHeader = (IMAGE_COR20_HEADER*)GetPhysicalFromVirtual(cliHdrOff);
            }
        }

        //************************************************************************
        /// <summary>
        /// Try to find the given name in the exported symbols.
        /// </summary>
        //************************************************************************
        public bool FindExport(string name)
        {
            uint rva = pDataDirectory[IMAGE_DATA_DIRECTORY.EXPORT].VirtualAddress;
            if (rva != 0) {
                IMAGE_EXPORT_DIRECTORY* pExport = (IMAGE_EXPORT_DIRECTORY*)GetPhysicalFromVirtual(rva);
                uint rvaAllStringsBase = pExport->AddressOfNames;
                // Not really strings, rather rvas, but I keep the base to avoid calling GetPhysicalFromVirtual for each string...
                if (rvaAllStringsBase != 0) {
                    sbyte* pAllStringsBase = (sbyte*)GetPhysicalFromVirtual(rvaAllStringsBase);
                    uint* pRvaString = (uint*)pAllStringsBase;
                    for (int i = 0; i < pExport->NumberOfNames; ++i, ++pRvaString) {
                        sbyte* pName = pAllStringsBase + (*pRvaString - rvaAllStringsBase);
                        string s = new string(pName);
                        if ( string.Equals(s, name, StringComparison.OrdinalIgnoreCase)) {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        //************************************************************************
        /// <summary>
        /// Fills the m_DllDependencies field
        /// </summary>
        //************************************************************************
        private void SetDllDependencies()
        {
            if (m_DllDependencies != null)
                return;
            m_DllDependencies = new List<DllDependency>();

            // Normal import entries
            uint rva = pDataDirectory[IMAGE_DATA_DIRECTORY.IMPORT].VirtualAddress;
            if (rva != 0) {
                for (IMAGE_IMPORT_DESCRIPTOR* pDesc = (IMAGE_IMPORT_DESCRIPTOR*)GetPhysicalFromVirtual(rva); ; ++pDesc) {
                    // The doc says if Characteristics is 0, we're done. But asmex doesn't do it like that because it says old PEs behave differently !!
                    if (pDesc->Characteristics == 0)
                        break;
                    uint rvaName = pDesc->Name;
                    byte* pName = GetPhysicalFromVirtual(rvaName);
                    DllDependency dep = new DllDependency(new string((sbyte*)pName), 1, 0);
                    m_DllDependencies.Add(dep);
                }
            }

            // Delayed import entries
            rva = pDataDirectory[IMAGE_DATA_DIRECTORY.DELAY_IMPORT].VirtualAddress;
            if (rva != 0) {
                for (IMAGE_DELAY_IMPORT_DESCRIPTOR* pDesc = (IMAGE_DELAY_IMPORT_DESCRIPTOR*)GetPhysicalFromVirtual(rva); ; ++pDesc) {
                    // The doc says if Characteristics is 0, we're done. But asmex doesn't do it like that because it says old PEs behave differently !!
                    if (pDesc->Attrs == 0)
                        break;
                    uint rvaName = pDesc->Name;
                    byte* pName = GetPhysicalFromVirtual(rvaName);
                    DllDependency dep = new DllDependency(new string((sbyte*)pName), 0, 1);
                    m_DllDependencies.Add(dep);
                }
            }
        }

        //************************************************************************
        /// <summary>
        /// Fills the m_AssemblyReferences field.
        /// </summary>
        //************************************************************************
        private void SetAssemblyReferences()
        {
            if (m_AssemblyReferences != null)
                return;
            m_AssemblyReferences = new List<AssemblyReference>();
            if (pCorHeader == null)
                return;
            uint rvaMetaData = ((IMAGE_DATA_DIRECTORY*)pCorHeader->MetaData)->VirtualAddress;
            if (rvaMetaData == 0)
                return;
            MetaDataHeaders metaDataHeaders = new MetaDataHeaders(GetPhysicalFromVirtual(rvaMetaData));
            metaDataHeaders.ComputeTableOffsets();
            foreach (Row row in metaDataHeaders.Tables.Tables[(int)Types.AssemblyRef].Rows) {
                m_AssemblyReferences.Add(new AssemblyReference(row[6] as string));
            }
            // Doesn't really belong here (C++ DLLs used by .Net assembly), but just to make sure it works...
            foreach (Row row in metaDataHeaders.Tables.Tables[(int)Types.ModuleRef].Rows) {
                m_AssemblyReferences.Add(new AssemblyReference(row[0] as string));
            }
        }

        //************************************************************************
        /// <summary>
        /// Reads the Version resource and extracts the VersionInfo strings from it.
        /// </summary>
        //************************************************************************
        public string[] ReadVersionInfo()
        {
            byte* pResources = GetPhysicalFromVirtual(pDataDirectory[IMAGE_DATA_DIRECTORY.RESOURCE].VirtualAddress);
            IMAGE_RESOURCE_DIRECTORY* prdRoot = (IMAGE_RESOURCE_DIRECTORY*)pResources;

            List<string> infos = new List<string>();
            ResourceDirEnum enumLevel0 = new ResourceDirEnum(pResources, 0, 0);
            IMAGE_RESOURCE_DIRECTORY_ENTRY* pDirLevel0;
            while ((pDirLevel0 = enumLevel0.Next()) != null) {
                // Filter on the 'Version' resource type.
                if (pDirLevel0->Name == (ULONG)ResourceType.Version) {
                    ResourceDirEnum enumLevel1 = new ResourceDirEnum(enumLevel0, pDirLevel0->OffsetToData);
                    IMAGE_RESOURCE_DIRECTORY_ENTRY* pDirLevel1;
                    while ((pDirLevel1 = enumLevel1.Next()) != null) {
                        ResourceDirEnum enumLevel2 = new ResourceDirEnum(enumLevel1, pDirLevel1->OffsetToData);
                        IMAGE_RESOURCE_DIRECTORY_ENTRY* pDirLevel2;
                        while ((pDirLevel2 = enumLevel2.Next()) != null) {
                            IMAGE_RESOURCE_DATA_ENTRY* pData = enumLevel2.GetDataEntry(pDirLevel2);
                            ReadVersionFileInfo(GetPhysicalFromVirtual(pData->OffsetToData), infos);
                        }
                    }
                }
            }
            return infos.ToArray();
        }

        //************************************************************************
        /// <summary>
        /// Reads the specific VS_VERSION_INFO resource and produces strings from it.
        /// </summary>
        /// <remarks>
        /// A VS_VERSION_INFO resource is composed of
        /// - A FixedFileInfo struct.
        /// - A string table called StringFileInfo, where the 'standard' strings are found, like 'BuildNumber', 'FileVersion', ...
        /// - A kind-of string table called VarFileInfo, for the translations blah
        /// </remarks>
        //************************************************************************
        private void ReadVersionFileInfo(byte* pStart, List<string> infos)
        {
            ByteStream bs = new ByteStream(pStart);
            ushort wholeLen = Read6Bytes(bs);
            string resName = bs.ReadUnicodeString();
            if (resName != "VS_VERSION_INFO") {
                throw new Exception("Unexpected resource name");
            }
            bs.Align(4);

            // Read FixedFileInfo
            VS_FIXEDFILEINFO* pffInfo = (VS_FIXEDFILEINFO*)bs.Advance((uint)sizeof(VS_FIXEDFILEINFO));

            // Then loop on string tables
            while ((bs.CurP - pStart) < wholeLen) {
                byte* pStartTable = bs.CurP;
                ushort tableLen = Read6Bytes(bs);
                string tableName = bs.ReadUnicodeString();
                switch (tableName) {
                    case "StringFileInfo":
                        string langId = ReadPrefixedString(bs);
                        infos.Add(string.Format("{0} for LangId: {1}", tableName, langId));
                        while ((bs.CurP - pStartTable) < tableLen) {
                            string s1 = ReadPrefixedString(bs);
                            infos.Add(string.Format("{0} -> {1}", s1, bs.ReadUnicodeString()));
                            bs.Align(4);
                        }
                        break;
                    case "VarFileInfo":
                        infos.Add(tableName);
                        bs.Advance((uint)(tableLen - 30)); // Assume we've skipped the name and prefix
                        break;
                    default:
                        throw new Exception("Unknown VersionFileInfo table");
                }
            }
        }

        //************************************************************************
        /// <summary>
        /// Because all strings are prefixed by this...
        /// </summary>
        //************************************************************************
        private ushort Read6Bytes(ByteStream bs)
        {
            return *(ushort*)bs.Advance(6);
        }

        //************************************************************************
        /// <summary>
        /// Read string prefixed by its 6 bytes.
        /// </summary>
        //************************************************************************
        private string ReadPrefixedString(ByteStream bs)
        {
            bs.Advance(6);
            string s = bs.ReadUnicodeString();
            bs.Align(4);
            return s;
        }

        //************************************************************************
        /// <summary>
        /// Reads a resource string if it's not a resource type.
        /// </summary>
        //************************************************************************
        private string ReadResourceString(ULONG name)
        {
            if (name <= (ULONG)ResourceType._nb) {
                return Enum.GetName(typeof(ResourceType), name);
            }
            throw new Exception("Bad resource name");
        }

        //************************************************************************
        /// <summary>
        /// Find the physical address corresponding to the given virtual address.
        /// </summary>
        /// <param name="virtualAddress"></param>
        /// <returns></returns>
        /// <remarks>
        /// I don't find it very optimal, but that's how it seems to be done if we want to remain generic. It's quite efficient too...
        /// </remarks>
        //************************************************************************
        public byte* GetPhysicalFromVirtual(uint virtualAddress)
        {
            return m_Mmf.GetPtr(Rva2Offset(virtualAddress));
        }

        //************************************************************************
        /// <summary>
        /// Computes the real offset in the file from a virtual address.
        /// </summary>
        /// <param name="rva"></param>
        /// <returns>The real offset</returns>
        //************************************************************************
        public uint Rva2Offset(uint rva)
        {
            IMAGE_SECTION_HEADER* pSec = pSection;
            for (int i = 0; i < pPe->NumberOfSections; ++i, ++pSec) {
                if ((pSec->VirtualAddress <= rva) && (pSec->VirtualAddress + pSec->SizeOfRawData > rva))
                    return (pSec->PointerToRawData + (rva - pSec->VirtualAddress));
            }

            throw new Exception("Module: Invalid RVA address.");
        }

        //************************************************************************
        /// <summary>
        /// Close the file.
        /// </summary>
        //************************************************************************
        public void Close()
        {
            if (m_Mmf != null) {
                m_Mmf.Close();
                m_Mmf = null;
            }
        }

        //************************************************************************
        /// <summary>
        /// Returns all the dependencies of a DLL/EXE, recursively.
        /// </summary>
        //************************************************************************
        public static DllDependency[] ReadAllDependencies(string[] lookupPaths, string[] fileNames, bool recurseDelayed)
        {
            // Prepare the dictionary that'll hold all the names to find out if a dll has already been processed.
            // And the list of dlls to start with.
            Dictionary<string, DllDependency> dict = new Dictionary<string, DllDependency>();
            List<DllDependency> toProcess = new List<DllDependency>();
            foreach (var file in fileNames) {
                string filePath = Util2.FindExistingFile(lookupPaths, file);
                DllDependency dep = new DllDependency(filePath, 1, 0);
                dict[filePath] = dep;
                toProcess.Add(dep);
            }

            // Loop until there are no more new dlls to process.
            while (toProcess.Count != 0) {
                DllDependency[] tmpToProcess = new DllDependency[toProcess.Count];
                toProcess.CopyTo(tmpToProcess);
                toProcess.Clear();
                foreach (DllDependency depProc in tmpToProcess) {
                    try {
                        // Extract the dependencies from that DLL and add the new ones
                        using (DllReader dllReader = new DllReader(depProc.Name)) {
                            foreach (var dep in dllReader.DllDependencies) {
                                // Adjust the name to contain the whole path before trying to find it.
                                string fullPath = Util2.FindExistingFile(lookupPaths, dep.Name);
                                if (fullPath == null) {
                                    DllDependency depFound;
                                    // We only handle its flag the first time it's inserted in the dict.
                                    if (!dict.TryGetValue(dep.Name, out depFound)) {
                                        dict[dep.Name] = dep;
                                        dep.DllFlags |= DllFlags.HasError;
                                    }
                                } else {
                                    dep.Name = fullPath;
                                    DllDependency depFound;
                                    if (dict.TryGetValue(dep.Name, out depFound)) {
                                        // If the parent is delayed, we are delayed.
                                        // The goal is that if a DLL is delayed in one but not in the other, we don't want it to be delayed...
                                        if (depProc.IsDelayed) {
                                            ++depFound.NbRefDelayed;
                                        } else {
                                            ++depFound.NbRef;
                                        }
                                    } else {
                                        dict[dep.Name] = dep;
                                        if (!dep.IsDelayed || recurseDelayed) {
                                            toProcess.Add(dep);
                                        }
                                    }
                                }
                            }
                        }
                    } catch {
                        //Console.WriteLine("Error opening '{0}': {1}", depProc.Name, e.Message);
                        dict[depProc.Name].DllFlags |= DllFlags.HasError;
                    }
                }
            }

            // Compute the IsDelayed, IsMsvcrt, etc flags.
            foreach (var dep in dict.Values) {
                //Console.WriteLine("{0} -> {1}, {2}", dep.Name, dep.NbRef, dep.NbRefDelayed);
                dep.ComputeFlags();
            }
            DllDependency[] deps = new DllDependency[dict.Values.Count];
            dict.Values.CopyTo(deps, 0);
            return deps;
        }

        //************************************************************************
        //************************************************************************
        public SortedDictionary<string, SortedDictionary<string, List<string>>> GetTypeRefs()
        {
            // Map of assembly, map of namespace, symbols
            var typeRefs = new SortedDictionary<string, SortedDictionary<string, List<string>>>();
            uint rvaMetaData = ((IMAGE_DATA_DIRECTORY*)pCorHeader->MetaData)->VirtualAddress;
            if (rvaMetaData != 0) {
                MetaDataHeaders metaDataHeaders = new MetaDataHeaders(GetPhysicalFromVirtual(rvaMetaData));
                metaDataHeaders.ComputeTableOffsets();
                var assemblyRefs = metaDataHeaders.Tables.Tables[(int)Types.AssemblyRef].Rows;
                foreach (Row row in metaDataHeaders.Tables.Tables[(int)Types.TypeRef].Rows) {
                    var assemblyRefName = row[0].ToString();
                    var assTokens = assemblyRefName.Split(' ');
                    if (assTokens[0] != "AssemblyRef") {
                        continue;
                    }
                    var assemblyName = assemblyRefs[int.Parse(assTokens[1], System.Globalization.NumberStyles.AllowHexSpecifier) - 1][6] as string;
                    var symbolName = row[1] as string;
                    var namespaceName = row[2] as string;
                    SortedDictionary<string, List<string>> namespaces;
                    if (!typeRefs.TryGetValue(assemblyName, out namespaces)) {
                        namespaces = new SortedDictionary<string, List<string>>();
                        typeRefs[assemblyName] = namespaces;
                    }
                    List<string> symbols;
                    if (!namespaces.TryGetValue(namespaceName, out symbols)) {
                        symbols = new List<string>();
                        namespaces[namespaceName] = symbols;
                    }
                    symbols.Add(symbolName);
                }
            }
            return typeRefs;
        }

        //************************************************************************
        //************************************************************************
        public SortedDictionary<string, SortedDictionary<string, SortedDictionary<string, List<string>>>> GetMemberRefs()
        {
            // Map of assembly, map of namespace, symbols
            var memberRefs = new SortedDictionary<string, SortedDictionary<string, SortedDictionary<string, List<string>>>>();
            uint rvaMetaData = ((IMAGE_DATA_DIRECTORY*)pCorHeader->MetaData)->VirtualAddress;
            if (rvaMetaData != 0) {
                MetaDataHeaders metaDataHeaders = new MetaDataHeaders(GetPhysicalFromVirtual(rvaMetaData));
                metaDataHeaders.ComputeTableOffsets();
                var assemblyRefs = metaDataHeaders.Tables.Tables[(int)Types.AssemblyRef].Rows;
                var typeRefs = metaDataHeaders.Tables.Tables[(int)Types.TypeRef].Rows;
                foreach (Row memberRefRow in metaDataHeaders.Tables.Tables[(int)Types.MemberRef].Rows) {
                    var typeRefName = memberRefRow[0].ToString();
                    var typeRefTokens = typeRefName.Split(' ');
                    if (typeRefTokens[0] != "TypeRef") {
                        continue;
                    }
                    var typeRefRow = typeRefs[int.Parse(typeRefTokens[1], System.Globalization.NumberStyles.AllowHexSpecifier) - 1];
                    var assemblyRefName = typeRefRow[0].ToString();
                    var assTokens = assemblyRefName.Split(' ');
                    if (assTokens[0] != "AssemblyRef") {
                        continue;
                    }
                    var assemblyName = assemblyRefs[int.Parse(assTokens[1], System.Globalization.NumberStyles.AllowHexSpecifier) - 1][6] as string;
                    var typeName = typeRefRow[1] as string;
                    var namespaceName = typeRefRow[2] as string;
                    SortedDictionary<string, SortedDictionary<string, List<string>>> namespaces;
                    if (!memberRefs.TryGetValue(assemblyName, out namespaces)) {
                        namespaces = new SortedDictionary<string, SortedDictionary<string, List<string>>>();
                        memberRefs[assemblyName] = namespaces;
                    }
                    SortedDictionary<string, List<string>> types;
                    if (!namespaces.TryGetValue(namespaceName, out types)) {
                        types = new SortedDictionary<string, List<string>>();
                        namespaces[namespaceName] = types;
                    }
                    List<string> members;
                    if (!types.TryGetValue(typeName, out members)) {
                        members = new List<string>();
                        types[typeName] = members;
                    }
                    members.Add(string.Format("{0} -- {1}", memberRefRow[1] as string, memberRefRow[2]));
                }
            }
            return memberRefs;
        }

        #region IDisposable implementation

        //************************************************************************
        /// <summary>
        /// Dispose.
        /// </summary>
        //************************************************************************
        public void Dispose()
        {
            Close();
        }

        #endregion
    }

    //************************************************************************
    /// <summary>
    /// DOS .EXE header
    /// </summary>
    //************************************************************************
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct IMAGE_DOS_HEADER
    {
        public WORD   e_magic;                     // Magic number
        public WORD   e_cblp;                      // Bytes on last page of file
        public WORD   e_cp;                        // Pages in file
        public WORD   e_crlc;                      // Relocations
        public WORD   e_cparhdr;                   // Size of header in paragraphs
        public WORD   e_minalloc;                  // Minimum extra paragraphs needed
        public WORD   e_maxalloc;                  // Maximum extra paragraphs needed
        public WORD   e_ss;                        // Initial (relative) SS value
        public WORD   e_sp;                        // Initial SP value
        public WORD   e_csum;                      // Checksum
        public WORD   e_ip;                        // Initial IP value
        public WORD   e_cs;                        // Initial (relative) CS value
        public WORD   e_lfarlc;                    // File address of relocation table
        public WORD   e_ovno;                      // Overlay number
        public fixed WORD e_res[4];                // Reserved words
        public WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
        public WORD   e_oeminfo;                   // OEM information; e_oemid specific
        public fixed WORD e_res2[10];              // Reserved words
        public LONG   e_lfanew;                    // File address of new exe header

        public const WORD    IMAGE_DOS_SIGNATURE          = 0x5A4D;   // MZ
    }

    //************************************************************************
    /// <summary>
    /// Standard PE header, sometimes known as COFF.
    /// </summary>
    //************************************************************************
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_FILE_HEADER
    {
        public DWORD  Magic;
        public WORD   Machine;
        public WORD   NumberOfSections;
        public DWORD  TimeDateStamp;
        public DWORD  PointerToSymbolTable;
        public DWORD  NumberOfSymbols;
        public WORD   SizeOfOptionalHeader;
        public WORD   Characteristics;

        public const DWORD   IMAGE_NT_SIGNATURE           = 0x00004550;    // PE00
        // Characteristics
        public const WORD    IMAGE_FILE_32BIT_MACHINE     = 0x0100;        // 32 bit word machine.
        public const WORD    IMAGE_FILE_DLL               = 0x2000;        // File is a DLL.
        // Machine
        public const WORD    IMAGE_FILE_MACHINE_I386      = 0x014c;        // Intel 386.
        public const WORD    IMAGE_FILE_MACHINE_AMD64     = 0x8664;        // AMD64 (K8)
    }

    //************************************************************************
    /// <summary>
    /// Directory format.
    /// </summary>
    //************************************************************************
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DATA_DIRECTORY
    {
        public const int SizeOf = 8;

        public DWORD   VirtualAddress;
        public DWORD   Size;

        // Directory Entries
        public const int EXPORT         =  0;   // Export Directory
        public const int IMPORT         =  1;   // Import Directory
        public const int RESOURCE       =  2;   // Resource Directory
        public const int EXCEPTION      =  3;   // Exception Directory
        public const int SECURITY       =  4;   // Security Directory
        public const int BASERELOC      =  5;   // Base Relocation Table
        public const int DEBUG          =  6;   // Debug Directory
        public const int ARCHITECTURE   =  7;   // Architecture Specific Data
        public const int GLOBALPTR      =  8;   // RVA of GP
        public const int TLS            =  9;   // TLS Directory
        public const int LOAD_CONFIG    = 10;   // Load Configuration Directory
        public const int BOUND_IMPORT   = 11;   // Bound Import Directory in headers
        public const int IAT            = 12;   // Import Address Table
        public const int DELAY_IMPORT   = 13;   // Delay Load Import Descriptors
        public const int COM_DESCRIPTOR = 14;   // COM Runtime descriptor
    }

    //************************************************************************
    /// <summary>
    /// Optional header format (32 bits)
    /// </summary>
    //************************************************************************
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct IMAGE_OPTIONAL_HEADER32
    {
        //
        // Standard fields.
        //
        public WORD    Magic;
        public BYTE    MajorLinkerVersion;
        public BYTE    MinorLinkerVersion;
        public DWORD   SizeOfCode;
        public DWORD   SizeOfInitializedData;
        public DWORD   SizeOfUninitializedData;
        public DWORD   AddressOfEntryPoint;
        public DWORD   BaseOfCode;
        public DWORD   BaseOfData;

        //
        // NT additional fields.
        //
        public DWORD   ImageBase;
        public DWORD   SectionAlignment;
        public DWORD   FileAlignment;
        public WORD    MajorOperatingSystemVersion;
        public WORD    MinorOperatingSystemVersion;
        public WORD    MajorImageVersion;
        public WORD    MinorImageVersion;
        public WORD    MajorSubsystemVersion;
        public WORD    MinorSubsystemVersion;
        public DWORD   Win32VersionValue;
        public DWORD   SizeOfImage;
        public DWORD   SizeOfHeaders;
        public DWORD   CheckSum;
        public WORD    Subsystem;
        public WORD    DllCharacteristics;
        public DWORD   SizeOfStackReserve;
        public DWORD   SizeOfStackCommit;
        public DWORD   SizeOfHeapReserve;
        public DWORD   SizeOfHeapCommit;
        public DWORD   LoaderFlags;
        public DWORD   NumberOfRvaAndSizes;
        public fixed byte DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES * IMAGE_DATA_DIRECTORY.SizeOf];

        public const int IMAGE_NUMBEROF_DIRECTORY_ENTRIES   = 16;
        public const WORD IMAGE_NT_OPTIONAL_HDR32_MAGIC     = 0x10B;
        public const WORD IMAGE_NT_OPTIONAL_HDR64_MAGIC     = 0x20B;
    }

    //************************************************************************
    /// <summary>
    /// Optional header format (64 bits)
    /// </summary>
    //************************************************************************
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct IMAGE_OPTIONAL_HEADER64
    {
        public WORD        Magic;
        public BYTE        MajorLinkerVersion;
        public BYTE        MinorLinkerVersion;
        public DWORD       SizeOfCode;
        public DWORD       SizeOfInitializedData;
        public DWORD       SizeOfUninitializedData;
        public DWORD       AddressOfEntryPoint;
        public DWORD       BaseOfCode;
        public ULONGLONG   ImageBase;
        public DWORD       SectionAlignment;
        public DWORD       FileAlignment;
        public WORD        MajorOperatingSystemVersion;
        public WORD        MinorOperatingSystemVersion;
        public WORD        MajorImageVersion;
        public WORD        MinorImageVersion;
        public WORD        MajorSubsystemVersion;
        public WORD        MinorSubsystemVersion;
        public DWORD       Win32VersionValue;
        public DWORD       SizeOfImage;
        public DWORD       SizeOfHeaders;
        public DWORD       CheckSum;
        public WORD        Subsystem;
        public WORD        DllCharacteristics;
        public ULONGLONG   SizeOfStackReserve;
        public ULONGLONG   SizeOfStackCommit;
        public ULONGLONG   SizeOfHeapReserve;
        public ULONGLONG   SizeOfHeapCommit;
        public DWORD       LoaderFlags;
        public DWORD       NumberOfRvaAndSizes;
        public fixed byte  DataDirectory[IMAGE_OPTIONAL_HEADER32.IMAGE_NUMBEROF_DIRECTORY_ENTRIES * IMAGE_DATA_DIRECTORY.SizeOf];
    }

    //************************************************************************
    /// <summary>
    /// Section header
    /// </summary>
    //************************************************************************
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct IMAGE_SECTION_HEADER
    {
        public fixed BYTE  Name[8];
        public DWORD       Misc;                // union { DWORD   PhysicalAddress; DWORD   VirtualSize; }
        public DWORD       VirtualAddress;
        public DWORD       SizeOfRawData;
        public DWORD       PointerToRawData;
        public DWORD       PointerToRelocations;
        public DWORD       PointerToLinenumbers;
        public WORD        NumberOfRelocations;
        public WORD        NumberOfLinenumbers;
        public DWORD       Characteristics;     // Lots. Look into winnt.h
    }

    //************************************************************************
    /// <summary>
    /// Different CLR constants. Not sure I need them all.
    /// </summary>
    //************************************************************************
    public enum ReplacesCorHdrNumericDefines
    {
        // COM+ Header entry point flags.
        COMIMAGE_FLAGS_ILONLY               = 0x00000001,
        COMIMAGE_FLAGS_32BITREQUIRED        = 0x00000002,
        COMIMAGE_FLAGS_IL_LIBRARY           = 0x00000004,   // Obsolete. Setting this will render the module unloodable.
        COMIMAGE_FLAGS_STRONGNAMESIGNED     = 0x00000008,
        COMIMAGE_FLAGS_TRACKDEBUGDATA       = 0x00010000,

        // Version flags for image.
        COR_VERSION_MAJOR_V2                = 2,
        COR_VERSION_MAJOR                   = COR_VERSION_MAJOR_V2,
        COR_VERSION_MINOR                   = 0,
        COR_DELETED_NAME_LENGTH             = 8,
        COR_VTABLEGAP_NAME_LENGTH           = 8,

        // Maximum size of a NativeType descriptor.
        NATIVE_TYPE_MAX_CB                  = 1,
        COR_ILMETHOD_SECT_SMALL_MAX_DATASIZE= 0xFF,

        // #defines for the MIH FLAGS
        IMAGE_COR_MIH_METHODRVA             = 0x01,
        IMAGE_COR_MIH_EHRVA                 = 0x02,
        IMAGE_COR_MIH_BASICBLOCK            = 0x08,

        // V-table constants
        COR_VTABLE_32BIT                    = 0x01,          // V-table slots are 32-bits in size.
        COR_VTABLE_64BIT                    = 0x02,          // V-table slots are 64-bits in size.
        COR_VTABLE_FROM_UNMANAGED           = 0x04,          // If set, transition from unmanaged.
        COR_VTABLE_FROM_UNMANAGED_RETAIN_APPDOMAIN  = 0x08,  // If set, transition from unmanaged with keeping the current appdomain.
        COR_VTABLE_CALL_MOST_DERIVED        = 0x10,          // Call most derived method described by

        // EATJ constants
        IMAGE_COR_EATJ_THUNK_SIZE           = 32,            // Size of a jump thunk reserved range.

        // Max name lengths
        //@todo: Change to unlimited name lengths.
        MAX_CLASS_NAME                      = 1024,
        MAX_PACKAGE_NAME                    = 1024,
    }

    //************************************************************************
    /// <summary>
    /// CLR 2.0 header structure.
    /// </summary>
    //************************************************************************
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct IMAGE_COR20_HEADER
    {
        // Header versioning
        public DWORD                   cb;
        public WORD                    MajorRuntimeVersion;
        public WORD                    MinorRuntimeVersion;

        // Symbol table and startup information
        public fixed byte              MetaData[IMAGE_DATA_DIRECTORY.SizeOf];
        public DWORD                   Flag;
        public DWORD                   EntryPointToken;

        // Binding information
        public fixed byte              Resources[IMAGE_DATA_DIRECTORY.SizeOf];
        public fixed byte              StrongNameSignature[IMAGE_DATA_DIRECTORY.SizeOf];

        // Regular fixup and binding information
        public fixed byte              CodeManagerTable[IMAGE_DATA_DIRECTORY.SizeOf];
        public fixed byte              VTableFixups[IMAGE_DATA_DIRECTORY.SizeOf];
        public fixed byte              ExportAddressTableJumps[IMAGE_DATA_DIRECTORY.SizeOf];

        // Precompiled image info (internal use only - set to zero)
        public fixed byte              ManagedNativeHeader[IMAGE_DATA_DIRECTORY.SizeOf];
    }

    //************************************************************************
    /// <summary>
    /// Imported file descriptor.
    /// </summary>
    //************************************************************************
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_IMPORT_DESCRIPTOR
    {
        public DWORD   Characteristics;         // union { DWORD   Characteristics;         // 0 for terminating null import descriptor
                                                //         DWORD   OriginalFirstThunk; }    // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
        public DWORD   TimeDateStamp;           // 0 if not bound,
                                                // -1 if bound, and real date\time stamp
                                                //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                                // O.W. date/time stamp of DLL bound to (Old BIND)
        public DWORD   ForwarderChain;          // -1 if no forwarders
        public DWORD   Name;
        public DWORD   FirstThunk;              // RVA to IAT (if bound this IAT has actual addresses)
    }

    //************************************************************************
    /// <summary>
    /// Delay-imported file descriptor
    /// </summary>
    //************************************************************************
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DELAY_IMPORT_DESCRIPTOR
    {
        public DWORD Attrs;
        public DWORD Name;
        public DWORD hmod;
        public DWORD IAT;
        public DWORD INT;
        public DWORD BoundIAT;
        public DWORD UnloadIAT;
        public DWORD TimeStamp;
    }

    //************************************************************************
    /// <summary>
    /// Resource descriptor
    /// </summary>
    //************************************************************************
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_RESOURCE_DIRECTORY
    {
        public ULONG   Characteristics;
        public ULONG   TimeDateStamp;
        public USHORT  MajorVersion;
        public USHORT  MinorVersion;
        public USHORT  NumberOfNamedEntries;
        public USHORT  NumberOfIdEntries;
    }

    //************************************************************************
    /// <summary>
    /// Resource directory entry
    /// </summary>
    //************************************************************************
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_RESOURCE_DIRECTORY_ENTRY
    {
        public ULONG   Name;
        public ULONG   OffsetToData;
    }

    //************************************************************************
    /// <summary>
    /// Resource data entry
    /// </summary>
    //************************************************************************
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_RESOURCE_DATA_ENTRY
    {
        public ULONG OffsetToData;
        public ULONG Size;
        public ULONG CodePage;
        public ULONG Reserved;
    }

    public unsafe class ResourceDirEnum
    {
        public byte* pBegin;
        public uint RdOffset;
        public int Level;
        public int Nb;
        public IMAGE_RESOURCE_DIRECTORY* pResDir;
        public IMAGE_RESOURCE_DIRECTORY_ENTRY* pFirst;

        private int i;
        private IMAGE_RESOURCE_DIRECTORY_ENTRY* pEntry;

        public ResourceDirEnum(byte* pBegin, uint rdOffset, int level)
        {
            this.pBegin = pBegin;
            RdOffset = rdOffset;
            pResDir = (IMAGE_RESOURCE_DIRECTORY*)(pBegin + rdOffset);
            Level = level;
            Nb = pResDir->NumberOfIdEntries;
            pFirst = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(pResDir + 1);
            pEntry = pFirst;
            i = 0;
        }
        public ResourceDirEnum(ResourceDirEnum rdParent, ULONG offset) :
            this(rdParent.pBegin, offset & 0x7FFFFFFF, rdParent.Level + 1)
        {
            if ((offset & 0x80000000) == 0) {
                throw new Exception("Trying to directory recurse in a leaf resource");
            }
        }
        public IMAGE_RESOURCE_DIRECTORY_ENTRY* Next()
        {
            if (i++ < Nb) {
                return pEntry++;
            }
            return null;
        }
        public IMAGE_RESOURCE_DATA_ENTRY* GetDataEntry(IMAGE_RESOURCE_DIRECTORY_ENTRY* pDirEntry)
        {
            if ((pDirEntry->OffsetToData & 0x80000000) != 0) {
                throw new Exception("This is not a data entry");
            }
            return (IMAGE_RESOURCE_DATA_ENTRY*)(pBegin + pDirEntry->OffsetToData);
        }
    }

    //************************************************************************
    /// <summary>
    /// The predefined resource types
    /// </summary>
    //************************************************************************
    public enum ResourceType
    {
        Unknown_0,
        Cursor,
        Bitmap,
        Icon,
        Menu,
        Dialog,
        String,
        FontDir,
        Font,
        Accelerator,
        RcData,
        MessageTable,
        GroupCursor,
        Unknown_13,
        GroupIcon,
        Unknown_15,
        Version,
        DialogInclude,
        Unknown_18,
        PlugNPlay,
        VxD,
        AnimatedCursor,
        AnimatedIcon,
        HTML,
        Manifest,
        _nb
    }

    /*
        Examples of string types:
            '0000' => 'Neutral',
            '007F' => 'Invariant',
            '0400' => 'Process default',
            '0401' => 'Arabic',
            '0402' => 'Bulgarian',
            '0403' => 'Catalan',
            '0404' => 'Chinese (Traditional)',
            '0405' => 'Czech',
            '0406' => 'Danish',
            '0407' => 'German',
            '0408' => 'Greek',
            '0409' => 'English (U.S.)',
            ...
    */

    //************************************************************************
    /// <summary>
    /// FixedFileInfo struct in the VS_VERSION_INFO resource
    /// </summary>
    //************************************************************************
    [StructLayout(LayoutKind.Sequential)]
    public struct VS_FIXEDFILEINFO
    {
        public DWORD   dwSignature;            /* e.g. 0xfeef04bd */
        public DWORD   dwStrucVersion;         /* e.g. 0x00000042 = "0.42" */
        public DWORD   dwFileVersionMS;        /* e.g. 0x00030075 = "3.75" */
        public DWORD   dwFileVersionLS;        /* e.g. 0x00000031 = "0.31" */
        public DWORD   dwProductVersionMS;     /* e.g. 0x00030010 = "3.10" */
        public DWORD   dwProductVersionLS;     /* e.g. 0x00000031 = "0.31" */
        public DWORD   dwFileFlagsMask;        /* = 0x3F for version "0.42" */
        public DWORD   dwFileFlags;            /* e.g. VFF_DEBUG | VFF_PRERELEASE */
        public DWORD   dwFileOS;               /* e.g. VOS_DOS_WINDOWS16 */
        public DWORD   dwFileType;             /* e.g. VFT_DRIVER */
        public DWORD   dwFileSubtype;          /* e.g. VFT2_DRV_KEYBOARD */
        public DWORD   dwFileDateMS;           /* e.g. 0 */
        public DWORD   dwFileDateLS;           /* e.g. 0 */
    }

    //************************************************************************
    /// <summary>
    /// Export directory struct.
    /// </summary>
    //************************************************************************
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_EXPORT_DIRECTORY
    {
        public DWORD   Characteristics;
        public DWORD   TimeDateStamp;
        public WORD    MajorVersion;
        public WORD    MinorVersion;
        public DWORD   Name;
        public DWORD   Base;
        public DWORD   NumberOfFunctions;
        public DWORD   NumberOfNames;
        public DWORD   AddressOfFunctions;     // RVA from base of image
        public DWORD   AddressOfNames;         // RVA from base of image
        public DWORD   AddressOfNameOrdinals;  // RVA from base of image
    }

    //************************************************************************
    /// <summary>
    /// Dll dependency as contained in m_DllDependencies
    /// </summary>
    //************************************************************************
    public class DllDependency
    {
        public string Name;
        public DllFlags DllFlags;
        public int NbRef;
        public int NbRefDelayed;
        public bool IsDelayed { get { return NbRefDelayed != 0; } }
        public bool IsWindows { get { return (DllFlags & DllFlags.IsWindows) != 0; } }
        public bool IsMsvcrt { get { return (DllFlags & DllFlags.IsMsvcrt) != 0; } }

        public DllDependency(string name, int nbRef, int nbRefDelayed)
        {
            Name = name;
            NbRef = nbRef;
            NbRefDelayed = nbRefDelayed;
        }

        public DllFlags ComputeFlags()
        {
            if (SpecialDlls.IsWindowsDll(Name)) {
                DllFlags |= DllFlags.IsWindows;
            }
            if (SpecialDlls.IsMsvcrtDll(Name)) {
                DllFlags |= DllFlags.IsMsvcrt;
            }
            // If at least one DLL references this one NOT as a delayed one, then it's non-delayed.
            if (NbRefDelayed != 0 && NbRef == 0) {
                DllFlags |= DllFlags.IsDelayed;
            }
            return DllFlags;
        }

        public override string ToString()
        {
            return (DllFlags == 0 ? Name : string.Format("{0} ({1})", Name, DllFlags));
        }
    }

    //************************************************************************
    /// <summary>
    /// Utility reader that takes an unmanaged ptr and advances in it.
    /// </summary>
    //************************************************************************
    public unsafe class ByteStream
    {
        byte* p;
        public byte* CurP { get { return p; } }

        public ByteStream(byte* p)
        {
            this.p = p;
        }
        public Byte ReadByte() { Byte v = *(Byte*)p; p += sizeof(Byte); return v; }
        public UInt16 ReadUInt16() { UInt16 v = *(UInt16*)p; p += sizeof(UInt16); return v; }
        public UInt32 ReadUInt32() { UInt32 v = *(UInt32*)p; p += sizeof(UInt32); return v; }
        public UInt64 ReadUInt64() { UInt64 v = *(UInt64*)p; p += sizeof(UInt64); return v; }
        public byte* Advance(uint nb) {byte* pCur = p; p += nb; return pCur; }
        public void Align(uint n)
        {
            --n;
            // Using a switch case, because we can't do a '~' on a ptr (or IntPtr).
            switch (IntPtr.Size) {
            case sizeof(uint) : p = (byte*)((uint )(p + n) & ~n); break;
            case sizeof(ulong): p = (byte*)((ulong)(p + n) & ~(ulong)n); break;
            default: throw new Exception("Unknown ptr size.");
            }
        }
        public string ReadStringWithLen()
        {
            uint len = ReadUInt32();
            string s = new string((sbyte*)Advance(len));
            return s;
        }

        public string ReadUnicodeString()
        {
            string s = new string((char*)p);
            p += (s.Length + 1) * 2; // A unicode char is 2 bytes
            return s;
        }

        public string ReadString(bool p_Aligned = false)
        {
            string s = new string((sbyte*)p);
            if (p_Aligned) {
                // The length has to be a multiple of 4. Weird.
                int len = s.Length + 1;
                len = (len + 3) & ~3;
                p += len;
            } else {
                p += s.Length + 1;
            }
            return s;
        }

        public int DecodeInt32()
        {
            int length = ReadByte();
            if ((length & 0x80) == 0) return length;
            if ((length & 0xC0) == 0x80) return ((length & 0x3F) << 8) | ReadByte();
            return ((length & 0x3F) << 24) | (ReadByte() << 16) | (ReadByte() << 8) | ReadByte();
        }

        public byte[] ReadBytes(int len)
        {
            byte[] data = new byte[len];
            Marshal.Copy((IntPtr)Advance((uint)len), data, 0, len);
            return data;
        }
    }

    //************************************************************************
    /// <summary>
    /// The entry point of all things .Net
    /// </summary>
    //************************************************************************
    public unsafe class MetaDataHeaders
    {
        private byte* m_pMetaData;
        public StorageSigAndHeader StorageSigAndHeader;
        public MDStreamHeader StringStream;
        public MDStreamHeader BlobStream;
        public MDStreamHeader GuidStream;
        public MDStreamHeader UsStream;
        public MDStreamHeader TableStream;
        public MetaDataTableHeader MetaDataTableHeader;
        public MDTables Tables;

        public unsafe MetaDataHeaders(byte* pMetaData)
        {
            m_pMetaData = pMetaData;
            ByteStream bs = new ByteStream(pMetaData);
            StorageSigAndHeader = new StorageSigAndHeader(bs);

            // Read all the stream headers, even if we don't need them all
            for (int i = 0; i < StorageSigAndHeader.NumOfStreams; ++i) {
                MDStreamHeader mds = new MDStreamHeader(bs);
                switch (mds.Name) {
                    case "#~" : TableStream = mds; break;
                    case "#Strings" : StringStream = mds; break;
                    case "#US" : UsStream = mds; break;
                    case "#GUID" : GuidStream = mds; break;
                    case "#Blob" : BlobStream = mds; break;
                    default: throw new Exception("Unknown blob: " + mds.Name);
                }
            }
        }

        public void ComputeTableOffsets()
        {
            ByteStream bs = new ByteStream(m_pMetaData + TableStream.Offset);
            MetaDataTableHeader = new MetaDataTableHeader(bs);
            Tables = new MDTables(this, bs);
        }

        public string ReadString(int off)
        {
            if (off < 0 || off > StringStream.Size) throw new Exception("MDTables: string offs out of range.");
            return new string((sbyte*)m_pMetaData + StringStream.Offset + off);
        }

        public MDBlob ReadBlob(int off)
        {
            if (off < 0 || off > BlobStream.Size) throw new Exception("MDTables: blob offs out of range.");
            return new MDBlob(new ByteStream(m_pMetaData + BlobStream.Offset + off));
        }

        public MDGUID ReadGuid(int off)
        {
            if (off == 0) return MDGUID.Empty;
            if (off < 1 || off > GuidStream.Size / 16) throw new Exception("MDTables: GUID offs out of range.");
            return new MDGUID(new ByteStream(m_pMetaData + GuidStream.Offset + off - 1));
        }
    }

    //************************************************************************
    /// <summary>
    /// Represents the header that tells us where to find metadata streams
    /// </summary>
    //************************************************************************
    public class StorageSigAndHeader
    {
        const uint Magic = 0x424A5342; // BSJB

        public ushort MajorVersion;
        public ushort MinorVersion;
        public string VersionString;
        public ushort NumOfStreams;

        public StorageSigAndHeader(ByteStream bs)
        {
            if (bs.ReadUInt32() != Magic)
                throw new Exception("MetaData:  Incorrect signature.");
            MajorVersion = bs.ReadUInt16();
            MinorVersion = bs.ReadUInt16();
            bs.ReadUInt32(); // extra data (unused)
            VersionString = bs.ReadStringWithLen();
            bs.Align(4);

            // storage header
            bs.ReadByte(); // flags(unused)
            bs.ReadByte(); // padding
            NumOfStreams = bs.ReadUInt16();
        }
    }

    //************************************************************************
    /// <summary>
    /// MetaData Streams
    /// </summary>
    /// <remarks>
    /// The ones which always seem to be there:
    ///     #~          // These are the tables, of which we'll extract the AssemblyRefs (and possibly others down the road)
    ///     #Strings
    ///     #US
    ///     #GUID
    ///     #Blob
    /// </remarks>
    //************************************************************************
    public class MDStreamHeader
    {
        public uint Offset;
        public uint Size;
        public string Name;

        public MDStreamHeader(ByteStream bs)
        {
            Offset = bs.ReadUInt32();
            Size = bs.ReadUInt32();
            Name = bs.ReadString(true);
        }
    }

    //************************************************************************
    /// <summary>
    /// MetaData table header
    /// </summary>
    //************************************************************************
    public struct MetaDataTableHeader
    {
        public uint   Reserved;
        public byte   MajorVersion;
        public byte   MinorVersion;
        public byte   HeapOffsetSizes;
        public byte   RIDPlaceholder;
        public ulong  MaskValid;
        public ulong  MaskSorted;
        public uint[] TableLengths;

        //************************************************************************
        /// <summary>
        /// Ctor taking a ptr in the mapped dll/exe
        /// </summary>
        /// <param name="bs"></param>
        //************************************************************************
        public unsafe MetaDataTableHeader(ByteStream bs)
        {
            TableLengths = new uint[64];

            Reserved = bs.ReadUInt32();
            MajorVersion = bs.ReadByte();
            MinorVersion = bs.ReadByte();
            HeapOffsetSizes = bs.ReadByte();
            RIDPlaceholder = bs.ReadByte();
            MaskValid = bs.ReadUInt64();
            MaskSorted = bs.ReadUInt64();

            // Read as many uints as there are bits set in maskvalid
            for (int i = 0; i < 64; i++) {
                TableLengths[i] = (uint)((((MaskValid >> i) & 1) == 0) ? 0 : bs.ReadUInt32());
            }
        }
    }

    //************************************************************************
    /// <summary>
    /// As returned in m_AssemblyReferences
    /// </summary>
    //************************************************************************
    public class AssemblyReference
    {
        public short MajorVersion;
        public short MinorVersion;
        public short BuildNumber;
        public short RevisionNumber;
        public uint Flags;
        public byte[] PublicKeyOrToken;
        public string Name;
        public string Locale;
        public byte[] HashValue;

        public AssemblyReference(string name)
        {
            Name = name;
        }
    }

    //************************************************************************
    /// <summary>
    /// Utility class to list and/or inquire about Windows DLLs used in our C++ apps.
    /// </summary>
    //************************************************************************
    public static class SpecialDlls
    {
        public static readonly string[] WindowsDlls =
        {
            "activeds.dll",
            "advapi32.dll",
            "comdlg32.dll",
            "crypt32.dll",
            "dbghelp.dll",
            "gdi32.dll",
            "gdiplus.dll",
            "kernel32.dll",
            "mpr.dll",
            "msi.dll",
            //"mscoree.dll",
            "mswsock.dll",
            "netapi32.dll",
            "odbc32.dll",
            "odbccp32.dll",
            "ole32.dll",
            "oleaut32.dll",
            "psapi.dll",
            "query.dll",
            "rpcrt4.dll",
            "secur32.dll",
            "shell32.dll",
            "snmpapi.dll",
            "user32.dll",
            "uuid.dll",
            "version.dll",
            "wininet.dll",
            "winmm.dll",
            "winspool.dll",
            "ws2_32.dll",
            "wsock32.dll",
        };

        public static readonly string[] MsvcrtDlls =
        {
            "msvcm80.dll",
            "msvcm80d.dll",
            "msvcp80.dll",
            "msvcp80d.dll",
            "msvcr80.dll",
            "msvcr80d.dll",
        };

        public static bool IsWindowsDll(string name)
        {
            return IsIn(name, WindowsDlls);
        }

        public static bool IsMsvcrtDll(string name)
        {
            return IsIn(name, MsvcrtDlls);
        }

        private static bool IsIn(string name, string[] names)
        {
            foreach (string s in names) {
                if (string.Equals(s, name, StringComparison.OrdinalIgnoreCase)) {
                    return true;
                }
            }
            return false;
        }
    }

    public class Util2
    {
        //************************************************************************
        /// <summary>
        /// Returns the full path of the file found in the passed paths. Else the fileName alone.
        /// </summary>
        //************************************************************************
        public static string FindExistingFile(string[] lookupPaths, string fileName)
        {
            foreach (string lookupPath in lookupPaths) {
                string filePath = Path.Combine(lookupPath, fileName);
                if (File.Exists(filePath)) {
                    return filePath;
                }
            }
            return null;
        }
    }
}
