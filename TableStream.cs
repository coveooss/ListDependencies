//****************************************************************************
// Copyright (c) 2005-2015, Coveo Solutions Inc.
//****************************************************************************

/***
 *
 * Inspired by ASMEX by RiskCare Ltd.
 *
 * If you use this code or have comments on it, please mail me at
 * support@jbrowse.com or ben.peterson@riskcare.com
 *
 */

using System;
using System.IO;
using System.Collections;
using System.Text;

namespace Coveo.Cdf.DllUtil
{
    using ModException = Exception;

    /// <summary>
    /// 'Types' in .NET metadata may be simple types, coded token types, or tables.
    /// Thus this enum describes all tables and codedtoken types as well as describing all types.
    /// </summary>
    public enum Types
    {
        //Tables
        Module = 0,
        TypeRef = 1,
        TypeDef = 2,
        FieldPtr = 3,
        Field = 4,
        MethodPtr = 5,
        Method = 6,
        ParamPtr = 7,
        Param = 8,
        InterfaceImpl = 9,
        MemberRef = 10,
        Constant = 11,
        CustomAttribute = 12,
        FieldMarshal = 13,
        Permission = 14,
        ClassLayout = 15,
        FieldLayout = 16,
        StandAloneSig = 17,
        EventMap = 18,
        EventPtr = 19,
        Event = 20,
        PropertyMap = 21,
        PropertyPtr = 22,
        Property = 23,
        MethodSemantics = 24,
        MethodImpl = 25,
        ModuleRef = 26,
        TypeSpec = 27,
        ImplMap = 28, //lidin book is wrong again here?  It has enclog at 28
        FieldRVA = 29,
        ENCLog = 30,
        ENCMap = 31,
        Assembly = 32,
        AssemblyProcessor= 33,
        AssemblyOS = 34,
        AssemblyRef = 35,
        AssemblyRefProcessor = 36,
        AssemblyRefOS = 37,
        File = 38,
        ExportedType = 39,
        ManifestResource = 40,
        NestedClass = 41,
        TypeTyPar = 42,
        MethodTyPar = 43,

        //Coded Token Types
        TypeDefOrRef = 64,
        HasConstant = 65,
        CustomAttributeType = 66,
        HasSemantic = 67,
        ResolutionScope = 68,
        HasFieldMarshal = 69,
        HasDeclSecurity = 70,
        MemberRefParent = 71,
        MethodDefOrRef = 72,
        MemberForwarded = 73,
        Implementation = 74,
        HasCustomAttribute = 75,

        //Simple
        UInt16 = 97,
        UInt32 = 99,
        String = 101,
        Blob = 102,
        Guid = 103,
        UserString = 112
    }

    /// <summary>
    /// The information that specifies one MD Table column
    /// </summary>
    public class ColDesc
    {
        public Types Type;
        public string Name;

        public ColDesc(Types type, string name)
        {
            Type = type;
            Name = name;
        }
    }

    /// <summary>
    /// The definition of a MetaDataTable, i.e. all its columns and their types.
    /// From that, we can find out, for a given assembly, what's the size of the row.
    /// </summary>
    public class TableDef
    {
        public Types Type;
        public ColDesc[] ColDescs;

        public TableDef(Types type, Types[] colTypes, String[] colNames)
        {
            Type = type;
            ColDescs = new ColDesc[colTypes.Length];
            for (int i = 0; i < ColDescs.Length; ++i) {
                ColDescs[i] = new ColDesc(colTypes[i], colNames[i]);
            }
        }
    }

    /// <summary>
    /// An MD table.  Includes the schema (a coldesc array) and some rows that are accessed via the indexer
    /// </summary>
    public unsafe class Table
    {
        TableDef TableDef;
        MDTables _helper;
        uint _nbRows; // == helper.GetTableNbRows
        int _rowSize;
        byte* _pData;
        Row[] _rows;

        public Table(TableDef tableDef, MDTables helper, ByteStream bs)
        {
            _pData = bs.CurP;

            TableDef = tableDef;
            _helper = helper;

            _nbRows = helper.GetTableNbRows(tableDef.Type);

            _rowSize = 0;
            foreach (ColDesc cd in tableDef.ColDescs) {
                _rowSize += _helper.SizeOfType(cd.Type);
            }

            bs.Advance((uint)(_rowSize * _nbRows));
        }

        public Types Type { get { return TableDef.Type; } }

        public ColDesc[] ColDescs { get { return TableDef.ColDescs; } }

        public uint Count { get { return _nbRows; } }

        public MDTables Helper { get { return _helper; } }

        public Row[] Rows
        {
            get
            {
                if (_rows == null) {
                    _rows = new Row[_nbRows];
                    ByteStream bs = new ByteStream(_pData);
                    for (int i = 0; i < _nbRows; ++i) {
                        _rows[i] = new Row(this, bs);
                    }
                }
                return _rows;
            }
        }

        public override String ToString()
        {
            StringBuilder sb = new StringBuilder(100);
            sb.Append (Type.ToString());
            sb.Append (" (");
            sb.Append (_nbRows);
            sb.Append (")    (");

            for(int i=0; i < ColDescs.Length;++i)
            {
                sb.Append(ColDescs[i].Name);
                if(i < ColDescs.Length-1) sb.Append("  --   ");
            }

            sb.Append(")");

            return sb.ToString();
        }
    }

    /// <summary>
    /// An MD Table row
    /// </summary>
    public class Row
    {
        Table _table;
        object[] _cells;

        public Row(Table table, ByteStream bs)
        {
            _table = table;
            ColDesc[] cols = table.ColDescs;
            _cells = new object[cols.Length];
            MDTables helper = table.Helper;
            for (int i = 0; i < cols.Length; ++i) {
                _cells[i] = ReadValue(cols[i].Type, bs, helper);
            }
        }

        public Table Table { get { return _table; } }

        public object this[int index] { get { return _cells[index]; } }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < _cells.Length; ++i) {
                if (i != 0)
                    sb.Append("   --    ");
                sb.Append(_cells[i].ToString());
            }
            return sb.ToString();
        }

        public object ReadValue(Types type, ByteStream bs, MDTables helper)
        {
            // Fixed
            if (type == Types.UInt16) return bs.ReadUInt16();
            if (type == Types.UInt32) return bs.ReadUInt32();

            // Heap
            if (type == Types.String) return helper.ReadString(bs);
            if (type == Types.Guid) return helper.ReadGuid(bs);
            if (type == Types.Blob) return helper.ReadBlob(bs);

            // Rid
            if ((int)type < 64) {
                Table table = helper.GetTable(type);
                uint _rawData =  (uint)(((uint) type << 24) | (table.Count < 65536 ? (uint)bs.ReadUInt16() : bs.ReadUInt32()));
                return new RID(type, _rawData);
            }

            // Coded token (may need to be uncompressed from 2-byte form)
            if ((int) type < 97) {
                uint codedToken = (helper.SizeOfType(type) == 2) ? bs.ReadUInt16() : bs.ReadUInt32();
                Types[] referredTables = (Types[]) helper.CodedTokenTypes(type);

                int tableIndex = (int) (codedToken & ~(-1 << helper.CodedTokenBits(referredTables.Length)));
                int index = (int) (codedToken >> helper.CodedTokenBits(referredTables.Length));

                int token = helper.ToToken(referredTables[tableIndex], index - 1);
                uint _rawData = (uint) token;
                return new CodedToken(type, _rawData, helper);
            }
            throw new Exception("Unknown type to read");
        }
    }


    /// <summary>
    /// An RID. 'type' is not part of the RID's actual content but rather a note saying what
    /// sort of column the RID was found in and thus what table it must refer to
    /// </summary>
    public class RID
    {
        uint _rawData;
        Types _type;

        public RID(Types type, uint raw)
        {
            _rawData = raw;
            _type = type;
        }

        public uint Raw{get{return _rawData;}}

        public override string ToString()
        {
            return _type.ToString() + " " + _rawData.ToString("X8");
        }
    }

    /// <summary>
    /// A coded token.  As with the RID class, 'type' is not actually data held in the coded token but a note
    /// telling us what kind of column the ct was found in and thus what kind of ct it must be
    /// </summary>
    public class CodedToken
    {
        uint _rawData;
        Types _type;

        public CodedToken(Types type, uint raw, MDTables helper)
        {
            _rawData = raw;
            _type = type;
        }

        public uint Raw{get{return _rawData;}}

        public override string ToString()
        {
            Types t = (Types)((_rawData & 0xff000000) >> 24);

            return t.ToString() + " " +( _rawData & 0x00ffffff).ToString("X8");
        }
    }

    /// <summary>
    /// The collection of all md tables in the file
    /// </summary>
    public class MDTables
    {
        static int[] _codedTokenBits;
        static Hashtable _ctok;
        static TableDef[] _tableDefs;

        public int StringIndexSize;
        public int BlobIndexSize;
        public int GuidIndexSize;

        Table[] _td;
        MetaDataHeaders _mod;

        public MDTables(MetaDataHeaders mod, ByteStream bs)
        {
            _mod = mod;

            byte heapOffsetSizes = _mod.MetaDataTableHeader.HeapOffsetSizes;
            StringIndexSize = ((heapOffsetSizes & 0x01) != 0) ? 4 : 2;
            GuidIndexSize = ((heapOffsetSizes & 0x02) != 0) ? 4 : 2;
            BlobIndexSize = ((heapOffsetSizes & 0x04) != 0) ? 4 : 2;

            // .NET expects the consumer of the metadata to know the schema of the metadata database.
            // That schema is represented here as an array of 'table' objs which will be filled with actual rows elsewhere.
            _td = new Table[_tableDefs.Length];
            for (int i = 0; i < _tableDefs.Length; ++i) {
                _td[i] = new Table(_tableDefs[i], this, bs);
            }
        }

        public Table[] Tables { get { return _td; } }

        public Types[] CodedTokenTypes(Types t)
        {
            return (Types[])_ctok[t];
        }

        public int CodedTokenBits(Types t)
        {
            return _codedTokenBits[(int)t];
        }

        public int CodedTokenBits(int i)
        {
            return _codedTokenBits[i];
        }

        public Table GetTable(int token)
        {
            int idx = token >> 24;
            if (idx >= _td.Length) throw new ModException("MDTables:  No such table");
            return _td[idx];
        }

        public Table GetTable(Types type)
        {
            int idx = (int) type;
            if (idx >= _td.Length) throw new ModException("MDTables:  No such table");
            return _td[idx];
        }

        public uint GetTableNbRows(Types t)
        {
            int idx = (int)t;
            if (idx < 0 || idx > _mod.MetaDataTableHeader.TableLengths.Length) throw new ModException("MDHelper:  Tried to get length of nonexistant table");
            return _mod.MetaDataTableHeader.TableLengths[(int)t];
        }

        public int ToToken(Types tableType, int index)
        {
            int type = (int) tableType;
            index++;
            if (index < 0) return -1;
            return ((type << 24) | index);
        }

        public string ReadString(ByteStream bs)
        {
            int off = (int)(StringIndexSize == 2 ? bs.ReadUInt16() : bs.ReadUInt32());
            return _mod.ReadString(off);
        }

        public MDBlob ReadBlob(ByteStream bs)
        {
            int off = (int)(BlobIndexSize == 2 ? bs.ReadUInt16() : bs.ReadUInt32());
            return _mod.ReadBlob(off);
        }

        // Hmm. 'offsets' in the guid heap actually seem to be 1-based indexes?  And an index of 0 means empty?
        // ITS NOT LIKE THIS IS ACTUALLY ***DOCUMENTED*** ANYWHERE AFTER ALL.
        public MDGUID ReadGuid(ByteStream bs)
        {
            int off = (int)(GuidIndexSize == 2 ? bs.ReadUInt16() : bs.ReadUInt32());
            return _mod.ReadGuid(off);
        }

        // Note that the size of a type cannot be known until at least table sizes are loaded from file
        public int SizeOfType(Types type)
        {
            // Fixed
            if (type == Types.UInt16) return sizeof(UInt16);
            if (type == Types.UInt32) return sizeof(UInt32);

            // Heap
            if (type == Types.String) return StringIndexSize;
            if (type == Types.Blob) return BlobIndexSize;
            if (type == Types.Guid) return GuidIndexSize;

            // RID
            if ((int)type < 64)
            {
                uint nbRows = GetTableNbRows(type);
                return (nbRows < 65536) ? 2 : 4;
            }

            // CodedToken
            Types[] referredTypes = (Types[]) CodedTokenTypes(type);
            if (referredTypes != null)
            {
                uint maxRows = 0;
                foreach (Types referredType in referredTypes)
                {
                    if (referredType != Types.UserString)//but what if there is a large user string table?
                    {
                        uint rows = GetTableNbRows(referredType);
                        if (maxRows < rows)
                            maxRows = rows;
                    }
                }

                maxRows = maxRows << CodedTokenBits(referredTypes.Length);
                return (maxRows < 65536) ? 2 : 4;
            }

            throw new ModException("Table:  Sizeof invalid token type.");
        }

        static MDTables()
        {
            // Number of bits in coded token tag for a coded token that refers to n tables.
            // Values 5-17 are not used :I
            _codedTokenBits = new int[] { 0, 1, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5 };

            // Hash telling us what tables a given coded token type can refer to
            _ctok = new Hashtable();
            _ctok[Types.TypeDefOrRef] = new Types[] { Types.TypeDef, Types.TypeRef, Types.TypeSpec };
            _ctok[Types.HasConstant] = new Types[] { Types.Field, Types.Param, Types.Property };
            _ctok[Types.CustomAttributeType] = new Types[] { Types.TypeRef, Types.TypeDef, Types.Method, Types.MemberRef, Types.UserString };
            _ctok[Types.HasSemantic] = new Types[] { Types.Event, Types.Property };
            _ctok[Types.ResolutionScope] = new Types[] { Types.Module, Types.ModuleRef, Types.AssemblyRef, Types.TypeRef };
            _ctok[Types.HasFieldMarshal] = new Types[] { Types.Field, Types.Param };
            _ctok[Types.HasDeclSecurity] = new Types[] { Types.TypeDef, Types.Method, Types.Assembly };
            _ctok[Types.MemberRefParent] = new Types[] { Types.TypeDef, Types.TypeRef, Types.ModuleRef, Types.Method, Types.TypeSpec };
            _ctok[Types.MethodDefOrRef] = new Types[] { Types.Method, Types.MemberRef };
            _ctok[Types.MemberForwarded] = new Types[] { Types.Field, Types.Method };
            _ctok[Types.Implementation] = new Types[] { Types.File, Types.AssemblyRef, Types.ExportedType };
            _ctok[Types.HasCustomAttribute] = new Types[] { Types.Method, Types.Field, Types.TypeRef, Types.TypeDef, Types.Param, Types.InterfaceImpl, Types.MemberRef, Types.Module, Types.Permission, Types.Property, Types.Event, Types.StandAloneSig, Types.ModuleRef, Types.TypeSpec, Types.Assembly, Types.AssemblyRef, Types.File, Types.ExportedType, Types.ManifestResource };

            _tableDefs = new TableDef[0x2C];
            _tableDefs[0x00] = new TableDef(Types.Module, new Types[] { Types.UInt16, Types.String, Types.Guid, Types.Guid, Types.Guid }, new String[] { "Generation", "Name", "Mvid", "EncId", "EncBaseId" });
            _tableDefs[0x01] = new TableDef(Types.TypeRef, new Types[] { Types.ResolutionScope, Types.String, Types.String }, new String[] { "ResolutionScope", "Name", "Namespace" });
            _tableDefs[0x02] = new TableDef(Types.TypeDef, new Types[] { Types.UInt32, Types.String, Types.String, Types.TypeDefOrRef, Types.Field, Types.Method }, new String[] { "Flags", "Name", "Namespace", "Extends", "FieldList", "MethodList" });
            _tableDefs[0x03] = new TableDef(Types.FieldPtr, new Types[] { Types.Field }, new String[] { "Field" });
            _tableDefs[0x04] = new TableDef(Types.Field, new Types[] { Types.UInt16, Types.String, Types.Blob }, new String[] { "Flags", "Name", "Signature" });
            _tableDefs[0x05] = new TableDef(Types.MethodPtr, new Types[] { Types.Method }, new String[] { "Method" });
            _tableDefs[0x06] = new TableDef(Types.Method, new Types[] { Types.UInt32, Types.UInt16, Types.UInt16, Types.String, Types.Blob, Types.Param }, new String[] { "RVA", "ImplFlags", "Flags", "Name", "Signature", "ParamList" });
            _tableDefs[0x07] = new TableDef(Types.ParamPtr, new Types[] { Types.Param }, new String[] { "Param" });
            _tableDefs[0x08] = new TableDef(Types.Param, new Types[] { Types.UInt16, Types.UInt16, Types.String }, new String[] { "Flags", "Sequence", "Name" });
            _tableDefs[0x09] = new TableDef(Types.InterfaceImpl, new Types[] { Types.TypeDef, Types.TypeDefOrRef }, new String[] { "Class", "Interface" });
            _tableDefs[0x0A] = new TableDef(Types.MemberRef, new Types[] { Types.MemberRefParent, Types.String, Types.Blob }, new String[] { "Class", "Name", "Signature" });
            _tableDefs[0x0B] = new TableDef(Types.Constant, new Types[] { Types.UInt16, Types.HasConstant, Types.Blob }, new String[] { "Type", "Parent", "Value" });
            _tableDefs[0x0C] = new TableDef(Types.CustomAttribute, new Types[] { Types.HasCustomAttribute, Types.CustomAttributeType, Types.Blob }, new String[] { "Type", "Parent", "Value" });
            _tableDefs[0x0D] = new TableDef(Types.FieldMarshal, new Types[] { Types.HasFieldMarshal, Types.Blob }, new String[] { "Parent", "Native" });
            _tableDefs[0x0E] = new TableDef(Types.Permission, new Types[] { Types.UInt16, Types.HasDeclSecurity, Types.Blob }, new String[] { "Action", "Parent", "PermissionSet" });
            _tableDefs[0x0F] = new TableDef(Types.ClassLayout, new Types[] { Types.UInt16, Types.UInt32, Types.TypeDef }, new String[] { "PackingSize", "ClassSize", "Parent" });
            _tableDefs[0x10] = new TableDef(Types.FieldLayout, new Types[] { Types.UInt32, Types.Field }, new String[] { "Offset", "Field" });
            _tableDefs[0x11] = new TableDef(Types.StandAloneSig, new Types[] { Types.Blob }, new String[] { "Signature" });
            _tableDefs[0x12] = new TableDef(Types.EventMap, new Types[] { Types.TypeDef, Types.Event }, new String[] { "Parent", "EventList" });
            _tableDefs[0x13] = new TableDef(Types.EventPtr, new Types[] { Types.Event }, new String[] { "Event" });
            _tableDefs[0x14] = new TableDef(Types.Event, new Types[] { Types.UInt16, Types.String, Types.TypeDefOrRef }, new String[] { "EventFlags", "Name", "EventType" });
            _tableDefs[0x15] = new TableDef(Types.PropertyMap, new Types[] { Types.TypeDef, Types.Property }, new String[] { "Parent", "PropertyList" });
            _tableDefs[0x16] = new TableDef(Types.PropertyPtr, new Types[] { Types.Property }, new String[] { "Property" });
            _tableDefs[0x17] = new TableDef(Types.Property, new Types[] { Types.UInt16, Types.String, Types.Blob }, new String[] { "PropFlags", "Name", "Type" });
            _tableDefs[0x18] = new TableDef(Types.MethodSemantics, new Types[] { Types.UInt16, Types.Method, Types.HasSemantic }, new String[] { "Semantic", "Method", "Association" });
            _tableDefs[0x19] = new TableDef(Types.MethodImpl, new Types[] { Types.TypeDef, Types.MethodDefOrRef, Types.MethodDefOrRef }, new String[] { "Class", "MethodBody", "MethodDeclaration" });
            _tableDefs[0x1A] = new TableDef(Types.ModuleRef, new Types[] { Types.String }, new String[] { "Name" });
            _tableDefs[0x1B] = new TableDef(Types.TypeSpec, new Types[] { Types.Blob }, new String[] { "Signature" });
            _tableDefs[0x1C] = new TableDef(Types.ImplMap, new Types[] { Types.UInt16, Types.MemberForwarded, Types.String, Types.ModuleRef }, new String[] { "MappingFlags", "MemberForwarded", "ImportName", "ImportScope" });
            _tableDefs[0x1D] = new TableDef(Types.FieldRVA, new Types[] { Types.UInt32, Types.Field }, new String[] { "RVA", "Field" });
            _tableDefs[0x1E] = new TableDef(Types.ENCLog, new Types[] { Types.UInt32, Types.UInt32 }, new String[] { "Token", "FuncCode" });
            _tableDefs[0x1F] = new TableDef(Types.ENCMap, new Types[] { Types.UInt32 }, new String[] { "Token" });
            _tableDefs[0x20] = new TableDef(Types.Assembly, new Types[] { Types.UInt32, Types.UInt16, Types.UInt16, Types.UInt16, Types.UInt16, Types.UInt32, Types.Blob, Types.String, Types.String }, new String[] { "HashAlgId", "MajorVersion", "MinorVersion", "BuildNumber", "RevisionNumber", "Flags", "PublicKey", "Name", "Locale" });
            _tableDefs[0x21] = new TableDef(Types.AssemblyProcessor, new Types[] { Types.UInt32 }, new String[] { "Processor" });
            _tableDefs[0x22] = new TableDef(Types.AssemblyOS, new Types[] { Types.UInt32, Types.UInt32, Types.UInt32 }, new String[] { "OSPlatformId", "OSMajorVersion", "OSMinorVersion" });
            _tableDefs[0x23] = new TableDef(Types.AssemblyRef, new Types[] { Types.UInt16, Types.UInt16, Types.UInt16, Types.UInt16, Types.UInt32, Types.Blob, Types.String, Types.String, Types.Blob }, new String[] { "MajorVersion", "MinorVersion", "BuildNumber", "RevisionNumber", "Flags", "PublicKeyOrToken", "Name", "Locale", "HashValue" });
            _tableDefs[0x24] = new TableDef(Types.AssemblyRefProcessor, new Types[] { Types.UInt32, Types.AssemblyRef }, new String[] { "Processor", "AssemblyRef" });
            _tableDefs[0x25] = new TableDef(Types.AssemblyRefOS, new Types[] { Types.UInt32, Types.UInt32, Types.UInt32, Types.AssemblyRef }, new String[] { "OSPlatformId", "OSMajorVersion", "OSMinorVersion", "AssemblyRef" });
            _tableDefs[0x26] = new TableDef(Types.File, new Types[] { Types.UInt32, Types.String, Types.Blob }, new String[] { "Flags", "Name", "HashValue" });
            _tableDefs[0x27] = new TableDef(Types.ExportedType, new Types[] { Types.UInt32, Types.UInt32, Types.String, Types.String, Types.Implementation }, new String[] { "Flags", "TypeDefId", "TypeName", "TypeNamespace", "TypeImplementation" });
            _tableDefs[0x28] = new TableDef(Types.ManifestResource, new Types[] { Types.UInt32, Types.UInt32, Types.String, Types.Implementation }, new String[] { "Offset", "Flags", "Name", "Implementation" });
            _tableDefs[0x29] = new TableDef(Types.NestedClass, new Types[] { Types.TypeDef, Types.TypeDef }, new String[] { "NestedClass", "EnclosingClass" });
            // Unused TyPar tables taken from Roeder's reflector... are these documented anywhere?  Since they are always empty, does it matter
            _tableDefs[0x2A] = new TableDef(Types.TypeTyPar, new Types[] { Types.UInt16, Types.TypeDef, Types.TypeDefOrRef, Types.String }, new String[] { "Number", "Class", "Bound", "Name" });
            _tableDefs[0x2B] = new TableDef(Types.MethodTyPar, new Types[] { Types.UInt16, Types.Method, Types.TypeDefOrRef, Types.String }, new String[] { "Number", "Method", "Bound", "Name" });
        }
    }

    public class MDBlob
    {
        public byte[] _data;
        int _length;

        public MDBlob(ByteStream bs)
        {
            // Read length indicator
            _length = bs.DecodeInt32();

            _data = bs.ReadBytes(_length);
        }

        public int Length { get { return _length; } }
        public override string ToString()
        {
            int l = 32;
            if (_length < l) l = _length;

            string sAsc = "", s = "";

            for (int i = 0; i < l; ++i) {
                s += _data[i].ToString("X2") + " ";
                if (_data[i] >= 0x20 && _data[i] < 127) {
                    sAsc += (char)_data[i];
                } else {
                    sAsc += ".";
                }
            }

            if (_length > 32) {
                sAsc += "...";
                s += "...";
            }

            return /*"[" + sAsc + "]       " +*/ s;
        }

        public byte[] ToBytes()
        {
            return _data;
        }
    }

    public class MDGUID
    {
        Guid _g;

        public static MDGUID Empty = new MDGUID();

        public MDGUID()
        {
            _g = Guid.Empty;
        }

        public MDGUID(ByteStream bs)
        {
            _g = new Guid(bs.ReadBytes(16));
        }

        public override string ToString()
        {
            return "{" + _g.ToString() + "}";
        }

        public Guid ToGuid()
        {
            return _g;
        }
    }
}
