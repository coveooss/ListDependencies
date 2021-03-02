//****************************************************************************
// Copyright (c) 2005-2015, Coveo Solutions Inc.
//****************************************************************************

using System;
using System.IO;
using Microsoft.ApplicationBlocks.MemoryMappedFile; // Used for their mapping to Windows routines

namespace Coveo.Cdf.DllUtil
{
    //************************************************************************
    /// <summary>
    /// I wanted an efficient way to read DLL and EXE files.
    /// </summary>
    //************************************************************************
    public unsafe class MmfFile : IDisposable
    {
        private IntPtr m_hFile;
        private IntPtr m_hFileMapping;
        private byte* m_pMapView;

        //************************************************************************
        /// <summary>
        /// Returns the physical address of an offset in the file.
        /// </summary>
        /// <param name="offset"></param>
        /// <returns>The ptr in the mapped file.</returns>
        //************************************************************************
        public unsafe byte* GetPtr(uint offset)
        {
            return (byte*)m_pMapView + offset;
        }

        //************************************************************************
        /// <summary>
        /// Ctor
        /// </summary>
        /// <param name="name"></param>
        //************************************************************************
        public MmfFile(string name)
        {
            MemoryProtection protection = MemoryProtection.PageReadOnly;

            // Open the file
            m_hFile = MemoryMappedFileHelper.CreateFile(
                name,                                       // File name
                Win32FileAccess.GENERIC_READ,               // Access mode
                Win32FileShare.FILE_SHARE_READ,             // Share mode
                IntPtr.Zero,                                // Security Descriptor
                Win32FileMode.OPEN_EXISTING,                // How to create
                Win32FileAttributes.FILE_ATTRIBUTE_NORMAL,  // File attributes
                IntPtr.Zero);                               // Handle to template file
            if (m_hFile == (IntPtr)(-1)) {
                throw new IOException(MemoryMappedFileHelper.GetWin32ErrorMessage(MemoryMappedFileHelper.GetLastError()));
            }

            // Create a file mapping
            m_hFileMapping = MemoryMappedFileHelper.CreateFileMapping(m_hFile, IntPtr.Zero, MemoryProtection.PageReadOnly, 0, 0, null);
            if (m_hFileMapping == IntPtr.Zero) {
                throw new IOException(MemoryMappedFileHelper.GetWin32ErrorMessage(MemoryMappedFileHelper.GetLastError()));
            }

            // Map view it all
            m_pMapView = (byte*)MemoryMappedFileHelper.MapViewOfFile(m_hFileMapping, MemoryMappedFileHelper.GetWin32FileMapAccess(protection), 0, 0, 0);
            if (m_pMapView == null) {
                // If GetLastError returns 5 throw specific exception
                if (MemoryMappedFileHelper.GetLastError() == 5) {
                    throw new Exception("Memory Unavailable");
                } else {
                    throw new IOException(MemoryMappedFileHelper.GetWin32ErrorMessage(MemoryMappedFileHelper.GetLastError()));
                }
            }
        }

        //************************************************************************
        /// <summary>
        /// Close the view, mapping and file
        /// </summary>
        //************************************************************************
        public void Close()
        {
            if (m_pMapView != null) {
                MemoryMappedFileHelper.UnmapViewOfFile((IntPtr)m_pMapView);
            }
            if (m_hFileMapping != IntPtr.Zero) {
                MemoryMappedFileHelper.CloseHandle(m_hFileMapping);
            }
            if (m_hFile != IntPtr.Zero) {
                MemoryMappedFileHelper.CloseHandle(m_hFile);
            }
            GC.SuppressFinalize(this);
        }

        #region IDisposable implementation

        //************************************************************************
        /// <summary>
        /// Dispose the instance of the memory mapped file.
        /// </summary>
        //************************************************************************
        public void Dispose()
        {
            Close();
        }

        #endregion
    }
}
