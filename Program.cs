//****************************************************************************
// Copyright (c) 2005-2014, Coveo Solutions Inc.
//****************************************************************************

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Coveo.Cdf.DllUtil;

namespace ListDependencies
{
    //****************************************************************************
    /// <summary>
    /// Small utility that outputs the dependencies required by an exe/dll to the console.
    /// Usage: ListDependencies someFile.ext <verbose|internal> <outputfile.ext>
    ///     Arg1 == File to inspect
    ///     Arg2 == verbose or internal (prints a tree, or just internal dlls with full paths)
    ///     Arg3 == a file to output results to
    /// </summary>
    //****************************************************************************
    class Program
    {
        const string USAGE = "\nUsage: ListDependencies someFile.ext <verbose|internal> <outputfile.ext>\n";

        const string PYD_EXT = ".pyd";
        const string DLL_EXT = ".dll";
        const string EXE_EXT = ".exe";

        static bool verbose = false;
        static bool internalOnly = false;

        static HashSet<string> FoundInCurrentDir = new HashSet<string>();
        static HashSet<string> FoundInWindowsDir = new HashSet<string>();
        static HashSet<string> NotFound = new HashSet<string>();

        // 
        // https://regex101.com/r/CKvCnx/2
        static string ApiSetPattern = "(api-|ext-)[a-zA-Z0-9-]*(l[0-9]-[0-9]-[0-9])";
        static Regex ApiSetRegex;

        static void Main(string[] args)
        {
            if (args == null || string.IsNullOrWhiteSpace(args[0])) {
                Console.WriteLine(USAGE);
                Environment.Exit(1);
            }

            ApiSetRegex = new Regex(ApiSetPattern, RegexOptions.IgnoreCase | RegexOptions.Compiled);

            FileInfo filename;
            if (File.Exists(args[0])) {
                filename = new FileInfo(args[0]);
                Directory.SetCurrentDirectory(filename.DirectoryName);
            } else {
                throw new Exception("Cannot find " + args[0]);
            }

            verbose = args.Length > 1 && args[1] == "verbose";
            internalOnly = args.Length > 1 && args[1] == "internal";

            AddDependencies(0, filename.Name);

            StringBuilder output = new StringBuilder();

            if (!internalOnly) {
                output.AppendLine("\nDependencies in current directory:");
                foreach (var key in FoundInCurrentDir.OrderBy(x => x)) {
                    output.AppendLine("  " + ResolveFileName(key));
                }
                output.AppendLine("\nDependencies in Windows System32 directory:");
                foreach (var key in FoundInWindowsDir.OrderBy(x => x))
                {
                    output.AppendLine("  " + ResolveFileName(key));
                }
                output.AppendLine("\nNot found:");
                foreach (var key in NotFound.OrderBy(x => x))
                {
                    output.AppendLine("  " + key);
                }
            }
            else {
                foreach (var key in FoundInCurrentDir.OrderBy(x => x)) {
                    FileInfo dep = new FileInfo(ResolveFileName(key));
                    output.AppendLine(dep.FullName);
                }
            }

            if (args.Length > 2) {
                Console.WriteLine(output.ToString());
                File.WriteAllText(args[2], output.ToString());
            } else {
                Console.WriteLine(output.ToString());
            }
        }

        static string ResolveFileName(string p_FileName)
        {
            if (!File.Exists(p_FileName)) {
                if (File.Exists(p_FileName + DLL_EXT)) {
                    p_FileName = p_FileName + DLL_EXT;
                } else if (File.Exists(p_FileName + EXE_EXT)) {
                    p_FileName = p_FileName + EXE_EXT;
                }
            }
            return p_FileName;
        }

        static void AddDependencies(int p_Level, string p_Filename)
        {
            if (FoundInCurrentDir.Contains(p_Filename) || FoundInWindowsDir.Contains(p_Filename) || NotFound.Contains(p_Filename)) {
                return;
            }
            if( ApiSetRegex.IsMatch(p_Filename))
            {
                return;
            }

            if (verbose)
            {
                Console.WriteLine(new string(' ', p_Level * 2) + p_Filename);
            }

            FoundInCurrentDir.Add(p_Filename);
            bool hasDllExt = p_Filename.EndsWith(DLL_EXT, StringComparison.InvariantCultureIgnoreCase) ||
                             p_Filename.EndsWith(PYD_EXT, StringComparison.InvariantCultureIgnoreCase) ||
                             p_Filename.EndsWith(EXE_EXT, StringComparison.InvariantCultureIgnoreCase);
            try {
                using (var dllReader = new DllReader(hasDllExt ? p_Filename : p_Filename + DLL_EXT)) {
                    if (dllReader.IsPureClr) {
                        foreach (var ass in dllReader.AssemblyReferences) {
                            AddDependencies(p_Level + 1, ass.Name);
                        }
                    } else {
                        foreach (var dll in dllReader.DllDependencies) {
                            AddDependencies(p_Level + 1, dll.Name);
                        }
                    }
                }
            } catch (Exception) {
                FoundInCurrentDir.Remove(p_Filename);
                if(File.Exists( Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), p_Filename)))
                {
                    FoundInWindowsDir.Add(p_Filename);
                }
                else
                {
                    NotFound.Add(p_Filename);
                }
            }
        }

    }
}
