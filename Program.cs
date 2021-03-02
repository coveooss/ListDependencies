//****************************************************************************
// Copyright (c) 2005-2014, Coveo Solutions Inc.
//****************************************************************************

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
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

        static void Main(string[] args)
        {
            if (args == null || string.IsNullOrWhiteSpace(args[0])) {
                Console.WriteLine(USAGE);
                Environment.Exit(1);
            }

            FileInfo filename;
            if (File.Exists(args[0])) {
                filename = new FileInfo(args[0]);
                Directory.SetCurrentDirectory(filename.DirectoryName);
            } else {
                throw new Exception("Cannot find " + args[0]);
            }

            verbose = args.Length > 1 && args[1] == "verbose";
            internalOnly = args.Length > 1 && args[1] == "internal";

            var dict = new HashSet<string>();
            var unable = new HashSet<string>();
            AddDependencies(0, dict, unable, filename.Name);

            StringBuilder output = new StringBuilder();

            if (!internalOnly) {
                output.AppendLine("\nNot in directory:");
                foreach (var key in unable.OrderBy(x => x)) {
                    output.AppendLine("  " + key);
                }
                output.AppendLine("\nDependencies:");
                foreach (var key in dict.OrderBy(x => x)) {
                    output.AppendLine("  " + ResolveFileName(key));
                }
            } else {
                foreach (var key in dict.OrderBy(x => x)) {
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

        static void AddDependencies(int p_Level, HashSet<string> p_Dict, HashSet<string> p_Unable, string p_Filename)
        {
            if (p_Dict.Contains(p_Filename) || p_Unable.Contains(p_Filename)) {
                return;
            }
            if (verbose) {
                Console.WriteLine(new string(' ', p_Level * 2) + p_Filename);
            }
            p_Dict.Add(p_Filename);
            bool hasDllExt = p_Filename.EndsWith(DLL_EXT, StringComparison.InvariantCultureIgnoreCase) ||
                             p_Filename.EndsWith(PYD_EXT, StringComparison.InvariantCultureIgnoreCase) ||
                             p_Filename.EndsWith(EXE_EXT, StringComparison.InvariantCultureIgnoreCase);
            try {
                using (var dllReader = new DllReader(hasDllExt ? p_Filename : p_Filename + DLL_EXT)) {
                    if (dllReader.IsPureClr) {
                        foreach (var ass in dllReader.AssemblyReferences) {
                            AddDependencies(p_Level + 1, p_Dict, p_Unable, ass.Name);
                        }
                    } else {
                        foreach (var dll in dllReader.DllDependencies) {
                            AddDependencies(p_Level + 1, p_Dict, p_Unable, dll.Name);
                        }
                    }
                }
            } catch (Exception) {
                p_Dict.Remove(p_Filename);
                p_Unable.Add(p_Filename);
            }
        }

    }
}
