using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using static System.Net.WebRequestMethods;

namespace TelemetryAssessmentTool
{
    // Analyses Windows diagnostic data folders for telemetry data and personal information (PII)
    public class DiagnosticDataAnalyser
    {
        // Logging list to track detailed scan operations
        private List<string> scanLog = new List<string>();

        // Main method to analyse diagnostic data
        public async Task<DiagnosticAnalysisResult> AnalyzeDiagnosticDataAsync(Action<int, string> progressCallback = null)
        {
            return await Task.Run(() =>
            {
                var result = new DiagnosticAnalysisResult
                {
                    AnalysisTime = DateTime.UtcNow,
                    MachineName = Environment.MachineName,
                    Username = Environment.UserName
                };

                try
                {
                    // 1. Find diagnostic folders
                    LogMessage("=== STARTING DIAGNOSTIC FOLDER SCAN ===");
                    result.DiagnosticFolders = FindDiagnosticFolders(progressCallback);
                    LogMessage($"Found {result.DiagnosticFolders.Count} potential diagnostic locations");

                    // 2. Scan for diagnostic files
                    progressCallback?.Invoke(30, "Scanning for diagnostic files...");
                    LogMessage("=== STARTING FILE SCAN ===");
                    result.FoundFiles = ScanDiagnosticFiles(result.DiagnosticFolders);
                    LogMessage($"Scanned {result.FoundFiles.Count} files");

                    // 3. Analyse for PII in text files
                    progressCallback?.Invoke(60, "Analyzing text files for PII...");
                    LogMessage("=== STARTING TEXT FILE PII ANALYSIS ===");
                    AnalyzeFileContents(result);

                    // 4. Analyse ETL files for PII
                    progressCallback?.Invoke(70, "Analyzing ETL files for PII...");
                    LogMessage("=== STARTING ETL FILE ANALYSIS ===");
                    AnalyzeEtlFiles(result);

                    // 5. Calculate statistics
                    progressCallback?.Invoke(80, "Calculating statistics...");
                    LogMessage("=== CALCULATING STATISTICS ===");
                    CalculateStatistics(result);

                    // 6. Risk assessment
                    //progressCallback?.Invoke(90, "Assessing privacy risk...");
                    //LogMessage("=== ASSESSING PRIVACY RISK ===");
                    //AssessPrivacyRisk(result);

                    progressCallback?.Invoke(100, "Scan complete");
                    LogMessage("=== SCAN COMPLETED SUCCESSFULLY ===");

                    result.ScanLog = scanLog;
                }
                catch (Exception ex)
                {
                    result.Error = ex.Message;
                    LogMessage($"ERROR: {ex.Message}");
                    LogMessage($"STACK TRACE: {ex.StackTrace}");
                    result.ScanLog = scanLog;
                }

                return result;
            });
        }


        // Scans 10 folders with AllDirectories option
        private List<DiagnosticFolder> FindDiagnosticFolders(Action<int, string> progressCallback = null)
        {
            var folders = new List<DiagnosticFolder>();

            // Expanded list of diagnostic folder locations
            var potentialPaths = new[]
            {
                
                new { Path = @"C:\ProgramData\Microsoft\Diagnosis", Type = "System", Description = "System diagnostics" },
                new { Path = @"C:\Windows\Temp\Diagnostics", Type = "System", Description = "Temp diagnostics" },
                new { Path = Environment.ExpandEnvironmentVariables(@"%LocalAppData%\Diagnostics"), Type = "User", Description = "User diagnostics" },
                new { Path = Environment.ExpandEnvironmentVariables(@"%LocalAppData%\Microsoft\Windows\WER"), Type = "Error", Description = "Error reporting" },

                new { Path = @"C:\ProgramData\Microsoft\Diagnosis\ETLLogs", Type = "System", Description = "Telemetry event logs" },
                new { Path = @"C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger", Type = "System", Description = "AutoLogger telemetry" },
                new { Path = @"C:\Windows\System32\LogFiles\WMI", Type = "System", Description = "WMI event logs" },
                new { Path = @"C:\Windows\System32\LogFiles\WMI\RtBackup", Type = "System", Description = "WMI backup logs" },
                new { Path = Environment.ExpandEnvironmentVariables(@"%LocalAppData%\Microsoft\Windows\Explorer"), Type = "User", Description = "Explorer telemetry" },
                new { Path = @"C:\Windows\Logs\CBS", Type = "System", Description = "Component-Based Servicing logs" },
            };

            int folderIndex = 0;
            foreach (var location in potentialPaths)
            {
                folderIndex++;
                int progressPercent = 10 + (folderIndex * 15 / potentialPaths.Length);

                // Show which folder is currently being accessed
                progressCallback?.Invoke(progressPercent, $"Accessing: {location.Path}");

                LogMessage($"Checking folder: {location.Path}");

                if (Directory.Exists(location.Path))
                {
                    try
                    {
                        var dirInfo = new DirectoryInfo(location.Path);

                        // Searches through all listed directories

                        var files = dirInfo.GetFiles("*", SearchOption.AllDirectories)
                            .Take(1000) // Safety limit: max 1000 files per location
                            .ToArray();

                        folders.Add(new DiagnosticFolder
                        {
                            Path = location.Path,
                            Type = location.Type,
                            Description = location.Description,
                            Exists = true,
                            FileCount = files.Length,
                            TotalSizeBytes = files.Sum(f => f.Length),
                            LastModified = dirInfo.LastWriteTime,
                            IsAccessible = true
                        });

                        LogMessage($"SUCCESS: Accessed {location.Path} - Found {files.Length} files ({FormatBytes(files.Sum(f => f.Length))})");
                    }
                    catch (UnauthorizedAccessException ex)
                    {
                        folders.Add(new DiagnosticFolder
                        {
                            Path = location.Path,
                            Type = location.Type,
                            Description = location.Description,
                            Exists = true,
                            IsAccessible = false,
                            AccessError = "Access denied - requires administrator privileges"
                        });

                        LogMessage($"ACCESS DENIED: {location.Path} - {ex.Message}");
                    }
                    catch (Exception ex)
                    {
                        folders.Add(new DiagnosticFolder
                        {
                            Path = location.Path,
                            Type = location.Type,
                            Description = location.Description,
                            Exists = true,
                            IsAccessible = false,
                            AccessError = $"Error: {ex.Message}"
                        });

                        LogMessage($"ERROR: {location.Path} - {ex.Message}");
                    }
                }
                else
                {
                    folders.Add(new DiagnosticFolder
                    {
                        Path = location.Path,
                        Type = location.Type,
                        Description = location.Description,
                        Exists = false
                    });

                    LogMessage($"NOT FOUND: {location.Path}");
                }
            }

            return folders;
        }

        // Scans diagnostic folders for relevant file types
        private List<DiagnosticFile> ScanDiagnosticFiles(List<DiagnosticFolder> folders)
        {
            var files = new List<DiagnosticFile>();

            // Added .etl to extensions list
            var diagnosticExtensions = new[]
            {
                "*.log", "*.txt", "*.etl", "*.tmp",
                "*.wer", "*.dmp", "*.xml", "*.json"
            };

            foreach (var folder in folders.Where(f => f.Exists && f.IsAccessible))
            {
                LogMessage($"Scanning files in: {folder.Path}");
                int filesFoundInFolder = 0;

                foreach (var extension in diagnosticExtensions)
                {
                    try
                    {
                        // Recursive with limit
                        var foundFiles = Directory.GetFiles(folder.Path, extension, SearchOption.AllDirectories)
                            .Take(100) // Limit: max 100 files per extension per folder
                            .ToArray();

                        foreach (var filePath in foundFiles)
                        {
                            try
                            {
                                var fileInfo = new FileInfo(filePath);

                                // Skip extremely large files (>50MB) for performance
                                if (fileInfo.Length > 50 * 1024 * 1024)
                                {
                                    LogMessage($"  Skipped (too large): {Path.GetFileName(filePath)} ({FormatBytes(fileInfo.Length)})");
                                    continue;
                                }

                                files.Add(new DiagnosticFile
                                {
                                    FilePath = filePath,
                                    FileName = Path.GetFileName(filePath),
                                    Extension = Path.GetExtension(filePath),
                                    SizeBytes = fileInfo.Length,
                                    Created = fileInfo.CreationTime,
                                    Modified = fileInfo.LastWriteTime,
                                    FolderType = folder.Type,
                                    IsReadable = true
                                });

                                filesFoundInFolder++;
                            }
                            catch (Exception ex)
                            {
                                LogMessage($"  Error accessing file {filePath}: {ex.Message}");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        LogMessage($"  Error scanning {extension} in {folder.Path}: {ex.Message}");
                    }
                }

                LogMessage($"  Found {filesFoundInFolder} files in this folder");
            }

            LogMessage($"Total files collected for analysis: {files.Count}");
            return files;
        }

        // Analyzes text file contents for PII patterns
        private void AnalyzeFileContents(DiagnosticAnalysisResult result)
        {
            var piiFiles = new List<PiiDetection>();

            var piiPatterns = new[]
            {
                new PiiPattern { Name = "Email", Pattern = @"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", RiskLevel = "Medium" },
                // Improved IP pattern that validates octets (0-255)
                new PiiPattern { Name = "IP Address", Pattern = @"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", RiskLevel = "Low" },
                new PiiPattern { Name = "File Path", Pattern = @"[A-Za-z]:\\(?:[^\\/:*?""<>|\r\n]+\\)*[^\\/:*?""<>|\r\n]*", RiskLevel = "Low" },
            };

            // Only scan text-based files (not binary)
            var textFiles = result.FoundFiles.Where(f =>
                f.Extension.Equals(".log", StringComparison.OrdinalIgnoreCase) ||
                f.Extension.Equals(".txt", StringComparison.OrdinalIgnoreCase) ||
                f.Extension.Equals(".xml", StringComparison.OrdinalIgnoreCase) ||
                f.Extension.Equals(".json", StringComparison.OrdinalIgnoreCase));

            LogMessage($"Analyzing {textFiles.Count()} text files for PII");

            // Takes 50 files for analysis for more detailed report
            int filesAnalyzed = 0;
            foreach (var file in textFiles.Take(50))
            {
                try
                {
                    // Read first 64KB of file (increased from 32KB)
                    var content = ReadFileSafely(file.FilePath, 64 * 1024);

                    if (!string.IsNullOrEmpty(content))
                    {
                        bool foundPiiInFile = false;

                        foreach (var pattern in piiPatterns)
                        {
                            var matches = Regex.Matches(content, pattern.Pattern, RegexOptions.IgnoreCase);

                            if (matches.Count > 0)
                            {
                                // Filter out false positives for IP addresses
                                var validMatches = matches.Cast<Match>().Select(m => m.Value).ToList();

                                if (pattern.Name == "IP Address")
                                {
                                    // Filter out local/private IPs to reduce noise
                                    validMatches = validMatches.Where(ip => !IsLocalOrPrivateIP(ip)).ToList();
                                }

                                if (validMatches.Any())
                                {
                                    var uniqueMatches = validMatches.Distinct().Take(3).ToList();

                                    piiFiles.Add(new PiiDetection
                                    {
                                        FilePath = file.FilePath,
                                        PiiType = pattern.Name,
                                        RiskLevel = pattern.RiskLevel,
                                        MatchCount = validMatches.Count,
                                        SampleMatches = uniqueMatches
                                    });

                                    foundPiiInFile = true;
                                }
                            }
                        }

                        if (foundPiiInFile)
                        {
                            LogMessage($"  PII FOUND in {Path.GetFileName(file.FilePath)}");
                        }

                        filesAnalyzed++;
                    }
                }
                catch (Exception ex)
                {
                    LogMessage($"  Error reading {file.FilePath}: {ex.Message}");
                }
            }

            LogMessage($"Analyzed {filesAnalyzed} text files, found PII in {piiFiles.Count} instances");
            result.PiiDetections = piiFiles;
        }

        // Analyses ETL files - ETL files are binary telemetry logs that require special parsing
        private void AnalyzeEtlFiles(DiagnosticAnalysisResult result)
        {
            // Find all .etl files
            var etlFiles = result.FoundFiles.Where(f =>
                f.Extension.Equals(".etl", StringComparison.OrdinalIgnoreCase));

            LogMessage($"Found {etlFiles.Count()} ETL files to analyze");

            if (!etlFiles.Any())
            {
                LogMessage("No ETL files to analyze");
                return;
            }

            int etlFilesAnalyzed = 0;
            int etlFilesWithPii = 0;

            // Limit ETL analysis to 20 files for performance
            foreach (var etlFile in etlFiles.Take(20))
            {
                try
                {
                    LogMessage($"  Analyzing ETL: {Path.GetFileName(etlFile.FilePath)}");

                    // Parse ETL file and extract text content
                    var extractedText = ParseEtlFile(etlFile.FilePath);

                    if (!string.IsNullOrEmpty(extractedText))
                    {
                        bool foundPii = false;

                        // Check for emails
                        var emailMatches = Regex.Matches(extractedText,
                            @"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
                            RegexOptions.IgnoreCase);

                        if (emailMatches.Count > 0)
                        {
                            result.PiiDetections.Add(new PiiDetection
                            {
                                FilePath = etlFile.FilePath,
                                PiiType = "Email (ETL)",
                                RiskLevel = "High", // Higher risk because it's in telemetry logs
                                MatchCount = emailMatches.Count,
                                SampleMatches = emailMatches.Cast<Match>()
                                    .Select(m => m.Value)
                                    .Distinct()
                                    .Take(3)
                                    .ToList()
                            });
                            foundPii = true;
                        }

                        // Check for usernames/paths
                        var usernameMatches = Regex.Matches(extractedText,
                            @"C:\\Users\\([^\\]+)\\",
                            RegexOptions.IgnoreCase);

                        if (usernameMatches.Count > 0)
                        {
                            var usernames = usernameMatches.Cast<Match>()
                                .Select(m => m.Groups[1].Value)
                                .Distinct()
                                .Where(u => u != "Public" && u != "Default")
                                .Take(3)
                                .ToList();

                            if (usernames.Any())
                            {
                                result.PiiDetections.Add(new PiiDetection
                                {
                                    FilePath = etlFile.FilePath,
                                    PiiType = "Username (ETL)",
                                    RiskLevel = "Medium",
                                    MatchCount = usernames.Count,
                                    SampleMatches = usernames
                                });
                                foundPii = true;
                            }
                        }

                        if (foundPii)
                        {
                            etlFilesWithPii++;
                            LogMessage($"    PII FOUND in ETL file");
                        }
                    }

                    etlFilesAnalyzed++;
                }
                catch (Exception ex)
                {
                    LogMessage($"    Error parsing ETL {etlFile.FilePath}: {ex.Message}");
                }
            }

            LogMessage($"ETL Analysis complete: {etlFilesAnalyzed} files analyzed, {etlFilesWithPii} contained PII");
        }

        // Parses ETL binary files to extract readable text
        // Uses EventLogReader to decode Windows Event Tracing logs
        private string ParseEtlFile(string etlFilePath)
        {
            var extractedText = new System.Text.StringBuilder();

            try
            {
                // Use EventLogReader to parse ETL files
                var query = new EventLogQuery(etlFilePath, PathType.FilePath);

                using (var reader = new EventLogReader(query))
                {
                    EventRecord record;
                    int eventCount = 0;

                    // Read up to 100 events from the ETL file
                    while ((record = reader.ReadEvent()) != null && eventCount < 100)
                    {
                        try
                        {
                            // Extract text from event description
                            if (!string.IsNullOrEmpty(record.FormatDescription()))
                            {
                                extractedText.AppendLine(record.FormatDescription());
                            }

                            // Extract text from event properties
                            if (record.Properties != null)
                            {
                                foreach (var prop in record.Properties)
                                {
                                    if (prop.Value != null)
                                    {
                                        extractedText.AppendLine(prop.Value.ToString());
                                    }
                                }
                            }

                            eventCount++;
                        }
                        catch
                        {
                            continue;
                        }
                    }

                    LogMessage($"    Extracted {eventCount} events from ETL");
                }
            }
            catch (EventLogNotFoundException)
            {
                // ETL file is not a valid event log - try binary text extraction
                LogMessage($"    ETL file not in event log format, attempting binary scan");
                return ExtractTextFromBinary(etlFilePath);
            }
            catch (Exception ex)
            {
                LogMessage($"    Error parsing ETL with EventLogReader: {ex.Message}");
                return ExtractTextFromBinary(etlFilePath);
            }

            return extractedText.ToString();
        }

        // Fallback method to extract ASCII text from binary ETL files
        // Scans for readable text strings in binary data
        private string ExtractTextFromBinary(string filePath)
        {
            var extractedText = new System.Text.StringBuilder();

            try
            {
                // Read first 512KB of binary file
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    byte[] buffer = new byte[Math.Min(512 * 1024, fs.Length)];
                    int bytesRead = fs.Read(buffer, 0, buffer.Length);

                    // Extract printable ASCII strings (minimum 4 characters)
                    var currentString = new System.Text.StringBuilder();

                    for (int i = 0; i < bytesRead; i++)
                    {
                        byte b = buffer[i];

                        // Check if byte is printable ASCII (32-126)
                        if (b >= 32 && b <= 126)
                        {
                            currentString.Append((char)b);
                        }
                        else
                        {
                            // End of string - save if long enough
                            if (currentString.Length >= 4)
                            {
                                extractedText.Append(currentString.ToString());
                                extractedText.Append(' ');
                            }
                            currentString.Clear();
                        }
                    }

                    // Add final string if exists
                    if (currentString.Length >= 4)
                    {
                        extractedText.Append(currentString.ToString());
                    }
                }

                LogMessage($"    Binary extraction found {extractedText.Length} characters");
            }
            catch (Exception ex)
            {
                LogMessage($"    Binary extraction failed: {ex.Message}");
            }

            return extractedText.ToString();
        }

        //  Filters out local/private IP addresses to reduce false positives
        // Returns true if IP is local/private
        private bool IsLocalOrPrivateIP(string ipAddress)
        {
            try
            {
                var parts = ipAddress.Split('.');
                if (parts.Length != 4) return false;

                int firstOctet = int.Parse(parts[0]);
                int secondOctet = int.Parse(parts[1]);

                // Loopback (127.0.0.0/8)
                if (firstOctet == 127) return true;

                // Private Class A (10.0.0.0/8)
                if (firstOctet == 10) return true;

                // Private Class B (172.16.0.0/12)
                if (firstOctet == 172 && secondOctet >= 16 && secondOctet <= 31) return true;

                // Private Class C (192.168.0.0/16)
                if (firstOctet == 192 && secondOctet == 168) return true;

                // Link-local (169.254.0.0/16)
                if (firstOctet == 169 && secondOctet == 254) return true;

                return false;
            }
            catch
            {
                return false;
            }
        }

        // Calculates statistics about found files
        private void CalculateStatistics(DiagnosticAnalysisResult result)
        {
            result.TotalFilesFound = result.FoundFiles.Count;
            result.TotalDataSizeBytes = result.FoundFiles.Sum(f => f.SizeBytes);

            result.FilesByType = result.FoundFiles
                .GroupBy(f => f.Extension.ToLower())
                .Select(g => new FileTypeSummary
                {
                    Extension = g.Key,
                    Count = g.Count(),
                    TotalSizeBytes = g.Sum(f => f.SizeBytes)
                })
                .OrderByDescending(x => x.Count)
                .ToList();

            LogMessage($"Statistics: {result.TotalFilesFound} files, {FormatBytes(result.TotalDataSizeBytes)} total");
        }

        // Improved risk assessment algorithm
        // Tiered thresholds and weighted PII scoring
        //private void AssessPrivacyRisk(DiagnosticAnalysisResult result)
        //{
        //    int riskScore = 0;
        //    var risks = new List<string>();

        //    // Tiered volume risk assessment
        //    double totalMB = result.TotalDataSizeBytes / (1024.0 * 1024.0);

        //    // Multi-tier volume assessment (raised thresholds)
        //    if (totalMB > 500)
        //    {
        //        riskScore += 40;
        //        risks.Add($"Very large diagnostic data volume: {totalMB:F1} MB");
        //    }
        //    else if (totalMB > 100)
        //    {
        //        riskScore += 20;
        //        risks.Add($"Large diagnostic data volume: {totalMB:F1} MB");
        //    }
        //    else if (totalMB > 50)
        //    {
        //        riskScore += 10;
        //        risks.Add($"Moderate diagnostic data volume: {totalMB:F1} MB");
        //    }

        //    // Weighted PII risk by sensitivity
        //    if (result.PiiDetections.Any())
        //    {
        //        int piiScore = 0;

        //        foreach (var detection in result.PiiDetections)
        //        {
        //            // Weight by PII type and source
        //            if (detection.PiiType.Contains("Email"))
        //            {
        //                piiScore += detection.PiiType.Contains("ETL") ? 15 : 10;
        //            }
        //            else if (detection.PiiType.Contains("Username"))
        //            {
        //                piiScore += 8;
        //            }
        //            else if (detection.PiiType.Contains("IP Address"))
        //            {
        //                piiScore += 3;
        //            }
        //            else if (detection.PiiType.Contains("File Path"))
        //            {
        //                piiScore += 2;
        //            }
        //            else
        //            {
        //                piiScore += 5;
        //            }
        //        }

        //        riskScore += Math.Min(50, piiScore); // Cap PII contribution at 50 points
        //        risks.Add($"Found PII in {result.PiiDetections.Count} file instances");
        //    }

        //    // ETL file presence increases risk
        //    var etlCount = result.FoundFiles.Count(f => f.Extension.Equals(".etl", StringComparison.OrdinalIgnoreCase));
        //    if (etlCount > 50)
        //    {
        //        riskScore += 10;
        //        risks.Add($"High number of telemetry trace logs: {etlCount} ETL files");
        //    }

        //    // Cap at 100
        //    result.PrivacyRiskScore = Math.Min(100, riskScore);

        //    result.PrivacyRiskLevel = result.PrivacyRiskScore switch
        //    {
        //        >= 70 => "High",
        //        >= 40 => "Medium",
        //        >= 15 => "Low",
        //        _ => "Minimal"
        //    };

        //    result.RiskFactors = risks;

        //    LogMessage($"Final Risk Score: {result.PrivacyRiskScore}/100 ({result.PrivacyRiskLevel})");
        //}

        // Safely reads file with read-only access
        private string ReadFileSafely(string filePath, int maxBytes)
        {
            try
            {
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (var reader = new StreamReader(fs))
                {
                    char[] buffer = new char[maxBytes];
                    int bytesRead = reader.Read(buffer, 0, maxBytes);
                    return new string(buffer, 0, bytesRead);
                }
            }
            catch
            {
                return string.Empty;
            }
        }

        // Adds message to scan log for detailed tracking
        private void LogMessage(string message)
        {
            string timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
            scanLog.Add($"[{timestamp}] {message}");
        }

        // Formats bytes into human-readable format
        private string FormatBytes(long bytes)
        {
            if (bytes == 0) return "0 B";

            string[] suffixes = { "B", "KB", "MB", "GB", "TB" };
            int suffixIndex = 0;
            double size = bytes;

            while (size >= 1024 && suffixIndex < suffixes.Length - 1)
            {
                size /= 1024;
                suffixIndex++;
            }

            return $"{size:F2} {suffixes[suffixIndex]}";
        }

        // Data Models

        public class DiagnosticAnalysisResult
        {
            public DateTime AnalysisTime { get; set; }
            public string MachineName { get; set; }
            public string Username { get; set; }
            public string Error { get; set; }

            public List<DiagnosticFolder> DiagnosticFolders { get; set; } = new();
            public List<DiagnosticFile> FoundFiles { get; set; } = new();
            public List<FileTypeSummary> FilesByType { get; set; } = new();
            public List<PiiDetection> PiiDetections { get; set; } = new();

            public int TotalFilesFound { get; set; }
            public long TotalDataSizeBytes { get; set; }

            //public int PrivacyRiskScore { get; set; }
            //public string PrivacyRiskLevel { get; set; }
            //public List<string> RiskFactors { get; set; } = new();

            public List<string> ScanLog { get; set; } = new();
        }

        public class DiagnosticFolder
        {
            public string Path { get; set; }
            public string Type { get; set; }
            public string Description { get; set; }
            public bool Exists { get; set; }
            public bool IsAccessible { get; set; }
            public string AccessError { get; set; }
            public int FileCount { get; set; }
            public long TotalSizeBytes { get; set; }
            public DateTime LastModified { get; set; }
        }

        public class DiagnosticFile
        {
            public string FilePath { get; set; }
            public string FileName { get; set; }
            public string Extension { get; set; }
            public string FolderType { get; set; }
            public long SizeBytes { get; set; }
            public DateTime Created { get; set; }
            public DateTime Modified { get; set; }
            public bool IsReadable { get; set; }
        }

        public class PiiDetection
        {
            public string FilePath { get; set; }
            public string PiiType { get; set; }
            public string RiskLevel { get; set; }
            public int MatchCount { get; set; }
            public List<string> SampleMatches { get; set; } = new();
        }

        public class FileTypeSummary
        {
            public string Extension { get; set; }
            public int Count { get; set; }
            public long TotalSizeBytes { get; set; }
        }

        public class PiiPattern
        {
            public string Name { get; set; }
            public string Pattern { get; set; }
            public string RiskLevel { get; set; }
        }
    }
}
