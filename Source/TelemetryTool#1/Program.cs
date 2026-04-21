using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using TelemetryAssessmentTool.Services;
using static TelemetryAssessmentTool.DiagnosticDataAnalyser;
using static TelemetryAssessmentTool.Services.TelemetryRegistryScanner;
using static TelemetryAssessmentTool.Services.TelemetryServicesScanner;

namespace TelemetryAssessmentTool
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("=== Windows Telemetry Assessment Tool ===\n");

            CheckAdministratorPrivileges();

            while (true)
            {
                Console.WriteLine("\nOptions:");
                Console.WriteLine("1. Scan Windows Registry for telemetry keys");
                Console.WriteLine("2. Scan Diagnostic Data Files for Personally Identifiable Information");
                Console.WriteLine("3. Scan Windows Services for telemetry components");
                Console.WriteLine("4. Run Complete Exposure Analysis (All Scans)");
                Console.WriteLine("5. Exit");

                Console.Write("\nSelect option: ");
                string input = Console.ReadLine();

                switch (input)
                {
                    case "1":
                        await ScanRegistryTelemetryAsync();
                        break;
                    case "2":
                        await ScanDiagnosticDataAsync();
                        break;
                    case "3":
                        await ScanTelemetryServicesAsync();
                        break;
                    case "4":
                        await RunCompleteExposureAnalysisAsync();
                        break;
                    case "5":
                        Console.WriteLine("\nExiting...");
                        return;
                    default:
                        Console.WriteLine("Invalid option");
                        break;
                }
            }
        }

        // Checks if the program is running with administrator privileges
        // Warns user if not elevated, as diagnostic folder access will be limited
        static void CheckAdministratorPrivileges()
        {
            bool isAdmin = false;

            try
            {
                var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                isAdmin = principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch
            {
                isAdmin = false;
            }

            if (!isAdmin)
            {
                Console.WriteLine("WARNING: Not running as Administrator");
                Console.WriteLine("Some diagnostic folders may be inaccessible.");
                Console.WriteLine("For complete analysis, right-click and 'Run as Administrator'\n");
            }
            else
            {
                Console.WriteLine("Running with Administrator privileges\n");
            }
        }

        // Scans Windows Registry for telemetry configuration keys
        // Checks AllowTelemetry and CEIPEnable settings
        static async Task ScanRegistryTelemetryAsync()
        {
            Console.Clear();
            Console.WriteLine("=== Windows Registry Telemetry Scanner ===\n");
            Console.WriteLine("Scanning registry for telemetry keys...\n");

            Console.Write("Progress: [");

            var scanner = new TelemetryRegistryScanner();

            var findings = await scanner.ScanTelemetryKeysAsync((current, max) =>
            {
                Console.Write("#");
            });

            Console.Write("] 100%\n\n");

            Console.WriteLine("==========================================");
            Console.WriteLine("              SCAN RESULTS");
            Console.WriteLine("==========================================\n");

            if (findings.Count == 0)
            {
                Console.WriteLine("No telemetry registry keys found.");
            }
            else
            {
                var allowTelemetryResults = new List<RegistryFinding>();
                var ceipResults = new List<RegistryFinding>();

                foreach (var finding in findings)
                {
                    if (finding.KeyName == "AllowTelemetry")
                        allowTelemetryResults.Add(finding);
                    else if (finding.KeyName == "CEIPEnable")
                        ceipResults.Add(finding);
                }

                if (allowTelemetryResults.Count > 0)
                {
                    Console.WriteLine("ALLOWTELEMETRY SETTINGS:");
                    Console.WriteLine("------------------------");

                    foreach (var finding in allowTelemetryResults)
                    {
                        Console.WriteLine($"Path: {finding.Path}");
                        Console.WriteLine($"Value: {finding.Value}");

                        if (finding.Value == "1" || finding.Value == "2" || finding.Value == "3")
                        {
                            Console.WriteLine("Status: ACTIVE - Telemetry is enabled");
                        }
                        else if (finding.Value == "0")
                        {
                            Console.WriteLine("Status: INACTIVE - Telemetry is disabled");
                        }
                        Console.WriteLine();
                    }
                }

                if (ceipResults.Count > 0)
                {
                    Console.WriteLine("CEIPENABLE SETTINGS:");
                    Console.WriteLine("-------------------");

                    foreach (var finding in ceipResults)
                    {
                        Console.WriteLine($"Path: {finding.Path}");
                        Console.WriteLine($"Value: {finding.Value}");

                        if (finding.Value == "1")
                        {
                            Console.WriteLine("Status: ACTIVE - CEIP is enabled");
                        }
                        else if (finding.Value == "0")
                        {
                            Console.WriteLine("Status: INACTIVE - CEIP is disabled");
                        }
                        Console.WriteLine();
                    }
                }

                Console.WriteLine("==========================================");
                Console.WriteLine("          ACTIVE SERVICES SUMMARY");
                Console.WriteLine("==========================================");

                bool foundActive = false;

                foreach (var finding in findings)
                {
                    if (finding.KeyName == "AllowTelemetry" &&
                        (finding.Value == "1" || finding.Value == "2" || finding.Value == "3"))
                    {
                        if (!foundActive)
                        {
                            Console.WriteLine("\nThese telemetry services are active:");
                            foundActive = true;
                        }
                        Console.WriteLine($"- AllowTelemetry at {finding.Path} (Level: {finding.Value})");
                    }

                    if (finding.KeyName == "CEIPEnable" && finding.Value == "1")
                    {
                        if (!foundActive)
                        {
                            Console.WriteLine("\nThese telemetry services are active:");
                            foundActive = true;
                        }
                        Console.WriteLine($"- CEIPEnable at {finding.Path}");
                    }
                }

                if (!foundActive)
                {
                    Console.WriteLine("\nNo active telemetry services detected.");
                }

                Console.WriteLine($"\nTotal registry entries scanned: {findings.Count}");
            }

            Console.WriteLine("\n==========================================");
            Console.WriteLine("\nPress any key to return to menu...");
            Console.ReadKey();
            Console.Clear();
        }

        // Scans diagnostic data files with live folder status logging during analysis
        // Analyzes files for PII and provides statistics on telemetry data volume
        static async Task ScanDiagnosticDataAsync()
        {
            Console.Clear();
            Console.WriteLine("=== Diagnostic Data File Analyzer ===\n");
            Console.WriteLine("Scanning Windows diagnostic folders for PII in telemetry files...\n");

            try
            {
                var analyzer = new DiagnosticDataAnalyser();

                var result = await analyzer.AnalyzeDiagnosticDataAsync((progress, message) =>
                {
                    Console.CursorLeft = 0;
                    Console.Write(new string(' ', Console.WindowWidth - 1));
                    Console.CursorLeft = 0;
                    Console.Write(message);
                });

                Console.WriteLine("\n\n==========================================");
                Console.WriteLine("          SCAN COMPLETE");
                Console.WriteLine("==========================================\n");

                DisplayDiagnosticResults(result);

                Console.Write("\nSave detailed results to file? (y/n): ");
                if (Console.ReadLine()?.ToLower() == "y")
                {
                    string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                    string timestamp = DateTime.Now.ToString("dd-MM-yyyy_HH-mm-ss");
                    string filename = $"Telemetry-Scan-Results_{timestamp}.txt";
                    string fullPath = Path.Combine(desktopPath, filename);

                    SaveDiagnosticResultsToFile(result, fullPath);

                    Console.WriteLine($"\nResults saved to Desktop: {filename}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nError during diagnostic scan: {ex.Message}");
                Console.WriteLine("Please run as administrator for full access to diagnostic folders.");
            }

            Console.WriteLine("\n==========================================");
            Console.WriteLine("\nPress any key to return to menu...");
            Console.ReadKey();
            Console.Clear();
        }

        // Scans Windows services for telemetry components
        // Identifies which telemetry services are running, stopped, or disabled
        static async Task ScanTelemetryServicesAsync()
        {
            Console.Clear();
            Console.WriteLine("=== Windows Telemetry Services Scanner ===\n");
            Console.WriteLine("Scanning for telemetry-related Windows services...\n");

            try
            {
                var scanner = new TelemetryServicesScanner();

                var findings = await scanner.ScanTelemetryServicesAsync((progress, message) =>
                {
                    Console.CursorLeft = 0;
                    Console.Write(new string(' ', Console.WindowWidth - 1));
                    Console.CursorLeft = 0;
                    Console.Write(message);
                });

                Console.WriteLine("\n\n==========================================");
                Console.WriteLine("          SCAN COMPLETE");
                Console.WriteLine("==========================================\n");

                DisplayServiceResults(findings);

                Console.Write("\nSave service scan results to file? (y/n): ");
                if (Console.ReadLine()?.ToLower() == "y")
                {
                    string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                    string timestamp = DateTime.Now.ToString("dd-MM-yyyy_HH-mm-ss");
                    string filename = $"Telemetry-Services-Scan_{timestamp}.txt";
                    string fullPath = Path.Combine(desktopPath, filename);

                    SaveServiceResultsToFile(findings, fullPath);

                    Console.WriteLine($"\nResults saved to Desktop: {filename}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nError during service scan: {ex.Message}");
            }

            Console.WriteLine("\n==========================================");
            Console.WriteLine("\nPress any key to return to menu...");
            Console.ReadKey();
            Console.Clear();
        }

        // Runs all three scans and calculates unified exposure score
        // Combines registry settings, service status, and diagnostic data into comprehensive analysis
        static async Task RunCompleteExposureAnalysisAsync()
        {
            Console.Clear();
            Console.WriteLine("=== Complete Telemetry Exposure Analysis ===\n");
            Console.WriteLine("Running comprehensive scan (Registry + Services + Diagnostic Data)...\n");

            try
            {
                Console.WriteLine("[1/3] Scanning Windows Registry...");
                var registryScanner = new TelemetryRegistryScanner();
                var registryFindings = await registryScanner.ScanTelemetryKeysAsync(null);
                Console.WriteLine($"      Registry scan complete: {registryFindings.Count} entries found\n");

                Console.WriteLine("[2/3] Scanning Windows Services...");
                var servicesScanner = new TelemetryServicesScanner();
                var serviceFindings = await servicesScanner.ScanTelemetryServicesAsync(null);
                Console.WriteLine($"      Services scan complete: {serviceFindings.Count(s => s.IsRunning)} running services found\n");

                Console.WriteLine("[3/3] Scanning Diagnostic Data Files...");
                var diagnosticAnalyzer = new DiagnosticDataAnalyser();
                var diagnosticResults = await diagnosticAnalyzer.AnalyzeDiagnosticDataAsync((progress, message) =>
                {
                    Console.CursorLeft = 0;
                    Console.Write(new string(' ', Console.WindowWidth - 1));
                    Console.CursorLeft = 0;
                    Console.Write($"      {message}");
                });
                Console.WriteLine($"\n Diagnostic scan complete: {diagnosticResults.TotalFilesFound} files analyzed\n");

                Console.WriteLine("Calculating exposure score...\n");
                var calculator = new ExposureScoreCalculator();
                var exposureScore = calculator.CalculateExposureScore(
                    registryFindings,
                    serviceFindings,
                    diagnosticResults
                );

                Console.WriteLine("==========================================");
                Console.WriteLine("          EXPOSURE ANALYSIS COMPLETE");
                Console.WriteLine("==========================================\n");

                DisplayExposureScoreResults(exposureScore, registryFindings, serviceFindings, diagnosticResults);

                Console.Write("\nSave complete analysis to file? (y/n): ");
                if (Console.ReadLine()?.ToLower() == "y")
                {
                    string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                    string timestamp = DateTime.Now.ToString("dd-MM-yyyy_HH-mm-ss");
                    string filename = $"Complete-Exposure-Analysis_{timestamp}.txt";
                    string fullPath = Path.Combine(desktopPath, filename);

                    SaveCompleteAnalysisToFile(exposureScore, registryFindings, serviceFindings, diagnosticResults, fullPath);
                    Console.WriteLine($"\nComplete analysis saved to Desktop: {filename}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nError during analysis: {ex.Message}");
            }

            Console.WriteLine("\n==========================================");
            Console.WriteLine("\nPress any key to return to menu...");
            Console.ReadKey();
            Console.Clear();
        }

        // Displays diagnostic data scan results
        // Shows folder summary, file analysis, and PII detection results
        static void DisplayDiagnosticResults(DiagnosticAnalysisResult result)
        {
            Console.WriteLine($"Scan completed at: {result.AnalysisTime:yyyy-MM-dd HH:mm:ss}");
            Console.WriteLine($"Machine: {result.MachineName}");
            Console.WriteLine($"User: {result.Username}\n");

            Console.WriteLine("=== FOLDER SUMMARY ===");
            var accessibleFolders = result.DiagnosticFolders.Where(f => f.Exists && f.IsAccessible).ToList();
            var inaccessibleFolders = result.DiagnosticFolders.Where(f => f.Exists && !f.IsAccessible).ToList();

            Console.WriteLine($"Folders scanned: {accessibleFolders.Count}");
            Console.WriteLine($"Folders denied access: {inaccessibleFolders.Count}\n");

            Console.WriteLine("=== FILE ANALYSIS ===");
            Console.WriteLine($"Total files found: {result.TotalFilesFound}");
            Console.WriteLine($"Total data size: {FormatBytes(result.TotalDataSizeBytes)}\n");

            Console.WriteLine("=== PII DETECTION RESULTS ===");
            if (result.PiiDetections.Any())
            {
                Console.WriteLine($"Found PII in {result.PiiDetections.Count} file instances\n");

                var grouped = result.PiiDetections
                    .GroupBy(p => p.PiiType)
                    .OrderByDescending(g => g.Count());

                foreach (var group in grouped)
                {
                    Console.WriteLine($"{group.Key}: {group.Count()} instances");
                }
            }
            else
            {
                Console.WriteLine("No PII detected in scanned files.");
            }

            Console.WriteLine("\nNote: For comprehensive privacy exposure assessment, use option 4 (Complete Exposure Analysis)");
        }

        // Displays telemetry service scan results
        // Shows which services are found, running, and their startup configuration
        static void DisplayServiceResults(List<ServiceFinding> findings)
        {
            Console.WriteLine($"Total services scanned: {findings.Count}");
            Console.WriteLine($"Services found on system: {findings.Count(f => f.Found)}");
            Console.WriteLine($"Services currently running: {findings.Count(f => f.IsRunning)}\n");

            Console.WriteLine("=== SERVICE DETAILS ===\n");

            foreach (var service in findings.Where(f => f.Found))
            {
                Console.WriteLine($"Service: {service.DisplayName}");
                Console.WriteLine($"  Name: {service.ServiceName}");
                Console.WriteLine($"  Description: {service.Description}");
                Console.WriteLine($"  Status: {service.Status}");
                Console.WriteLine($"  Startup Type: {service.StartType}");
                Console.WriteLine($"  Running: {(service.IsRunning ? "YES" : "NO")}");
                Console.WriteLine();
            }

            var notFound = findings.Where(f => !f.Found).ToList();
            if (notFound.Any())
            {
                Console.WriteLine("=== SERVICES NOT FOUND ON THIS SYSTEM ===\n");
                foreach (var service in notFound)
                {
                    Console.WriteLine($"- {service.DisplayName} ({service.ServiceName})");
                }
                Console.WriteLine();
            }
        }

        // Displays complete exposure score results, all scans
        // Shows total score, component breakdown, and interpretation
        static void DisplayExposureScoreResults(
            ExposureScoreCalculator.ExposureScoreResult exposureScore,
            List<RegistryFinding> registryFindings,
            List<ServiceFinding> serviceFindings,
            DiagnosticAnalysisResult diagnosticResults)
        {
            Console.WriteLine("=== EXPOSURE SCORE ===");
            Console.WriteLine($"Total Exposure Score: {exposureScore.TotalExposureScore}/100");
            Console.WriteLine($"Exposure Level: {exposureScore.ExposureLevel}\n");

            Console.WriteLine("=== SCORE BREAKDOWN ===");
            foreach (var line in exposureScore.GetScoreBreakdown())
            {
                Console.WriteLine($"  {line}");
            }

            Console.WriteLine("\n=== COMPONENT SUMMARIES ===\n");

            Console.WriteLine($"Registry Configuration ({exposureScore.RegistryContribution}/30 points):");
            var allowTelemetry = registryFindings.FirstOrDefault(f => f.KeyName == "AllowTelemetry");
            if (allowTelemetry != null)
            {
                string level = allowTelemetry.Value switch
                {
                    "0" => "Security Only (Disabled)",
                    "1" => "Basic",
                    "2" => "Enhanced",
                    "3" => "Full",
                    _ => "Unknown"
                };
                Console.WriteLine($"  AllowTelemetry: {level}");
            }
            else
            {
                Console.WriteLine($"  AllowTelemetry: Not configured");
            }

            var ceip = registryFindings.FirstOrDefault(f => f.KeyName == "CEIPEnable");
            if (ceip != null)
            {
                Console.WriteLine($"  CEIP: {(ceip.Value == "1" ? "Enabled" : "Disabled")}");
            }

            Console.WriteLine($"\nActive Services ({exposureScore.ServicesContribution}/30 points):");
            var runningServices = serviceFindings.Where(s => s.IsRunning).ToList();
            Console.WriteLine($"  Running telemetry services: {runningServices.Count}");

            var diagTrack = runningServices.FirstOrDefault(s => s.ServiceName == "DiagTrack");
            if (diagTrack != null)
            {
                Console.WriteLine($"  DiagTrack (Main telemetry): Running");
            }

            Console.WriteLine($"\nDiagnostic Data ({exposureScore.DiagnosticDataContribution}/40 points):");
            Console.WriteLine($"  Total files: {diagnosticResults.TotalFilesFound}");
            Console.WriteLine($"  Total size: {FormatBytes(diagnosticResults.TotalDataSizeBytes)}");
            Console.WriteLine($"  PII instances found: {diagnosticResults.PiiDetections.Count}");

            Console.WriteLine("\n=== INTERPRETATION ===");
            DisplayExposureInterpretation(exposureScore.TotalExposureScore);
        }

        // Provides interpretation of exposure score
        // Explains what the score means in terms of telemetry activity and privacy exposure
        static void DisplayExposureInterpretation(int score)
        {
            if (score >= 70)
            {
                Console.WriteLine("HIGH EXPOSURE: Your system has active telemetry collection enabled with");
                Console.WriteLine("significant accumulated data. Windows is actively collecting and storing");
                Console.WriteLine("diagnostic information that may include personal data.");
            }
            else if (score >= 40)
            {
                Console.WriteLine("MEDIUM EXPOSURE: Your system has moderate telemetry activity. Some");
                Console.WriteLine("telemetry services are running and diagnostic data is being collected,");
                Console.WriteLine("though not at maximum levels.");
            }
            else if (score >= 15)
            {
                Console.WriteLine("LOW EXPOSURE: Your system has limited telemetry activity. Either");
                Console.WriteLine("telemetry is partially disabled or only historical data remains");
                Console.WriteLine("without active collection services running.");
            }
            else
            {
                Console.WriteLine("MINIMAL EXPOSURE: Your system has very limited telemetry exposure.");
                Console.WriteLine("Most telemetry services appear to be disabled with minimal data");
                Console.WriteLine("collection activity.");
            }
        }

        // Formats bytes into human-readable format
        // Converts byte values to KB, MB, GB, or TB as appropriate
        static string FormatBytes(long bytes)
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

            return $"{size:0.##} {suffixes[suffixIndex]}";
        }

        // Saves diagnostic data scan results to file
        // Includes folder details, file breakdown, PII detections, and scan log
        static void SaveDiagnosticResultsToFile(DiagnosticAnalysisResult result, string filename)
        {
            try
            {
                using (var writer = new StreamWriter(filename))
                {
                    writer.WriteLine("=================================================");
                    writer.WriteLine("   WINDOWS TELEMETRY DIAGNOSTIC DATA SCAN");
                    writer.WriteLine("=================================================");
                    writer.WriteLine();
                    writer.WriteLine($"Scan Time: {result.AnalysisTime:yyyy-MM-dd HH:mm:ss}");
                    writer.WriteLine($"Machine: {result.MachineName}");
                    writer.WriteLine($"User: {result.Username}");
                    writer.WriteLine();

                    writer.WriteLine("=== SUMMARY ===");
                    writer.WriteLine($"Folders scanned: {result.DiagnosticFolders.Count(f => f.Exists && f.IsAccessible)}");
                    writer.WriteLine($"Files analyzed: {result.TotalFilesFound}");
                    writer.WriteLine($"Total data volume: {FormatBytes(result.TotalDataSizeBytes)}");
                    writer.WriteLine($"PII detections: {result.PiiDetections.Count} instances");
                    writer.WriteLine();

                    writer.WriteLine("=== FOLDER DETAILS ===");

                    var accessibleFolders = result.DiagnosticFolders.Where(f => f.Exists && f.IsAccessible).ToList();
                    writer.WriteLine($"\nAccessible Folders ({accessibleFolders.Count}):");
                    foreach (var folder in accessibleFolders)
                    {
                        writer.WriteLine($"\n{folder.Path}");
                        writer.WriteLine($"  Type: {folder.Type}");
                        writer.WriteLine($"  Description: {folder.Description}");
                        writer.WriteLine($"  Files: {folder.FileCount}");
                        writer.WriteLine($"  Size: {FormatBytes(folder.TotalSizeBytes)}");
                        writer.WriteLine($"  Last Modified: {folder.LastModified:yyyy-MM-dd HH:mm:ss}");
                    }

                    var inaccessibleFolders = result.DiagnosticFolders.Where(f => f.Exists && !f.IsAccessible).ToList();
                    if (inaccessibleFolders.Any())
                    {
                        writer.WriteLine($"\nInaccessible Folders ({inaccessibleFolders.Count}):");
                        foreach (var folder in inaccessibleFolders)
                        {
                            writer.WriteLine($"\n{folder.Path}");
                            writer.WriteLine($"  Type: {folder.Type}");
                            writer.WriteLine($"  Error: {folder.AccessError}");
                        }
                    }

                    writer.WriteLine("\n\n=== FILE TYPE BREAKDOWN ===");
                    foreach (var fileType in result.FilesByType.OrderByDescending(f => f.TotalSizeBytes))
                    {
                        writer.WriteLine($"{fileType.Extension}: {fileType.Count} files, {FormatBytes(fileType.TotalSizeBytes)}");
                    }

                    writer.WriteLine("\n\n=== PII DETECTIONS ===");
                    if (result.PiiDetections.Any())
                    {
                        var grouped = result.PiiDetections.GroupBy(p => p.PiiType);

                        foreach (var group in grouped)
                        {
                            writer.WriteLine($"\n{group.Key} ({group.Count()} instances):");
                            foreach (var detection in group)
                            {
                                writer.WriteLine($"\n  File: {Path.GetFileName(detection.FilePath)}");
                                writer.WriteLine($"  Full Path: {detection.FilePath}");
                                writer.WriteLine($"  Match Count: {detection.MatchCount}");
                                if (detection.SampleMatches.Any())
                                {
                                    writer.WriteLine($"  Samples: {string.Join(", ", detection.SampleMatches)}");
                                }
                            }
                        }
                    }
                    else
                    {
                        writer.WriteLine("No PII detected in scanned files.");
                    }

                    writer.WriteLine("\n\n=== DETAILED SCAN LOG ===");
                    writer.WriteLine($"Total log entries: {result.ScanLog.Count}\n");
                    foreach (var logEntry in result.ScanLog)
                    {
                        writer.WriteLine(logEntry);
                    }

                    writer.WriteLine("\n\n=================================================");
                    writer.WriteLine("              END OF REPORT");
                    writer.WriteLine("=================================================");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nError saving file: {ex.Message}");
            }
        }

        // Saves service scan results to file
        // Includes service details, status, and startup configuration
        static void SaveServiceResultsToFile(List<ServiceFinding> findings, string filename)
        {
            try
            {
                using (var writer = new StreamWriter(filename))
                {
                    writer.WriteLine("=================================================");
                    writer.WriteLine("   WINDOWS TELEMETRY SERVICES SCAN REPORT");
                    writer.WriteLine("=================================================");
                    writer.WriteLine();
                    writer.WriteLine($"Scan Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                    writer.WriteLine($"Machine: {Environment.MachineName}");
                    writer.WriteLine($"User: {Environment.UserName}");
                    writer.WriteLine();

                    writer.WriteLine("=== SUMMARY ===");
                    writer.WriteLine($"Total services scanned: {findings.Count}");
                    writer.WriteLine($"Services found on system: {findings.Count(f => f.Found)}");
                    writer.WriteLine($"Services currently running: {findings.Count(f => f.IsRunning)}");
                    writer.WriteLine();

                    writer.WriteLine("=== SERVICE DETAILS ===");
                    writer.WriteLine();

                    foreach (var service in findings.Where(f => f.Found))
                    {
                        writer.WriteLine($"Service: {service.DisplayName}");
                        writer.WriteLine($"  Name: {service.ServiceName}");
                        writer.WriteLine($"  Description: {service.Description}");
                        writer.WriteLine($"  Status: {service.Status}");
                        writer.WriteLine($"  Startup Type: {service.StartType}");
                        writer.WriteLine($"  Running: {(service.IsRunning ? "YES" : "NO")}");

                        if (!string.IsNullOrEmpty(service.Error))
                        {
                            writer.WriteLine($"  Error: {service.Error}");
                        }

                        writer.WriteLine();
                    }

                    var notFound = findings.Where(f => !f.Found).ToList();
                    if (notFound.Any())
                    {
                        writer.WriteLine("=== SERVICES NOT FOUND ON THIS SYSTEM ===");
                        writer.WriteLine();
                        foreach (var service in notFound)
                        {
                            writer.WriteLine($"- {service.DisplayName} ({service.ServiceName})");
                        }
                    }

                    writer.WriteLine();
                    writer.WriteLine("=================================================");
                    writer.WriteLine("              END OF REPORT");
                    writer.WriteLine("=================================================");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nError saving file: {ex.Message}");
            }
        }

        // Saves complete exposure analysis to file
        // Includes exposure score, all component results, and detailed breakdowns
        static void SaveCompleteAnalysisToFile(
            ExposureScoreCalculator.ExposureScoreResult exposureScore,
            List<RegistryFinding> registryFindings,
            List<ServiceFinding> serviceFindings,
            DiagnosticAnalysisResult diagnosticResults,
            string filename)
        {
            try
            {
                using (var writer = new StreamWriter(filename))
                {
                    writer.WriteLine("=================================================");
                    writer.WriteLine("   COMPLETE TELEMETRY EXPOSURE ANALYSIS");
                    writer.WriteLine("=================================================");
                    writer.WriteLine();
                    writer.WriteLine($"Analysis Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                    writer.WriteLine($"Machine: {Environment.MachineName}");
                    writer.WriteLine($"User: {Environment.UserName}");
                    writer.WriteLine();

                    writer.WriteLine("=== EXPOSURE SCORE ===");
                    writer.WriteLine($"Total Exposure Score: {exposureScore.TotalExposureScore}/100");
                    writer.WriteLine($"Exposure Level: {exposureScore.ExposureLevel}");
                    writer.WriteLine();

                    writer.WriteLine("=== SCORE BREAKDOWN ===");
                    foreach (var line in exposureScore.GetScoreBreakdown())
                    {
                        writer.WriteLine($"  {line}");
                    }
                    writer.WriteLine();

                    writer.WriteLine("=== REGISTRY FINDINGS ===");
                    writer.WriteLine($"Contribution to score: {exposureScore.RegistryContribution}/30 points");
                    writer.WriteLine();
                    foreach (var finding in registryFindings)
                    {
                        writer.WriteLine($"{finding.KeyName}: {finding.Value}");
                        writer.WriteLine($"  Path: {finding.Path}");
                    }
                    writer.WriteLine();

                    writer.WriteLine("=== SERVICE FINDINGS ===");
                    writer.WriteLine($"Contribution to score: {exposureScore.ServicesContribution}/30 points");
                    writer.WriteLine();
                    foreach (var service in serviceFindings.Where(s => s.Found))
                    {
                        writer.WriteLine($"{service.DisplayName}");
                        writer.WriteLine($"  Status: {service.Status}");
                        writer.WriteLine($"  Startup: {service.StartType}");
                        writer.WriteLine($"  Running: {(service.IsRunning ? "YES" : "NO")}");
                        writer.WriteLine();
                    }

                    writer.WriteLine("=== DIAGNOSTIC DATA FINDINGS ===");
                    writer.WriteLine($"Contribution to score: {exposureScore.DiagnosticDataContribution}/40 points");
                    writer.WriteLine();
                    writer.WriteLine($"Total files: {diagnosticResults.TotalFilesFound}");
                    writer.WriteLine($"Total size: {FormatBytes(diagnosticResults.TotalDataSizeBytes)}");
                    writer.WriteLine($"PII instances: {diagnosticResults.PiiDetections.Count}");
                    writer.WriteLine();

                    if (diagnosticResults.PiiDetections.Any())
                    {
                        writer.WriteLine("PII Detections:");
                        foreach (var pii in diagnosticResults.PiiDetections.GroupBy(p => p.PiiType))
                        {
                            writer.WriteLine($"  {pii.Key}: {pii.Count()} instances");
                        }
                    }

                    writer.WriteLine();
                    writer.WriteLine("=================================================");
                    writer.WriteLine("              END OF ANALYSIS");
                    writer.WriteLine("=================================================");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nError saving file: {ex.Message}");
            }
        }
    }
}