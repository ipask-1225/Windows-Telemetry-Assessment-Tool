using System;
using System.Collections.Generic;
using System.Linq;
using static TelemetryAssessmentTool.DiagnosticDataAnalyser;
using static TelemetryAssessmentTool.Services.TelemetryRegistryScanner;
using static TelemetryAssessmentTool.Services.TelemetryServicesScanner;

namespace TelemetryAssessmentTool
{
    // Calculates exposure score based on registry settings, active services, and diagnostic data
    // Score ranges from 0-100 representing overall telemetry privacy exposure
    public class ExposureScoreCalculator
    {
        // Calculates comprehensive exposure score from all scanner results
        public ExposureScoreResult CalculateExposureScore(
            List<RegistryFinding> registryFindings,
            List<ServiceFinding> serviceFindings,
            DiagnosticAnalysisResult diagnosticResults)
        {
            var result = new ExposureScoreResult
            {
                CalculatedAt = DateTime.UtcNow
            };

            // Component 1: Registry Configuration Score (0-30 points)
            result.RegistryScore = CalculateRegistryScore(registryFindings);
            result.RegistryContribution = result.RegistryScore;

            // Component 2: Active Services Score (0-30 points)
            result.ServicesScore = CalculateServicesScore(serviceFindings);
            result.ServicesContribution = result.ServicesScore;

            // Component 3: Diagnostic Data Score (0-40 points) as its the largest scan
            result.DiagnosticDataScore = CalculateDiagnosticDataScore(diagnosticResults);
            result.DiagnosticDataContribution = result.DiagnosticDataScore;

            // Calculate total exposure score (capped at 100) for simplicity
            int totalScore = result.RegistryContribution + result.ServicesContribution + result.DiagnosticDataContribution;
            result.TotalExposureScore = Math.Min(100, totalScore);

            // Determine exposure level
            result.ExposureLevel = result.TotalExposureScore switch
            {
                >= 70 => "High",
                >= 40 => "Medium",
                >= 15 => "Low",
                _ => "Minimal"
            };

            return result;
        }

        // Component 1: Registry Configuration Score (0-30 points)
        // Active telemetry settings indicate current exposure configuration
        private int CalculateRegistryScore(List<RegistryFinding> findings)
        {
            int score = 0;
            var explanation = new List<string>();

            if (findings == null || !findings.Any())
            {
                return 0;
            }

            // Check AllowTelemetry settings
            var allowTelemetryFindings = findings.Where(f => f.KeyName == "AllowTelemetry");
            foreach (var finding in allowTelemetryFindings)
            {
                if (int.TryParse(finding.Value, out int telemetryLevel))
                {
                    // AllowTelemetry levels:
                    // 0 = Security (disabled) → 0 points
                    // 1 = Basic → 10 points
                    // 2 = Enhanced → 20 points
                    // 3 = Full → 30 points
                    int levelScore = telemetryLevel switch
                    {
                        3 => 30,  // Full telemetry - maximum exposure
                        2 => 20,  // Enhanced telemetry
                        1 => 10,  // Basic telemetry
                        0 => 0,   // Security only - no telemetry
                        _ => 0
                    };

                    if (levelScore > score)
                    {
                        score = levelScore;
                    }
                }
            }

            // Check CEIP (Customer Experience Improvement Program)
            var ceipFindings = findings.Where(f => f.KeyName == "CEIPEnable");
            foreach (var finding in ceipFindings)
            {
                if (finding.Value == "1")
                {
                    // CEIP enabled adds 5 points (less severe than main telemetry)
                    score += 5;
                }
            }

            // Cap registry contribution at 30
            return Math.Min(30, score);
        }

        // Component 2: Active Services Score (0-30 points)
        // Running telemetry services indicate active data collection
        private int CalculateServicesScore(List<ServiceFinding> findings)
        {
            int score = 0;

            if (findings == null || !findings.Any())
            {
                return 0;
            }

            // Service weights based on telemetry significance
            var serviceWeights = new Dictionary<string, int>
            {
                // Critical telemetry services
                { "DiagTrack", 15 },                    // Main telemetry service - highest weight
                
                // High-impact services
                { "dmwappushservice", 5 },              // Push notifications for telemetry
                { "WerSvc", 3 },                        // Error reporting
                { "InventoryCollectorSvc", 3 },         // Inventory collection
                
                // Medium-impact services
                { "CDPUserSvc", 2 },                    // Connected devices
                { "OneSyncSvc", 2 },                    // Sync services
                { "PcaSvc", 2 },                        // Compatibility assistant
                
                // Lower-impact services
                { "DPS", 1 },                           // Diagnostic policy
                { "WdiServiceHost", 1 },                // Diagnostic host
                { "WdiSystemHost", 1 },                 // Diagnostic system
                { "DoSvc", 1 },                         // Delivery optimization
                { "wuauserv", 1 }                       // Windows Update
            };

            foreach (var service in findings.Where(f => f.Found && f.IsRunning))
            {
                if (serviceWeights.TryGetValue(service.ServiceName, out int weight))
                {
                    score += weight;
                }
            }

            // Cap services contribution at 30
            return Math.Min(30, score);
        }

        // Component 3: Diagnostic Data Score (0-40 points)
        // Existing telemetry data indicates historical and current exposure
        // Combines data volume and PII detection with different weights
        private int CalculateDiagnosticDataScore(DiagnosticAnalysisResult diagnosticResults)
        {
            int score = 0;

            if (diagnosticResults == null)
            {
                return 0;
            }

            // Sub-component A: Data Volume (0-15 points)
            // Reduced from original 40 to fit new unified scoring
            double totalMB = diagnosticResults.TotalDataSizeBytes / (1024.0 * 1024.0);

            if (totalMB > 500)
            {
                score += 15;  // Very large volume
            }
            else if (totalMB > 100)
            {
                score += 10;  // Large volume
            }
            else if (totalMB > 50)
            {
                score += 5;   // Moderate volume
            }

            // Sub-component B: PII Detection (0-20 points)
            // Weighted by PII sensitivity
            int piiScore = 0;

            foreach (var detection in diagnosticResults.PiiDetections)
            {
                if (detection.PiiType.Contains("Email"))
                {
                    piiScore += detection.PiiType.Contains("ETL") ? 8 : 5;
                }
                else if (detection.PiiType.Contains("Username"))
                {
                    piiScore += 4;
                }
                else if (detection.PiiType.Contains("IP Address"))
                {
                    piiScore += 2;
                }
                else if (detection.PiiType.Contains("File Path"))
                {
                    piiScore += 1;
                }
                else
                {
                    piiScore += 3;
                }
            }

            score += Math.Min(20, piiScore);  // Cap PII contribution at 20

            // Sub-component C: ETL File Count (0-5 points)
            // Active telemetry logs
            var etlCount = diagnosticResults.FoundFiles.Count(f =>
                f.Extension.Equals(".etl", StringComparison.OrdinalIgnoreCase));

            if (etlCount > 50)
            {
                score += 5;
            }
            else if (etlCount > 20)
            {
                score += 3;
            }

            // Cap diagnostic data contribution at 40
            return Math.Min(40, score);
        }

        // Result model for exposure score calculation
        public class ExposureScoreResult
        {
            public DateTime CalculatedAt { get; set; }

            // Component scores (before weighting)
            public int RegistryScore { get; set; }
            public int ServicesScore { get; set; }
            public int DiagnosticDataScore { get; set; }

            // Weighted contributions to total score
            public int RegistryContribution { get; set; }
            public int ServicesContribution { get; set; }
            public int DiagnosticDataContribution { get; set; }

            // Final results
            public int TotalExposureScore { get; set; }
            public string ExposureLevel { get; set; }

            // Generates detailed breakdown of score calculation
            public List<string> GetScoreBreakdown()
            {
                var breakdown = new List<string>();

                breakdown.Add($"Registry Configuration: {RegistryContribution}/30 points");
                breakdown.Add($"Active Services: {ServicesContribution}/30 points");
                breakdown.Add($"Diagnostic Data: {DiagnosticDataContribution}/40 points");
                breakdown.Add($"Total Exposure Score: {TotalExposureScore}/100");
                breakdown.Add($"Exposure Level: {ExposureLevel}");

                return breakdown;
            }
        }
    }
}