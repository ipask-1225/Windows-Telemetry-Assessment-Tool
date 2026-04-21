using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace TelemetryAssessmentTool.Services
{
    public class TelemetryRegistryScanner
    {

        public async Task<List<RegistryFinding>> ScanTelemetryKeysAsync(Action<int, int> value)
        {
            return await Task.Run(() =>
            {
                var findings = new List<RegistryFinding>();

                Console.WriteLine("[Scanner] Starting registry scan...");

                // 1. Scan for AllowTelemetry
                ScanAllowTelemetry(findings);

                // 2. Scan for CEIPEnable
                ScanCEIPEnable(findings);

                Console.WriteLine($"[Scanner] Scan complete. Found {findings.Count} entries.");
                return findings;
            });
        }

        private void ScanAllowTelemetry(List<RegistryFinding> findings)
        {
            // Common locations for AllowTelemetry
            string[] allowTelemetryPaths = {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
                @"SOFTWARE\Policies\Microsoft\Windows\DataCollection"
            };

            foreach (var path in allowTelemetryPaths)
            {
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(path))
                    {
                        if (key != null)
                        {
                            var value = key.GetValue("AllowTelemetry");
                            findings.Add(new RegistryFinding
                            {
                                KeyName = "AllowTelemetry",
                                Path = $"HKLM\\{path}",
                                Value = value?.ToString() ?? "(not set)"
                            });

                            Console.WriteLine($"[Scanner] Found AllowTelemetry at: {path}");
                        }
                        else
                        {
                            Console.WriteLine($"[Scanner] Key not found: {path}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Scanner] Error scanning {path}: {ex.Message}");
                }
            }
        }

        private void ScanCEIPEnable(List<RegistryFinding> findings)
        {
            // Common locations for CEIPEnable
            string[] ceipPaths = {
                @"SOFTWARE\Microsoft\SQMClient\Windows",
                @"SOFTWARE\Policies\Microsoft\SQMClient\Windows"
            };

            foreach (var path in ceipPaths)
            {
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(path))
                    {
                        if (key != null)
                        {
                            var value = key.GetValue("CEIPEnable");
                            findings.Add(new RegistryFinding
                            {
                                KeyName = "CEIPEnable",
                                Path = $"HKLM\\{path}",
                                Value = value?.ToString() ?? "(not set)"
                            });

                            Console.WriteLine($"[Scanner] Found CEIPEnable at: {path}");
                        }
                        else
                        {
                            Console.WriteLine($"[Scanner] Key not found: {path}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Scanner] Error scanning {path}: {ex.Message}");
                }
            }
        }

        // Simple model for the findings
        public class RegistryFinding
        {
            public string KeyName { get; set; }
            public string Path { get; set; }
            public string Value { get; set; }
        }
    }
}
