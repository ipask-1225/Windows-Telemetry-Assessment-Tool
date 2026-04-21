using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceProcess;
using System.Threading.Tasks;

namespace TelemetryAssessmentTool.Services
{
    /// <summary>
    /// Scans Windows services that are responsible for telemetry data collection
    /// Identifies which telemetry services are running, stopped, or disabled
    /// </summary>
    public class TelemetryServicesScanner
    {
        /// <summary>
        /// Main method to scan for telemetry-related Windows services
        /// </summary>
        public async Task<List<ServiceFinding>> ScanTelemetryServicesAsync(Action<int, string> progressCallback = null)
        {
            return await Task.Run(() =>
            {
                var findings = new List<ServiceFinding>();

                progressCallback?.Invoke(10, "Scanning Windows telemetry services...");

                // List of known Windows telemetry services
                var telemetryServices = GetTelemetryServiceNames();

                int currentService = 0;
                int totalServices = telemetryServices.Count;

                foreach (var serviceName in telemetryServices)
                {
                    currentService++;
                    int progress = 10 + (currentService * 80 / totalServices);
                    progressCallback?.Invoke(progress, $"Checking service: {serviceName.DisplayName}");

                    try
                    {
                        // Try to get the service
                        var service = ServiceController.GetServices()
                        .FirstOrDefault(s => s.ServiceName.Equals(serviceName.Name, StringComparison.OrdinalIgnoreCase));

                        if (service != null)
                        {
                            findings.Add(new ServiceFinding
                            {
                                ServiceName = service.ServiceName,
                                DisplayName = service.DisplayName,
                                Description = serviceName.Description,
                                Status = service.Status.ToString(),
                                StartType = GetServiceStartMode(service.ServiceName),
                                IsRunning = service.Status == ServiceControllerStatus.Running,
                                Found = true
                            });
                        }
                        else
                        {
                            // Service not found on this system
                            findings.Add(new ServiceFinding
                            {
                                ServiceName = serviceName.Name,
                                DisplayName = serviceName.DisplayName,
                                Description = serviceName.Description,
                                Status = "Not Found",
                                StartType = "N/A",
                                IsRunning = false,
                                Found = false
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        findings.Add(new ServiceFinding
                        {
                            ServiceName = serviceName.Name,
                            DisplayName = serviceName.DisplayName,
                            Description = serviceName.Description,
                            Status = $"Error: {ex.Message}",
                            StartType = "Unknown",
                            IsRunning = false,
                            Found = false,
                            Error = ex.Message
                        });
                    }
                }

                progressCallback?.Invoke(100, "Service scan complete");
                return findings;
            });
        }

        /// <summary>
        /// Returns list of known Windows telemetry services
        /// Based on documented Windows diagnostic and telemetry components
        /// </summary>
        private List<TelemetryServiceInfo> GetTelemetryServiceNames()
        {
            return new List<TelemetryServiceInfo>
            {
                // Primary telemetry service
                new TelemetryServiceInfo
                {
                    Name = "DiagTrack",
                    DisplayName = "Connected User Experiences and Telemetry",
                    Description = "Main Windows telemetry service - collects and sends diagnostic data to Microsoft"
                },
                
                // Device management and push notifications
                new TelemetryServiceInfo
                {
                    Name = "dmwappushservice",
                    DisplayName = "Device Management Wireless Application Protocol",
                    Description = "Routes push messages for telemetry and device management"
                },
                
                // Windows Error Reporting
                new TelemetryServiceInfo
                {
                    Name = "WerSvc",
                    DisplayName = "Windows Error Reporting Service",
                    Description = "Collects and sends error reports to Microsoft"
                },
                
                // Diagnostic services
                new TelemetryServiceInfo
                {
                    Name = "DPS",
                    DisplayName = "Diagnostic Policy Service",
                    Description = "Enables problem detection, troubleshooting and resolution for Windows components"
                },
                new TelemetryServiceInfo
                {
                    Name = "WdiServiceHost",
                    DisplayName = "Diagnostic Service Host",
                    Description = "Hosts diagnostic infrastructure for Windows components"
                },
                new TelemetryServiceInfo
                {
                    Name = "WdiSystemHost",
                    DisplayName = "Diagnostic System Host",
                    Description = "Hosts diagnostic modules for system health"
                },
                
                // Compatibility and feedback
                new TelemetryServiceInfo
                {
                    Name = "PcaSvc",
                    DisplayName = "Program Compatibility Assistant Service",
                    Description = "Monitors program installations and sends compatibility data"
                },
                
                // Connected devices and data sync
                new TelemetryServiceInfo
                {
                    Name = "CDPUserSvc",
                    DisplayName = "Connected Devices Platform User Service",
                    Description = "Manages connected devices and sends activity data"
                },
                new TelemetryServiceInfo
                {
                    Name = "OneSyncSvc",
                    DisplayName = "Sync Host Service",
                    Description = "Synchronizes mail, contacts, calendar and other data"
                },
                
                // Inventory and compatibility
                new TelemetryServiceInfo
                {
                    Name = "InventoryCollectorSvc",
                    DisplayName = "Inventory Collector Service",
                    Description = "Collects software and hardware inventory data"
                },
                
                // Updates and delivery optimization
                new TelemetryServiceInfo
                {
                    Name = "wuauserv",
                    DisplayName = "Windows Update",
                    Description = "Downloads and installs updates - sends diagnostic data"
                },
                new TelemetryServiceInfo
                {
                    Name = "DoSvc",
                    DisplayName = "Delivery Optimization",
                    Description = "Optimizes bandwidth for updates - sends usage statistics"
                }
            };
        }

        /// <summary>
        /// Gets the startup type of a Windows service using WMI
        /// </summary>
        private string GetServiceStartMode(string serviceName)
        {
            try
            {
                var searcher = new System.Management.ManagementObjectSearcher(
                    $"SELECT StartMode FROM Win32_Service WHERE Name = '{serviceName}'");

                var results = searcher.Get();
                foreach (System.Management.ManagementObject result in results)
                {
                    return result["StartMode"]?.ToString() ?? "Unknown";
                }
            }
            catch
            {
                return "Unknown";
            }

            return "Unknown";
        }

        // ==================== DATA MODELS ====================

        /// <summary>
        /// Information about a telemetry service
        /// </summary>
        public class TelemetryServiceInfo
        {
            public string Name { get; set; }
            public string DisplayName { get; set; }
            public string Description { get; set; }
        }

        /// <summary>
        /// Result of scanning for a telemetry service
        /// </summary>
        public class ServiceFinding
        {
            public string ServiceName { get; set; }
            public string DisplayName { get; set; }
            public string Description { get; set; }
            public string Status { get; set; }
            public string StartType { get; set; }
            public bool IsRunning { get; set; }
            public bool Found { get; set; }
            public string Error { get; set; }
        }
    }
}