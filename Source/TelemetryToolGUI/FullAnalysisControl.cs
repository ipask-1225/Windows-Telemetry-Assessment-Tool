using System;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace TelemetryAssessmentTool.GUI
{
    public class FullAnalysisControl : UserControl
    {
        private Button btnRunScan;
        private Button btnExportReport;
        private ProgressBar scanProgressBar;
        private Label lblProgressMessage;
        private Panel scorePanel;
        private Label lblExposureScore;
        private Label lblExposureLevel;
        private ProgressBar scoreProgressBar;
        private TextBox txtResults;
        private Panel breakdownPanel;
        private Label lblRegistryScore;
        private Label lblServicesScore;
        private Label lblDataScore;

        private TelemetryAssessmentTool.ExposureScoreCalculator.ExposureScoreResult currentExposureScore;
        private System.Collections.Generic.List<TelemetryAssessmentTool.Services.TelemetryRegistryScanner.RegistryFinding> currentRegistryFindings;
        private System.Collections.Generic.List<TelemetryAssessmentTool.Services.TelemetryServicesScanner.ServiceFinding> currentServiceFindings;
        private TelemetryAssessmentTool.DiagnosticDataAnalyser.DiagnosticAnalysisResult currentDiagnosticResults;

        public FullAnalysisControl()
        {
            SetupControls();
        }

        private void SetupControls()
        {
            this.SuspendLayout();

            this.BackColor = Color.White;
            this.AutoScroll = true;
            this.Size = new Size(980, 700);

            Label lblTitle = new Label
            {
                Location = new Point(20, 20),
                Size = new Size(500, 30),
                Text = "Complete Exposure Analysis",
                Font = new Font("Segoe UI", 14F, FontStyle.Bold)
            };

            scorePanel = new Panel
            {
                Location = new Point(20, 60),
                Size = new Size(940, 130),
                BorderStyle = BorderStyle.FixedSingle,
                BackColor = Color.FromArgb(245, 245, 245)
            };

            Label lblScoreTitle = new Label
            {
                Location = new Point(15, 10),
                Size = new Size(200, 25),
                Text = "Exposure Score",
                Font = new Font("Segoe UI", 11F, FontStyle.Bold)
            };

            lblExposureScore = new Label
            {
                Location = new Point(15, 35),
                Size = new Size(150, 40),
                Text = "-- / 100",
                Font = new Font("Segoe UI", 20F, FontStyle.Bold),
                ForeColor = Color.DarkGray
            };

            lblExposureLevel = new Label
            {
                Location = new Point(170, 45),
                Size = new Size(150, 30),
                Text = "Not Analyzed",
                Font = new Font("Segoe UI", 12F),
                ForeColor = Color.Gray
            };

            scoreProgressBar = new ProgressBar
            {
                Location = new Point(15, 85),
                Size = new Size(910, 30),
                Style = ProgressBarStyle.Continuous,
                Maximum = 100,
                Value = 0
            };

            scorePanel.Controls.AddRange(new Control[] {
                lblScoreTitle, lblExposureScore, lblExposureLevel, scoreProgressBar
            });

            breakdownPanel = new Panel
            {
                Location = new Point(20, 200),
                Size = new Size(940, 90),
                BorderStyle = BorderStyle.FixedSingle,
                BackColor = Color.White
            };

            Label lblBreakdownTitle = new Label
            {
                Location = new Point(10, 10),
                Size = new Size(300, 20),
                Text = "Score Components:",
                Font = new Font("Segoe UI", 10F, FontStyle.Bold)
            };

            lblRegistryScore = new Label
            {
                Location = new Point(20, 35),
                Size = new Size(280, 20),
                Text = "Registry Configuration: -- / 30 points",
                Font = new Font("Segoe UI", 9F)
            };

            lblServicesScore = new Label
            {
                Location = new Point(20, 60),
                Size = new Size(280, 20),
                Text = "Active Services: -- / 30 points",
                Font = new Font("Segoe UI", 9F)
            };

            lblDataScore = new Label
            {
                Location = new Point(320, 35),
                Size = new Size(280, 20),
                Text = "Diagnostic Data: -- / 40 points",
                Font = new Font("Segoe UI", 9F)
            };

            breakdownPanel.Controls.AddRange(new Control[] {
                lblBreakdownTitle, lblRegistryScore, lblServicesScore, lblDataScore
            });

            txtResults = new TextBox
            {
                Location = new Point(20, 300),
                Size = new Size(940, 320),
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                ReadOnly = true,
                Font = new Font("Consolas", 9F),
                Text = "Run a complete analysis to see detailed results..."
            };

            scanProgressBar = new ProgressBar
            {
                Location = new Point(20, 630),
                Size = new Size(720, 25),
                Style = ProgressBarStyle.Continuous,
                Visible = false
            };

            lblProgressMessage = new Label
            {
                Location = new Point(20, 660),
                Size = new Size(720, 20),
                Text = "",
                Visible = false,
                Font = new Font("Segoe UI", 9F)
            };

            btnRunScan = new Button
            {
                Location = new Point(750, 630),
                Size = new Size(100, 30),
                Text = "Run Scan",
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                BackColor = Color.FromArgb(0, 120, 215),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand
            };
            btnRunScan.FlatAppearance.BorderSize = 0;
            btnRunScan.Click += BtnRunScan_Click;

            btnExportReport = new Button
            {
                Location = new Point(860, 630),
                Size = new Size(100, 30),
                Text = "Export",
                Font = new Font("Segoe UI", 9F),
                Enabled = false,
                Cursor = Cursors.Hand
            };
            btnExportReport.Click += BtnExportReport_Click;

            this.Controls.AddRange(new Control[] {
                lblTitle,
                scorePanel,
                breakdownPanel,
                txtResults,
                scanProgressBar,
                lblProgressMessage,
                btnRunScan,
                btnExportReport
            });

            this.ResumeLayout(false);
        }

        private async void BtnRunScan_Click(object sender, EventArgs e)
        {
            btnRunScan.Enabled = false;
            btnExportReport.Enabled = false;
            scanProgressBar.Visible = true;
            lblProgressMessage.Visible = true;
            txtResults.Clear();

            try
            {
                UpdateProgress(10, "Scanning Windows Registry...");
                var registryScanner = new TelemetryAssessmentTool.Services.TelemetryRegistryScanner();
                currentRegistryFindings = await registryScanner.ScanTelemetryKeysAsync(null);

                UpdateProgress(40, "Scanning Windows Services...");
                var servicesScanner = new TelemetryAssessmentTool.Services.TelemetryServicesScanner();
                currentServiceFindings = await servicesScanner.ScanTelemetryServicesAsync(null);

                UpdateProgress(60, "Scanning Diagnostic Data Files...");
                var diagnosticAnalyzer = new TelemetryAssessmentTool.DiagnosticDataAnalyser();
                currentDiagnosticResults = await diagnosticAnalyzer.AnalyzeDiagnosticDataAsync(
                    (progress, message) =>
                    {
                        UpdateProgress(60 + (progress * 30 / 100), message);
                    });

                UpdateProgress(95, "Calculating exposure score...");
                var calculator = new TelemetryAssessmentTool.ExposureScoreCalculator();
                currentExposureScore = calculator.CalculateExposureScore(
                    currentRegistryFindings,
                    currentServiceFindings,
                    currentDiagnosticResults);

                DisplayResults();
                UpdateProgress(100, "Analysis complete");
                btnExportReport.Enabled = true;

                MessageBox.Show("Complete analysis finished successfully!", "Analysis Complete",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error during scan: {ex.Message}", "Scan Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                btnRunScan.Enabled = true;
                scanProgressBar.Visible = false;
                lblProgressMessage.Visible = false;
            }
        }

        private void DisplayResults()
        {
            lblExposureScore.Text = $"{currentExposureScore.TotalExposureScore} / 100";
            lblExposureLevel.Text = currentExposureScore.ExposureLevel;
            scoreProgressBar.Value = currentExposureScore.TotalExposureScore;

            Color scoreColor;
            if (currentExposureScore.TotalExposureScore >= 70)
            {
                scoreColor = Color.FromArgb(192, 0, 0);
            }
            else if (currentExposureScore.TotalExposureScore >= 40)
            {
                scoreColor = Color.FromArgb(255, 140, 0);
            }
            else
            {
                scoreColor = Color.FromArgb(0, 128, 0);
            }
            lblExposureScore.ForeColor = scoreColor;
            lblExposureLevel.ForeColor = scoreColor;

            lblRegistryScore.Text = $"Registry Configuration: {currentExposureScore.RegistryContribution} / 30 points";
            lblServicesScore.Text = $"Active Services: {currentExposureScore.ServicesContribution} / 30 points";
            lblDataScore.Text = $"Diagnostic Data: {currentExposureScore.DiagnosticDataContribution} / 40 points";

            var results = new System.Text.StringBuilder();

            results.AppendLine("═══════════════════════════════════════════════════════════");
            results.AppendLine("              COMPLETE ANALYSIS RESULTS");
            results.AppendLine("═══════════════════════════════════════════════════════════");
            results.AppendLine();
            results.AppendLine($"Analysis Date: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            results.AppendLine($"Computer: {Environment.MachineName}");
            results.AppendLine($"User: {Environment.UserName}");
            results.AppendLine();

            results.AppendLine("─────────────────────────────────────────────────────────");
            results.AppendLine("  EXPOSURE SCORE");
            results.AppendLine("─────────────────────────────────────────────────────────");
            results.AppendLine($"Total Score: {currentExposureScore.TotalExposureScore}/100 ({currentExposureScore.ExposureLevel})");
            results.AppendLine();

            results.AppendLine("─────────────────────────────────────────────────────────");
            results.AppendLine("  REGISTRY CONFIGURATION");
            results.AppendLine("─────────────────────────────────────────────────────────");
            var allowTelemetry = currentRegistryFindings.FirstOrDefault(f => f.KeyName == "AllowTelemetry");
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
                results.AppendLine($"AllowTelemetry: {level}");
            }
            results.AppendLine();

            results.AppendLine("─────────────────────────────────────────────────────────");
            results.AppendLine("  ACTIVE SERVICES");
            results.AppendLine("─────────────────────────────────────────────────────────");
            var runningServices = currentServiceFindings.Where(s => s.IsRunning).ToList();
            results.AppendLine($"Running telemetry services: {runningServices.Count}");
            foreach (var service in runningServices.Take(10))
            {
                results.AppendLine($"  - {service.DisplayName}");
            }
            results.AppendLine();

            results.AppendLine("─────────────────────────────────────────────────────────");
            results.AppendLine("  DIAGNOSTIC DATA");
            results.AppendLine("─────────────────────────────────────────────────────────");
            results.AppendLine($"Files found: {currentDiagnosticResults.TotalFilesFound}");
            results.AppendLine($"Total size: {FormatBytes(currentDiagnosticResults.TotalDataSizeBytes)}");
            results.AppendLine($"PII instances: {currentDiagnosticResults.PiiDetections.Count}");

            if (currentDiagnosticResults.PiiDetections.Any())
            {
                var grouped = currentDiagnosticResults.PiiDetections.GroupBy(p => p.PiiType);
                foreach (var group in grouped)
                {
                    results.AppendLine($"  - {group.Key}: {group.Count()} found");
                }
            }

            txtResults.Text = results.ToString();
        }

        private void BtnExportReport_Click(object sender, EventArgs e)
        {
            SaveFileDialog saveDialog = new SaveFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt",
                FileName = $"Exposure-Analysis-{DateTime.Now:yyyy-MM-dd-HHmmss}.txt"
            };

            if (saveDialog.ShowDialog() == DialogResult.OK)
            {
                try
                {
                    System.IO.File.WriteAllText(saveDialog.FileName, txtResults.Text);
                    MessageBox.Show("Report exported successfully!", "Export Complete",
                        MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error: {ex.Message}", "Export Error",
                        MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private void UpdateProgress(int percentage, string message)
        {
            if (InvokeRequired)
            {
                Invoke(new Action<int, string>(UpdateProgress), percentage, message);
                return;
            }
            scanProgressBar.Value = Math.Min(percentage, 100);
            lblProgressMessage.Text = message;
        }

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
            return $"{size:0.##} {suffixes[suffixIndex]}";
        }
    }
}