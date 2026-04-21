using System;
using System.Drawing;
using System.Windows.Forms;

namespace TelemetryAssessmentTool.GUI
{
    public class RegistryScanControl : UserControl
    {
        private Button btnScan;
        private TextBox txtResults;
        private ProgressBar progressBar;

        public RegistryScanControl()
        {
            SetupControls();
        }

        private void SetupControls()
        {
            this.BackColor = Color.White;
            this.Padding = new Padding(20);

            Label lblTitle = new Label
            {
                Location = new Point(20, 20),
                Size = new Size(500, 30),
                Text = "Windows Registry Telemetry Scanner",
                Font = new Font("Segoe UI", 14F, FontStyle.Bold)
            };

            Label lblDescription = new Label
            {
                Location = new Point(20, 55),
                Size = new Size(900, 40),
                Text = "Scans Windows Registry for telemetry configuration keys including AllowTelemetry and CEIPEnable settings.",
                Font = new Font("Segoe UI", 9F)
            };

            txtResults = new TextBox
            {
                Location = new Point(20, 110),
                Size = new Size(940, 450),
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                ReadOnly = true,
                Font = new Font("Consolas", 9F),
                Text = "Click 'Run Scan' to begin registry analysis..."
            };

            progressBar = new ProgressBar
            {
                Location = new Point(20, 570),
                Size = new Size(840, 25),
                Visible = false
            };

            btnScan = new Button
            {
                Location = new Point(870, 570),
                Size = new Size(90, 30),
                Text = "Run Scan",
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                BackColor = Color.FromArgb(0, 120, 215),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            btnScan.FlatAppearance.BorderSize = 0;
            btnScan.Click += BtnScan_Click;

            this.Controls.Add(lblTitle);
            this.Controls.Add(lblDescription);
            this.Controls.Add(txtResults);
            this.Controls.Add(progressBar);
            this.Controls.Add(btnScan);
        }

        private async void BtnScan_Click(object sender, EventArgs e)
        {
            btnScan.Enabled = false;
            progressBar.Visible = true;
            txtResults.Text = "Scanning Windows Registry...\r\n\r\n";

            try
            {
                var scanner = new TelemetryAssessmentTool.Services.TelemetryRegistryScanner();
                var findings = await scanner.ScanTelemetryKeysAsync((current, max) =>
                {
                    UpdateProgress((current * 100) / max);
                });

                txtResults.Text = "═══════════════════════════════════════════════════════════\r\n";
                txtResults.AppendText("              REGISTRY SCAN RESULTS\r\n");
                txtResults.AppendText("═══════════════════════════════════════════════════════════\r\n\r\n");

                if (findings.Count == 0)
                {
                    txtResults.AppendText("No telemetry registry keys found.\r\n");
                }
                else
                {
                    var allowTelemetry = findings.FindAll(f => f.KeyName == "AllowTelemetry");
                    var ceip = findings.FindAll(f => f.KeyName == "CEIPEnable");

                    if (allowTelemetry.Count > 0)
                    {
                        txtResults.AppendText("─────────────────────────────────────────────────────────\r\n");
                        txtResults.AppendText("  ALLOWTELEMETRY SETTINGS\r\n");
                        txtResults.AppendText("─────────────────────────────────────────────────────────\r\n\r\n");

                        foreach (var finding in allowTelemetry)
                        {
                            txtResults.AppendText($"Registry Path: {finding.Path}\r\n");
                            txtResults.AppendText($"Current Value: {finding.Value}\r\n");

                            string description = finding.Value switch
                            {
                                "0" => "Security Only - Telemetry is disabled",
                                "1" => "Basic - Minimal diagnostic data collection",
                                "2" => "Enhanced - Additional diagnostic data",
                                "3" => "Full - Maximum data collection",
                                _ => "Unknown configuration"
                            };
                            txtResults.AppendText($"Description: {description}\r\n");

                            if (finding.Value == "1" || finding.Value == "2" || finding.Value == "3")
                            {
                                txtResults.AppendText("Status: ACTIVE - Telemetry is enabled\r\n");
                            }
                            else if (finding.Value == "0")
                            {
                                txtResults.AppendText("Status: INACTIVE - Telemetry is disabled\r\n");
                            }
                            txtResults.AppendText("\r\n");
                        }
                    }

                    if (ceip.Count > 0)
                    {
                        txtResults.AppendText("─────────────────────────────────────────────────────────\r\n");
                        txtResults.AppendText("  CUSTOMER EXPERIENCE IMPROVEMENT PROGRAM\r\n");
                        txtResults.AppendText("─────────────────────────────────────────────────────────\r\n\r\n");

                        foreach (var finding in ceip)
                        {
                            txtResults.AppendText($"Registry Path: {finding.Path}\r\n");
                            txtResults.AppendText($"Current Value: {finding.Value}\r\n");

                            if (finding.Value == "1")
                            {
                                txtResults.AppendText("Status: ACTIVE - CEIP is enabled\r\n");
                            }
                            else if (finding.Value == "0")
                            {
                                txtResults.AppendText("Status: INACTIVE - CEIP is disabled\r\n");
                            }
                            txtResults.AppendText("\r\n");
                        }
                    }

                    txtResults.AppendText("═══════════════════════════════════════════════════════════\r\n");
                    txtResults.AppendText($"Total registry entries scanned: {findings.Count}\r\n");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error during scan: {ex.Message}", "Scan Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                btnScan.Enabled = true;
                progressBar.Visible = false;
            }
        }

        private void UpdateProgress(int percentage)
        {
            if (InvokeRequired)
            {
                Invoke(new Action<int>(UpdateProgress), percentage);
                return;
            }
            progressBar.Value = Math.Min(percentage, 100);
        }
    }
}