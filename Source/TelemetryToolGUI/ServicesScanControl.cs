using System;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace TelemetryAssessmentTool.GUI
{
    public class ServicesScanControl : UserControl
    {
        private Button btnScan;
        private TextBox txtResults;
        private ProgressBar progressBar;
        private Label lblSummary;

        public ServicesScanControl()
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
                Text = "Windows Telemetry Services Scanner",
                Font = new Font("Segoe UI", 14F, FontStyle.Bold)
            };

            Label lblDescription = new Label
            {
                Location = new Point(20, 55),
                Size = new Size(900, 40),
                Text = "Scans Windows services that are responsible for telemetry data collection and transmission.",
                Font = new Font("Segoe UI", 9F)
            };

            lblSummary = new Label
            {
                Location = new Point(20, 100),
                Size = new Size(900, 20),
                Text = "Click 'Run Scan' to analyze telemetry services...",
                Font = new Font("Segoe UI", 9F)
            };

            txtResults = new TextBox
            {
                Location = new Point(20, 130),
                Size = new Size(940, 430),
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                ReadOnly = true,
                Font = new Font("Consolas", 9F),
                BackColor = Color.White
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
            this.Controls.Add(lblSummary);
            this.Controls.Add(txtResults);
            this.Controls.Add(progressBar);
            this.Controls.Add(btnScan);
        }

        private async void BtnScan_Click(object sender, EventArgs e)
        {
            btnScan.Enabled = false;
            progressBar.Visible = true;
            txtResults.Clear();

            try
            {
                var scanner = new TelemetryAssessmentTool.Services.TelemetryServicesScanner();
                var findings = await scanner.ScanTelemetryServicesAsync((progress, message) =>
                {
                    UpdateProgress(progress);
                });

                int foundCount = findings.Count(f => f.Found);
                int runningCount = findings.Count(f => f.IsRunning);

                lblSummary.Text = $"Scan complete: {foundCount} services found, {runningCount} currently running";

                var running = findings.Where(f => f.Found && f.IsRunning).ToList();
                var stopped = findings.Where(f => f.Found && !f.IsRunning).ToList();

                txtResults.AppendText("═══════════════════════════════════════════════════════════\r\n");
                txtResults.AppendText("           TELEMETRY SERVICES SCAN RESULTS\r\n");
                txtResults.AppendText("═══════════════════════════════════════════════════════════\r\n\r\n");

                txtResults.AppendText($"Total services scanned: {findings.Count}\r\n");
                txtResults.AppendText($"Services found on system: {foundCount}\r\n");
                txtResults.AppendText($"Currently running: {runningCount}\r\n\r\n");

                if (running.Any())
                {
                    txtResults.AppendText("─────────────────────────────────────────────────────────\r\n");
                    txtResults.AppendText("  RUNNING SERVICES (Active Collection)\r\n");
                    txtResults.AppendText("─────────────────────────────────────────────────────────\r\n\r\n");

                    foreach (var service in running)
                    {
                        txtResults.AppendText($"Service: {service.DisplayName}\r\n");
                        txtResults.AppendText($"  Name: {service.ServiceName}\r\n");
                        txtResults.AppendText($"  Status: {service.Status}\r\n");
                        txtResults.AppendText($"  Startup: {service.StartType}\r\n");
                        txtResults.AppendText($"  Description: {service.Description}\r\n\r\n");
                    }
                }

                if (stopped.Any())
                {
                    txtResults.AppendText("─────────────────────────────────────────────────────────\r\n");
                    txtResults.AppendText("  STOPPED SERVICES\r\n");
                    txtResults.AppendText("─────────────────────────────────────────────────────────\r\n\r\n");

                    foreach (var service in stopped)
                    {
                        txtResults.AppendText($"Service: {service.DisplayName}\r\n");
                        txtResults.AppendText($"  Name: {service.ServiceName}\r\n");
                        txtResults.AppendText($"  Status: {service.Status}\r\n");
                        txtResults.AppendText($"  Startup: {service.StartType}\r\n\r\n");
                    }
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