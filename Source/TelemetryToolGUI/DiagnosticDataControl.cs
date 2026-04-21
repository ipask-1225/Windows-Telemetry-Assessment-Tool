using System;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace TelemetryAssessmentTool.GUI
{
    public class DiagnosticDataControl : UserControl
    {
        private Button btnScan;
        private TextBox txtResults;
        private ProgressBar progressBar;
        private Label lblProgress;

        public DiagnosticDataControl()
        {
            SetupControls();
        }

        private void SetupControls()
        {
            this.SuspendLayout();

            this.BackColor = Color.White;
            this.Padding = new Padding(20);
            this.Size = new Size(980, 640);

            Label lblTitle = new Label
            {
                Location = new Point(20, 20),
                Size = new Size(500, 30),
                Text = "Diagnostic Data File Analyzer",
                Font = new Font("Segoe UI", 14F, FontStyle.Bold)
            };

            Label lblDescription = new Label
            {
                Location = new Point(20, 55),
                Size = new Size(900, 40),
                Text = "Scans Windows diagnostic folders for telemetry files and analyzes them for Personally Identifiable Information (PII).",
                Font = new Font("Segoe UI", 9F)
            };

            txtResults = new TextBox
            {
                Location = new Point(20, 110),
                Size = new Size(940, 430),
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                ReadOnly = true,
                Font = new Font("Consolas", 9F),
                Text = "Click 'Run Scan' to begin diagnostic data analysis...\r\n\r\n" +
                       "NOTE: This scan requires Administrator privileges for full access."
            };

            lblProgress = new Label
            {
                Location = new Point(20, 550),
                Size = new Size(840, 20),
                Text = "",
                Visible = false
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
            this.Controls.Add(lblProgress);
            this.Controls.Add(progressBar);
            this.Controls.Add(btnScan);

            this.ResumeLayout(false);
        }

        private async void BtnScan_Click(object sender, EventArgs e)
        {
            btnScan.Enabled = false;
            progressBar.Visible = true;
            lblProgress.Visible = true;
            txtResults.Text = "Starting diagnostic data scan...\r\n\r\n";

            try
            {
                var analyzer = new TelemetryAssessmentTool.DiagnosticDataAnalyser();
                var result = await analyzer.AnalyzeDiagnosticDataAsync((progress, message) =>
                {
                    UpdateProgress(progress, message);
                });

                txtResults.Text = "═══════════════════════════════════════════════════════════\r\n";
                txtResults.AppendText("           DIAGNOSTIC DATA SCAN COMPLETE\r\n");
                txtResults.AppendText("═══════════════════════════════════════════════════════════\r\n\r\n");

                txtResults.AppendText($"Scan completed: {result.AnalysisTime:yyyy-MM-dd HH:mm:ss}\r\n");
                txtResults.AppendText($"Machine: {result.MachineName}\r\n");
                txtResults.AppendText($"User: {result.Username}\r\n\r\n");

                var accessibleFolders = result.DiagnosticFolders.Where(f => f.Exists && f.IsAccessible).ToList();
                var inaccessibleFolders = result.DiagnosticFolders.Where(f => f.Exists && !f.IsAccessible).ToList();

                txtResults.AppendText("─────────────────────────────────────────────────────────\r\n");
                txtResults.AppendText("  FOLDER SUMMARY\r\n");
                txtResults.AppendText("─────────────────────────────────────────────────────────\r\n\r\n");
                txtResults.AppendText($"Folders scanned: {accessibleFolders.Count}\r\n");
                txtResults.AppendText($"Folders denied access: {inaccessibleFolders.Count}\r\n");
                txtResults.AppendText($"Total files found: {result.TotalFilesFound}\r\n");
                txtResults.AppendText($"Total data size: {FormatBytes(result.TotalDataSizeBytes)}\r\n\r\n");

                if (accessibleFolders.Any())
                {
                    txtResults.AppendText("Accessible Folders:\r\n");
                    foreach (var folder in accessibleFolders)
                    {
                        txtResults.AppendText($"  {folder.Path}\r\n");
                        txtResults.AppendText($"    Files: {folder.FileCount}, Size: {FormatBytes(folder.TotalSizeBytes)}\r\n");
                    }
                    txtResults.AppendText("\r\n");
                }

                if (inaccessibleFolders.Any())
                {
                    txtResults.AppendText("Inaccessible Folders:\r\n");
                    foreach (var folder in inaccessibleFolders)
                    {
                        txtResults.AppendText($"  {folder.Path}\r\n");
                        txtResults.AppendText($"    Error: {folder.AccessError}\r\n");
                    }
                    txtResults.AppendText("\r\n");
                }

                txtResults.AppendText("─────────────────────────────────────────────────────────\r\n");
                txtResults.AppendText("  PII DETECTION\r\n");
                txtResults.AppendText("─────────────────────────────────────────────────────────\r\n\r\n");

                if (result.PiiDetections.Any())
                {
                    txtResults.AppendText($"Found PII in {result.PiiDetections.Count} file instances\r\n\r\n");

                    var grouped = result.PiiDetections.GroupBy(p => p.PiiType).OrderByDescending(g => g.Count());
                    foreach (var group in grouped)
                    {
                        txtResults.AppendText($"{group.Key}: {group.Count()} instances\r\n");

                        foreach (var detection in group.Take(5))
                        {
                            txtResults.AppendText($"  File: {System.IO.Path.GetFileName(detection.FilePath)}\r\n");
                            txtResults.AppendText($"  Matches: {detection.MatchCount}\r\n");
                        }
                        txtResults.AppendText("\r\n");
                    }
                }
                else
                {
                    txtResults.AppendText("No PII detected in scanned files.\r\n");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}\r\n\r\nPlease run as Administrator.",
                    "Scan Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                btnScan.Enabled = true;
                progressBar.Visible = false;
                lblProgress.Visible = false;
            }
        }

        private void UpdateProgress(int percentage, string message)
        {
            if (InvokeRequired)
            {
                Invoke(new Action<int, string>(UpdateProgress), percentage, message);
                return;
            }
            progressBar.Value = percentage;
            lblProgress.Text = message;
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