using System;
using System.Drawing;
using System.Windows.Forms;

namespace TelemetryAssessmentTool.GUI
{
    public partial class MainForm : Form
    {
        private TabControl tabControl;
        private StatusStrip statusStrip;
        private ToolStripStatusLabel statusLabel;

        public MainForm()
        {
            InitializeComponent();
            SetupForm();
            SetupControls();
            CheckAdminPrivileges();
        }

        private void SetupForm()
        {
            this.Text = "Windows Telemetry Assessment Tool";
            this.Size = new Size(1000, 700);
            this.MinimumSize = new Size(900, 600);
            this.StartPosition = FormStartPosition.CenterScreen;
        }

        private void SetupControls()
        {
            tabControl = new TabControl
            {
                Dock = DockStyle.Fill,
                Font = new Font("Segoe UI", 9F)
            };

            TabPage fullAnalysisTab = new TabPage("Full Analysis");
            TabPage registryTab = new TabPage("Registry Scan");
            TabPage servicesTab = new TabPage("Services Scan");
            TabPage diagnosticTab = new TabPage("Diagnostic Data");

            var fullAnalysisControl = new FullAnalysisControl { Dock = DockStyle.Fill };
            var registryScanControl = new RegistryScanControl { Dock = DockStyle.Fill };
            var servicesScanControl = new ServicesScanControl { Dock = DockStyle.Fill };
            var diagnosticDataControl = new DiagnosticDataControl { Dock = DockStyle.Fill };

            fullAnalysisTab.Controls.Add(fullAnalysisControl);
            registryTab.Controls.Add(registryScanControl);
            servicesTab.Controls.Add(servicesScanControl);
            diagnosticTab.Controls.Add(diagnosticDataControl);

            tabControl.TabPages.Add(fullAnalysisTab);
            tabControl.TabPages.Add(registryTab);
            tabControl.TabPages.Add(servicesTab);
            tabControl.TabPages.Add(diagnosticTab);

            statusStrip = new StatusStrip();
            statusLabel = new ToolStripStatusLabel("Ready");
            statusStrip.Items.Add(statusLabel);

            this.Controls.Add(tabControl);
            this.Controls.Add(statusStrip);
        }

        private void CheckAdminPrivileges()
        {
            bool isAdmin = false;
            try
            {
                var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                isAdmin = principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch { }

            if (!isAdmin)
            {
                statusLabel.Text = "WARNING: Not running as Administrator - Some features may be limited";
                statusLabel.ForeColor = Color.Red;

                MessageBox.Show(
                    "This application is not running with Administrator privileges.\n\n" +
                    "Some diagnostic folders may be inaccessible.\n" +
                    "For complete analysis, right-click the application and select 'Run as Administrator'.",
                    "Administrator Privileges Required",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
            }
            else
            {
                statusLabel.Text = "Running with Administrator privileges";
                statusLabel.ForeColor = Color.Green;
            }
        }
    }
}