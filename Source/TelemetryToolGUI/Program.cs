using System;
using System.Windows.Forms;
using TelemetryAssessmentTool.GUI;

namespace TelemetryAssessmentTool.GUI
{
    internal static class Program
    {
        [STAThread]
        static void Main()
        {
            ApplicationConfiguration.Initialize();
            Application.Run(new MainForm());
        }
    }
}