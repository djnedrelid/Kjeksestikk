﻿using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace Kjeksestikk
{
	public partial class Form1 : Form
	{
		[DllImport("Injiserer32.dll")]
		[return: MarshalAs(UnmanagedType.I1)]
		public static extern bool Injiser(
			[MarshalAs(UnmanagedType.LPWStr)] String FullDllPath,
			[MarshalAs(UnmanagedType.LPWStr)] String ProcessName
		);

		[DllImport("kernel32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		static extern bool IsWow64Process(IntPtr hProcess, out bool lpSystemInfo);
	
		string ValgtKjeks = "";

		public Form1()
		{
			InitializeComponent();
			LoadProcesses();
			Status("Program startet.");
		}

		private void Status(string s)
		{
			txtStatusBoks.AppendText(
				DateTime.Now.ToString("HH:mm") +": "+ s + "\n"
			);
		}
	
		private bool Is64BitProcess(Process p)
		{
			bool is64Bit = false;

			// Default to 32-bit if unable to detect
			try
			{
				// 64-bit process running on 64-bit OS
				if (IntPtr.Size == 8) 
					is64Bit = true;

				else if (IsWow64Process(p.Handle, out bool wow64))
					is64Bit = !wow64; // If the process is not WOW64, it's 64-bit

			} catch {}

			return is64Bit;
		}

		private void LoadProcesses()
		{
			Process[] pArr = Process.GetProcesses().OrderBy(p => p.ProcessName).ToArray();
			foreach (Process p in pArr) {
				if (
					p.ProcessName == "svchost" ||
					p.ProcessName == "conhost" || 
					p.ProcessName == "dllhost" || 
					p.ProcessName == "RuntimeBroker" ||
					p.ProcessName.Contains("ServiceHub")
				)
					continue;

				if (!Is64BitProcess(p)) 
					lstProsesser.Items.Add(
						new KeyValuePair<string,int>(
							p.ProcessName,
							p.Id
						)
					);
			}

			Status("Prosesser lagt til liste.");
		}

		private void txtStatusBoks_TextChanged(object sender, EventArgs e)
		{
			txtStatusBoks.ScrollToCaret();
		}

		private void btnVelg_Click(object sender, EventArgs e)
		{
			OpenFileDialog openFileDialog = new OpenFileDialog();
			openFileDialog.Multiselect = false;
			openFileDialog.Filter = "DLL  (*.dll)|*.dll";
			openFileDialog.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
			if (openFileDialog.ShowDialog() == DialogResult.OK)
			{
				// Get information to the received about its size before accepting it.
				ValgtKjeks = Path.GetFullPath(openFileDialog.FileName);
				Status("Valgt kjeks: "+ ValgtKjeks);
			}
		}

		private void btnStikk_Click(object sender, EventArgs e)
		{
			if (lstProsesser.SelectedIndex == -1) {
				MessageBox.Show("Velg en målprosess først.");
				return;
			}

			if (ValgtKjeks == "") {
				MessageBox.Show("Velg en kjeks først.");
				return;
			}

			KeyValuePair<string,int> Prosess = (KeyValuePair<string,int>)lstProsesser.Items[lstProsesser.SelectedIndex];
			Status("Prøver injisering på "+ Prosess.Key +".exe");

			if (Injiser(ValgtKjeks, Prosess.Key +".exe"))
				Status("Injisering OK!");
			else
				Status("Injisering FEILET!");
		}
	}
}
