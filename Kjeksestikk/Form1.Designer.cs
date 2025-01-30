namespace Kjeksestikk
{
	partial class Form1
	{
		/// <summary>
		/// Required designer variable.
		/// </summary>
		private System.ComponentModel.IContainer components = null;

		/// <summary>
		/// Clean up any resources being used.
		/// </summary>
		/// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
		protected override void Dispose(bool disposing)
		{
			if (disposing && (components != null))
			{
				components.Dispose();
			}
			base.Dispose(disposing);
		}

		#region Windows Form Designer generated code

		/// <summary>
		/// Required method for Designer support - do not modify
		/// the contents of this method with the code editor.
		/// </summary>
		private void InitializeComponent()
		{
			System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form1));
			this.lstProsesser = new System.Windows.Forms.ListBox();
			this.label1 = new System.Windows.Forms.Label();
			this.btnVelg = new System.Windows.Forms.Button();
			this.btnStikk = new System.Windows.Forms.Button();
			this.txtStatusBoks = new System.Windows.Forms.RichTextBox();
			this.SuspendLayout();
			// 
			// lstProsesser
			// 
			this.lstProsesser.FormattingEnabled = true;
			this.lstProsesser.IntegralHeight = false;
			this.lstProsesser.Location = new System.Drawing.Point(12, 27);
			this.lstProsesser.Name = "lstProsesser";
			this.lstProsesser.ScrollAlwaysVisible = true;
			this.lstProsesser.Size = new System.Drawing.Size(200, 280);
			this.lstProsesser.TabIndex = 0;
			// 
			// label1
			// 
			this.label1.AutoSize = true;
			this.label1.Location = new System.Drawing.Point(23, 9);
			this.label1.Name = "label1";
			this.label1.Size = new System.Drawing.Size(98, 13);
			this.label1.TabIndex = 1;
			this.label1.Text = "Kjørende Prosesser";
			// 
			// btnVelg
			// 
			this.btnVelg.Location = new System.Drawing.Point(218, 256);
			this.btnVelg.Name = "btnVelg";
			this.btnVelg.Size = new System.Drawing.Size(225, 51);
			this.btnVelg.TabIndex = 2;
			this.btnVelg.Text = "VELG KJEKS.DLL";
			this.btnVelg.UseVisualStyleBackColor = true;
			this.btnVelg.Click += new System.EventHandler(this.btnVelg_Click);
			// 
			// btnStikk
			// 
			this.btnStikk.Location = new System.Drawing.Point(449, 256);
			this.btnStikk.Name = "btnStikk";
			this.btnStikk.Size = new System.Drawing.Size(222, 51);
			this.btnStikk.TabIndex = 3;
			this.btnStikk.Text = "STIKK DLL i VALGT MÅLPROSESS";
			this.btnStikk.UseVisualStyleBackColor = true;
			this.btnStikk.Click += new System.EventHandler(this.btnStikk_Click);
			// 
			// txtStatusBoks
			// 
			this.txtStatusBoks.BackColor = System.Drawing.Color.Black;
			this.txtStatusBoks.BorderStyle = System.Windows.Forms.BorderStyle.None;
			this.txtStatusBoks.Font = new System.Drawing.Font("Verdana", 9F, System.Drawing.FontStyle.Italic, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
			this.txtStatusBoks.ForeColor = System.Drawing.Color.White;
			this.txtStatusBoks.Location = new System.Drawing.Point(218, 27);
			this.txtStatusBoks.Name = "txtStatusBoks";
			this.txtStatusBoks.ReadOnly = true;
			this.txtStatusBoks.Size = new System.Drawing.Size(453, 223);
			this.txtStatusBoks.TabIndex = 4;
			this.txtStatusBoks.Text = "";
			this.txtStatusBoks.TextChanged += new System.EventHandler(this.txtStatusBoks_TextChanged);
			// 
			// Form1
			// 
			this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
			this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
			this.BackColor = System.Drawing.Color.White;
			this.ClientSize = new System.Drawing.Size(683, 319);
			this.Controls.Add(this.txtStatusBoks);
			this.Controls.Add(this.btnStikk);
			this.Controls.Add(this.btnVelg);
			this.Controls.Add(this.label1);
			this.Controls.Add(this.lstProsesser);
			this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
			this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
			this.MaximizeBox = false;
			this.Name = "Form1";
			this.Text = "Kjeksestikk64 - Thronic DLL Injector";
			this.ResumeLayout(false);
			this.PerformLayout();

		}

		#endregion

		private System.Windows.Forms.ListBox lstProsesser;
		private System.Windows.Forms.Label label1;
		private System.Windows.Forms.Button btnVelg;
		private System.Windows.Forms.Button btnStikk;
		private System.Windows.Forms.RichTextBox txtStatusBoks;
	}
}

