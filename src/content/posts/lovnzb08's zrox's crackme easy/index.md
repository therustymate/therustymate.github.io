---
title: lovnzb08's zrox's crackme easy
published: 2025-06-15
description: lovnzb08's zrox's crackme easy
tags: [analysis, csharp, dotnet]
category: Crackmes
draft: false
lang: en
---

# lovnzb08's zrox's crackme easy

## Entry Point
`Program.cs`
```csharp
using System;
using System.Windows.Forms;

namespace olartik
{
	internal static class Program
	{
		[STAThread]
		private static void Main()
		{
			Application.EnableVisualStyles();
			Application.SetCompatibleTextRenderingDefault(defaultValue: false);
			Application.Run(new Form1());
		}
	}
}
```

The above code is the entry point of the program. It is located in the `Main()` function of `Program.cs`.

Based on the structure, this is a typical **Windows Forms application** created as `WinForm` using `Visual Studio 2022`.

## WinForms Components
```csharp
private void InitializeComponent()
{
    this.txtKey = new System.Windows.Forms.TextBox();
    this.btnLogin = new System.Windows.Forms.Button();
    base.SuspendLayout();
    this.txtKey.Location = new System.Drawing.Point(12, 12);
    this.txtKey.Name = "txtKey";
    this.txtKey.Size = new System.Drawing.Size(260, 22);
    this.txtKey.TabIndex = 0;
    this.btnLogin.Location = new System.Drawing.Point(12, 40);
    this.btnLogin.Name = "btnLogin";
    this.btnLogin.Size = new System.Drawing.Size(75, 23);
    this.btnLogin.TabIndex = 1;
    this.btnLogin.Text = "Giris";
    this.btnLogin.UseVisualStyleBackColor = true;
    this.btnLogin.Click += new System.EventHandler(btnLogin_Click);
    base.AutoScaleDimensions = new System.Drawing.SizeF(8f, 16f);
    base.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
    base.ClientSize = new System.Drawing.Size(284, 76);
    base.Controls.Add(this.btnLogin);
    base.Controls.Add(this.txtKey);
    base.Name = "Form1";
    this.Text = "Key Giris Uygulamasi";
    base.ResumeLayout(false);
    base.PerformLayout();
}
```

The above code represents the components of the GUI of the application.

Based on the structure, the only function connected to the program is the `btnLogin_Click()` function.

## `btnLogin_Click()` Function
```csharp
private void btnLogin_Click(object sender, EventArgs e)
{
    string text = "sifreyok";
    if (txtKey.Text == text)
    {
        MessageBox.Show("giris basarili");
    }
    else
    {
        MessageBox.Show("giris basarisiz");
    }
}
```

This code verifies a kind of **password** entered by the user in `txtKey` (`TextBox`) and displays the result using a message box.

## Flag
Therefore, the final flag of this program is as follows: `sifreyok`