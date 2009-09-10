using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using System.Security.Cryptography.X509Certificates;

namespace EDLRegister
{
    public partial class MainForm : Form
    {
        public MainForm()
        {
            InitializeComponent();
        }

        private void registerButton_Click(object sender, EventArgs e)
        {
            try
            {
                /*Dictionary<X509Certificate2, CertificateContext> certs = RegisterCertificate.GetCertificates();
                foreach (KeyValuePair<X509Certificate2, CertificateContext> cert in certs)
                {
                    RegisterCertificate.Register(cert.Key, cert.Value);
                }*/
                List<RegisterCertificate.CertItem> certs = RegisterCertificate.GetCertificates();
                foreach (RegisterCertificate.CertItem cert in certs)
                    RegisterCertificate.Register(cert.cert, cert.context);
                MessageBox.Show("Rijbewijs geregistreerd.");
                this.Close();
            }
            catch (RegisterException ex)
            {
                switch (ex.EventArgs.Type)
                {
                    case RegisterException.ACQUIRE_CONTEXT:
                        MessageBox.Show(ex.Message);
                        break;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Geen rijbewijs gevonden. Controleer of het rijbewijs in de kaartlezer zit.");
                MessageBox.Show("Exception: " + ex.Message);
            }
        }
    }
}