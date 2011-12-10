using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using System.Net;
using System.Net.Sockets;
using SharpPcap;
using SharpPcap.Packets;
using System.Diagnostics;

namespace NScanner
{
    public partial class Form1 : Form
    {
        private int portFrom;
        private int portTo;
        private int percentComplete;
        private string _scannerType;
        private string _scanMethod;
        private PcapDevice dev;
        private IPAddress gateway;

        private delegate string ScanMethodDelegate(int port, IPEndPoint ipEnd);

        public Form1()
        {
            InitializeComponent();
            InitializeBackgroundWorker();
            comboBox3.DataSource = Pcap.GetAllDevices();
            comboBox3.DisplayMember = "Description";
        }

        private void button1_Click(object sender, EventArgs e)
        {
            textBox4.Clear();
            button1.Enabled = false;
            try
            {
                _scannerType = comboBox1.SelectedItem.ToString();
                _scanMethod = comboBox2.SelectedItem.ToString();
                portFrom = Convert.ToInt32(textBox1.Text);
                if (textBox2.Enabled) portTo = Convert.ToInt32(textBox2.Text);
                dev = (PcapDevice)comboBox3.SelectedItem;
                //Matching selected interface with .NET's facilities in order to get gateway's ip address
                //that is a property of the network interface of interest.
                foreach (NetworkInterface f in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (dev.Interface.Name.Contains(f.Id))
                    {
                        gateway = f.GetIPProperties().GatewayAddresses[0].Address;
                        break;
                    }
                }
                backgroundWorker1.RunWorkerAsync();                
            }
            catch (Exception ex)
            {
                textBox4.Text = "You have to insert all appropriate parameters.\n";
                textBox4.Text = ex.Message;
                button1.Enabled = true;
            }            

        }

        private List<string> ScanMethod(BackgroundWorker worker)
        {
            string line;
            var timeElapsed = new Stopwatch();
            timeElapsed.Start();
            var log = new List<string>();
            ScanMethodDelegate scan = null;
            //Determining the appropriate delegate to use
            switch (_scanMethod)
            {
                case "TCP Scan":
                    scan = new ScanMethodDelegate(TCPScan);
                    break;
                case "UDP Scan":
                    scan = new ScanMethodDelegate(UDPScan);
                    break;
                case "SYN Scan":
                    scan = new ScanMethodDelegate(SYNScan);
                    break;
            }
            log.Add("#Port Scanner/Sweeper Project, Version 0.1, June 2009" +"\n");
            log.Add("#Scanner type used in current scan: " + _scannerType + "\n");
            log.Add("#"+ _scanMethod + " initiated at: " + DateTime.Now.ToString()+ "\n");                
            if (_scannerType == "Port Scanner")
            {
                try
                {
                    IPAddress hostAddress = Dns.GetHostEntry(textBox3.Text).AddressList[0];
                    for (int port = portFrom; port <= portTo; port++)
                    {
                        Thread.Sleep(Convert.ToInt32(textBox5.Text));
                        line = (PortOfHost(port, hostAddress, scan)) + "/" + IPPort.getDescription(port) +"\n";
                        percentComplete = (int)((float)(port - portFrom) / (float)(portTo - portFrom) * 100);
                        if (portFrom==portTo)worker.ReportProgress(100);
                        else worker.ReportProgress(percentComplete);
                        log.Add(line);
                    }
                }
                catch (SocketException ex)
                {
                    log.Add("#Scan ended unexpectedly after " + timeElapsed.Elapsed.Seconds + " seconds.\n");
                    Console.WriteLine(ex.Message);
                }
            }
            else
            {
                log.Add("Port sweeped: " + portFrom + "/" + IPPort.getDescription(portFrom) + "\n");
                string[] addressList = Regex.Split(textBox3.Text.Trim(), " ");
                int i = 0;
                IPAddress hostAddress = null;
                foreach (var address in addressList)
                {
                    Thread.Sleep(Convert.ToInt32(textBox5.Text));  
                    i++;
                    try
                    {
                        hostAddress = Dns.GetHostEntry(address).AddressList[0];
                        line = "Host " + address + ":\n the port"; 
                        line += (PortOfHost(portFrom, hostAddress, scan));
                    }
                    catch (SocketException ex)
                    {
                        line = address + " reports " + ex.Message + "\n";
                    }                        
                    percentComplete = i / (addressList.Length) * 100;
                    worker.ReportProgress(percentComplete);
                    log.Add(line);
                }
            }                  
            timeElapsed.Stop();
            log.Add("#Scan ended succesfully after " + timeElapsed.Elapsed.Minutes +
                    " minutes " + timeElapsed.Elapsed.Seconds + " seconds.\n");
            return log;
        }

        private string PortOfHost(int port, IPAddress hostAddress, ScanMethodDelegate scanMethodDelegate)
        {
            return scanMethodDelegate(port, new IPEndPoint(hostAddress, port));           
        }

        private string UDPScan(int port, IPEndPoint ipEnd)
        {
            try
            {
                var udpcl = new UdpConnectCall(Convert.ToInt32(textBox6.Text));
                udpcl.Connect(ipEnd);
                return (string.Format("{0} is opened\n", port));
            }
            catch (Exception ex)
            {
                switch (ex.Message)
                {
                    case "CLOSED":
                        return (string.Format("{0} is closed\n", port));
                        break;
                    case "TIME_OUT":
                        return (string.Format("{0} is open/filtered\n", port));
                        break;
                    default:
                        break;
                }
            }
            return null;
        }

        private string TCPScan(int port, IPEndPoint ipEnd)
        {
            try
            {
                TcpConnectCall.Connect(new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp), ipEnd, Convert.ToInt32(textBox6.Text));
                return (string.Format("{0} is opened\n", port));
            }
            catch (Exception ex)
            {
                switch (ex.Message)
                {
                    case "TIME_OUT":
                        return (string.Format("{0} is filtered\n", port));
                        break; 
                    case "PORT_CLOSED":
                        return (string.Format("{0} is closed\n", port));
                        break;
                }
            }
            return null;
        }

        private string SYNScan(int port, IPEndPoint ipEnd)
        {
            try
            {                
                if ((new SynConnectCall(Convert.ToInt32(textBox6.Text), dev, gateway)).connect(ipEnd, port))
                    return (string.Format("{0} is opened\n", port));             
            }
            catch(Exception ex)
            {
                switch (ex.Message)
                {
                    case "TIME_OUT":
                        return (string.Format("{0} is filtered\n", port));
                    case "CLOSED":
                        return (string.Format("{0} is closed\n", port));
                    default:
                        Console.WriteLine(ex.Message);
                        break;
                }                
            }

            return null;
        }

        private void comboBox1_SelectedIndexChanged(object sender, EventArgs e)
        {
            textBox2.Enabled = (_scannerType = comboBox1.SelectedItem.ToString()) != "Port Sweeper";            
        }

        private void InitializeBackgroundWorker()
        {            
            backgroundWorker1.RunWorkerCompleted += new RunWorkerCompletedEventHandler(backgroundWorker1_RunWorkerCompleted);
            backgroundWorker1.ProgressChanged += new ProgressChangedEventHandler(BackgroundWorker1_ProgressChanged);
        }

        private void BackgroundWorker1_ProgressChanged(object sender, ProgressChangedEventArgs e)
        {
            progressBar1.Value = e.ProgressPercentage;
        }

        private void backgroundWorker1_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            foreach (var s in (List<string>)e.Result)
            {
                textBox4.AppendText(s);
            }
            button1.Enabled = true;
        }

        private void backgroundWorker1_DoWork(object sender, DoWorkEventArgs e)
        {
            var worker = sender as BackgroundWorker;
            e.Result = ScanMethod(worker);
        }

        private void exitToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Close();
        }

        private void saveAsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            saveFileDialog1.ShowDialog();
        }

        private void saveFileDialog1_FileOk(object sender, CancelEventArgs e)
        {
            using (FileStream fs = File.Create(saveFileDialog1.FileName))
            {
                Byte[] info = new UTF8Encoding(true).GetBytes(textBox4.Text);
                // Add some information to the file.
                fs.Write(info, 0, info.Length);
            }
        }

        private void aboutToolStripMenuItem_Click(object sender, EventArgs e)
        {
            MessageBox.Show("NScanner: Version 0.1\nA .NET (TCP, UDP, SYN) port scanner-sweeper by \nAggelos Mpimpoudis & Anastasios Nerantzinis");
        }

        private void button3_Click(object sender, EventArgs e)
        {
            Close();
        }
    }
}
