using CertificateManager;
using CertificateManager.Models;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SBCertUtils;

namespace CertsCreateDeviceCertificate
{
    /// <summary>
    /// https://docs.microsoft.com/en-us/azure/iot-hub/iot-hub-security-x509-get-started
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            var serviceProvider = new ServiceCollection()
                .AddCertificateManager()
                .BuildServiceProvider();

            var createClientServerAuthCerts = serviceProvider.GetService<CreateCertificatesClientServerAuth>();
            var iec = serviceProvider.GetService<ImportExportCertificate>();

            var fileName = CertUtils.CertPath("dpsIntermediate1.pfx");
            Console.WriteLine($"Importing {fileName}");
            var intermediate = new X509Certificate2(fileName, "1234");
            Console.WriteLine($"Imported  {fileName}");
            intermediate.PrintCert();

            var device = createClientServerAuthCerts.NewDeviceChainedCertificate(
                new DistinguishedName { CommonName = "testdevice01" },
                new ValidityPeriod { ValidFrom = DateTime.UtcNow, ValidTo = DateTime.UtcNow.AddYears(10) },
                "testdevice01", intermediate);
            //device.FriendlyName = "IoT device testdevice01";
      
            string password = "1234";
            var importExportCertificate = serviceProvider.GetService<ImportExportCertificate>();

            var deviceInPfxBytes = importExportCertificate.ExportChainedCertificatePfx(password, device, intermediate);
            fileName = CertUtils.CertPath("testdevice01.pfx");
            File.WriteAllBytes(fileName, deviceInPfxBytes);
            Console.WriteLine($"Exported {fileName}");

            var devicePEM = iec.PemExportPublicKeyCertificate(device);
            fileName = CertUtils.CertPath("testdevice01.pem");
            File.WriteAllText(fileName, devicePEM);
            Console.WriteLine($"Exported {fileName}");

   

        }
    }
}
