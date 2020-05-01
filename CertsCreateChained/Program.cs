using CertificateManager;
using CertificateManager.Models;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using SBCertUtils;

namespace CertsCreateChained
{
    class Program
    {
        static void Main(string[] args)
        {
            var serviceProvider = new ServiceCollection()
                .AddCertificateManager()
                .BuildServiceProvider();

            string password = "1234";
            var cc = serviceProvider.GetService<CreateCertificatesClientServerAuth>();
            var iec = serviceProvider.GetService<ImportExportCertificate>();

            var dpsCa = cc.NewRootCertificate(
                new DistinguishedName { CommonName = "dpsCa", Country = "CH" },
                new ValidityPeriod { ValidFrom = DateTime.UtcNow, ValidTo = DateTime.UtcNow.AddYears(10) },
                3, "dpsCa");
            //dpsCa.FriendlyName = "development root certificate";
            dpsCa.PrintCert(nameof(dpsCa));

            var dpsIntermediate1 = cc.NewIntermediateChainedCertificate(
                new DistinguishedName { CommonName = "dpsIntermediate1", Country = "CH" },
                new ValidityPeriod { ValidFrom = DateTime.UtcNow, ValidTo = DateTime.UtcNow.AddYears(10) },
                2, "dpsIntermediate1", dpsCa);
            //dpsIntermediate1.FriendlyName = "dpsIntermediate1 certificate";
            dpsIntermediate1.PrintCert(nameof(dpsIntermediate1));

            var dpsIntermediate2 = cc.NewIntermediateChainedCertificate(
                new DistinguishedName { CommonName = "dpsIntermediate2", Country = "CH" },
                new ValidityPeriod { ValidFrom = DateTime.UtcNow, ValidTo = DateTime.UtcNow.AddYears(10) },
                2, "dpsIntermediate2", dpsCa);
            //dpsIntermediate2.FriendlyName = "dpsIntermediate2 certificate";

            // EXPORTS PFX

            var rootCertInPfxBytes = iec.ExportRootPfx(password, dpsCa);
            var fileName = CertUtils.CertPath("dpsCa.pfx");
            File.WriteAllBytes(fileName, rootCertInPfxBytes);
            Console.WriteLine($"Exported {fileName}");

            var dpsIntermediate1Bytes = iec.ExportChainedCertificatePfx(password, dpsIntermediate1, dpsCa);
            fileName = CertUtils.CertPath("dpsIntermediate1.pfx");
            File.WriteAllBytes(fileName, dpsIntermediate1Bytes);
            Console.WriteLine($"Exported {fileName}");

            var dpsIntermediate2Bytes = iec.ExportChainedCertificatePfx(password, dpsIntermediate2, dpsCa);
            fileName = CertUtils.CertPath("dpsIntermediate2.pfx");
            File.WriteAllBytes(fileName, dpsIntermediate2Bytes);
            Console.WriteLine($"Exported {fileName}");

            // EXPORTS PEM

            var dpsCaPEM = iec.PemExportPublicKeyCertificate(dpsCa);
            fileName = CertUtils.CertPath("dpsCa.pem");
            File.WriteAllText(fileName, dpsCaPEM);
            Console.WriteLine($"Exported {fileName}");

            var dpsIntermediate1PEM = iec.PemExportPublicKeyCertificate(dpsIntermediate1);
            fileName = CertUtils.CertPath("dpsIntermediate1.pem");
            File.WriteAllText(fileName, dpsIntermediate1PEM);
            Console.WriteLine($"Exported {fileName}");

            var dpsIntermediate2PEM = iec.PemExportPublicKeyCertificate(dpsIntermediate2);
            fileName = CertUtils.CertPath("dpsIntermediate2.pem");
            File.WriteAllText(fileName, dpsIntermediate2PEM);
            Console.WriteLine($"Exported {fileName}");
            
            Console.WriteLine("Certificates exported to pfx and pem files");
        }
    }
}
