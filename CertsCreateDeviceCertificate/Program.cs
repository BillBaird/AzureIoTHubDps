using CertificateManager;
using CertificateManager.Models;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertsCreateDeviceCertificate
{
    /// <summary>
    /// https://docs.microsoft.com/en-us/azure/iot-hub/iot-hub-security-x509-get-started
    /// </summary>
    class Program
    {
        static string directory = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location);
        static string pathToCerts = $"{directory}/../../../../Certs/";

        static string CertPath(string fileName)
            => Path.GetFullPath(Path.Combine(pathToCerts, fileName));
        
        const string RSA = "1.2.840.113549.1.1.1";
        const string DSA = "1.2.840.10040.4.1";
        const string ECC = "1.2.840.10045.2.1";
        static void Main(string[] args)
        {
            var serviceProvider = new ServiceCollection()
                .AddCertificateManager()
                .BuildServiceProvider();

            var createClientServerAuthCerts = serviceProvider.GetService<CreateCertificatesClientServerAuth>();
            var iec = serviceProvider.GetService<ImportExportCertificate>();

            var fileName = CertPath("dpsIntermediate1.pfx");
            Console.WriteLine($"Importing {fileName}");
            var intermediate = new X509Certificate2(fileName, "1234");
            Console.WriteLine($"Imported  {fileName}");

            Console.WriteLine($"Has Private Key = {intermediate.HasPrivateKey}");
            Console.WriteLine($"PublicKey OID = {intermediate.PublicKey.Oid.Value}");
            switch (intermediate.PublicKey.Oid.Value) {
                case RSA:
            RSA_Label:
                    RSA rsa = intermediate.GetRSAPrivateKey(); // or cert.GetRSAPublicKey() when need public key
                    Console.WriteLine($"Got RSA PrivateKey = {rsa}, SignatureAlgorithm = {rsa.SignatureAlgorithm}, KeyExchangeAlgorithm = {rsa.KeyExchangeAlgorithm}, KeySize = {rsa.KeySize}");
                    // use the key
                    break;
                case DSA:
                    DSA dsa = intermediate.GetDSAPrivateKey(); // or cert.GetDSAPublicKey() when need public key
                    Console.WriteLine($"Got DSA PrivateKey = {dsa}, SignatureAlgorithm = {dsa.SignatureAlgorithm}, KeyExchangeAlgorithm = {dsa.KeyExchangeAlgorithm}, KeySize = {dsa.KeySize}");
                    // use the key
                    break;
                case ECC:
                    ECDsa ecc = intermediate.GetECDsaPrivateKey(); // or cert.GetECDsaPublicKey() when need public key
                    if (ecc == null)
                    {
                        Console.WriteLine("ecc was null, will do RSA");
                        goto RSA_Label;
                    }
                    Console.WriteLine($"Got ECC PrivateKey = {ecc}, SignatureAlgorithm = {ecc.SignatureAlgorithm}, KeyExchangeAlgorithm = {ecc.KeyExchangeAlgorithm}, KeySize = {ecc.KeySize}");
                    // use the key
                    break;
            }

            var device = createClientServerAuthCerts.NewDeviceChainedCertificate(
                new DistinguishedName { CommonName = "testdevice01" },
                new ValidityPeriod { ValidFrom = DateTime.UtcNow, ValidTo = DateTime.UtcNow.AddYears(10) },
                "testdevice01", intermediate);
            //device.FriendlyName = "IoT device testdevice01";
      
            string password = "1234";
            var importExportCertificate = serviceProvider.GetService<ImportExportCertificate>();

            var deviceInPfxBytes = importExportCertificate.ExportChainedCertificatePfx(password, device, intermediate);
            fileName = CertPath("testdevice01.pfx");
            File.WriteAllBytes(fileName, deviceInPfxBytes);
            Console.WriteLine($"Exported {fileName}");

            var devicePEM = iec.PemExportPublicKeyCertificate(device);
            fileName = CertPath("testdevice01.pem");
            File.WriteAllText(fileName, devicePEM);
            Console.WriteLine($"Exported {fileName}");

   

        }
    }
}
