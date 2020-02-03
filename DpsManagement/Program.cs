﻿using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace DpsManagement
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var sp = GetServices();

            var dpsEnrollmentGroup = sp.GetService<DpsEnrollmentGroup>();
            var dpsEnrollmentCertificate = new X509Certificate2("dpsIntermediate2.pem");
            await dpsEnrollmentGroup.CreateDpsEnrollmentGroupAsync("dpsIntermediate2", dpsEnrollmentCertificate);

            var dpsRegisterDevice = sp.GetService<DpsRegisterDevice>();
            X509Certificate2 deviceCertificate = new X509Certificate2("testdevice02.pfx", "1234");
            X509Certificate2 enrollmentCertificate = new X509Certificate2("dpsIntermediate1.pfx", "1234");
            await dpsRegisterDevice.RegisterDeviceAsync(deviceCertificate, enrollmentCertificate);
        }

        private static ServiceProvider GetServices()
        {
            var serviceProvider = new ServiceCollection()
                .AddCertificateManager()
                .AddSingleton<IConfiguration>(GetConfig())
                .AddTransient<DpsRegisterDevice>()
                .AddTransient<DpsEnrollmentGroup>()
                .BuildServiceProvider();

            return serviceProvider;
        }

        private static IConfigurationRoot GetConfig()
        {
            var location = Assembly.GetEntryAssembly().Location;
            var directory = Path.GetDirectoryName(location);
            var config = new ConfigurationBuilder();

            config.AddJsonFile($"{directory}{Path.DirectorySeparatorChar}appsettings.json", optional: false, reloadOnChange: true)
                    .AddUserSecrets("6556e69f-ba37-48cb-aad5-643d5620c84b");

            var builder = config.Build();
            return builder;
        }
    }
}