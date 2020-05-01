# Running on Linux
1. cd SomeFolderWhereYouWillRun
1. rm AzureIoTHubDps -r -f
2. git clone https://github.com/BillBaird/AzureIoTHubDps
3. cd AzureIoTHubDps
4. dotnet publish -p:DefineConstants="NETSTANDARD2_0" -c Debug -o ./Publish
5. cd Publish
6. \# Actually run it
 <br />
   ./CertsCreateChained/bin/Debug/netcoreapp3.1/CertsCreateChained
7. ls   
8. openssl x509 -inform der -in SB\ Dev\ Certificate\ Authority.cer -noout -text
9. openssl x509 -inform p12 -in Intermediate\ 1.pfx -noout -text
<br />
   (Note that this will prompt for a "pass phrase", although it does not appear to work)
10. ./CertsCreateDeviceCertificate/bin/Debug/netcoreapp3.1/CertsCreateDeviceCertificate


openssl pkcsF12 -in Intermediate\ 1.pfx