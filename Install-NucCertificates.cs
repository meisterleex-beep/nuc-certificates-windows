using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;

internal static class Program
{
    private const string Root = "Russian_Trusted_Root_CA.cer";
    private const string Sub2022 = "Russian_Trusted_Sub_CA.cer";
    private const string Sub2024 = "Russian_Trusted_Sub_CA_2024.cer";

    private static int Main(string[] args)
    {
        Console.OutputEncoding = new UTF8Encoding(false);
        bool interactive = args.Length == 0 && !Console.IsInputRedirected;
        try
        {
            if (args.Length == 1 && (args[0] == "--help" || args[0] == "-h"))
            {
                Console.WriteLine("Install-NucCertificates.exe [--install | --check] [--machine]");
                Console.WriteLine("По умолчанию устанавливает TLS-сертификаты НУЦ для текущего пользователя.");
                Console.WriteLine("--check проверяет наличие без установки. --machine выбирает хранилища компьютера.");
                return 0;
            }

            if (args.Length > 2 || args.Distinct().Count() != args.Length ||
                args.Any(arg => arg != "--install" && arg != "--check" && arg != "--machine") ||
                (args.Contains("--install") && args.Contains("--check")))
            {
                Console.Error.WriteLine("Недопустимые параметры. Справка доступна через --help.");
                return 1;
            }

            bool install = !args.Contains("--check");
            StoreLocation location = args.Contains("--machine") ? StoreLocation.LocalMachine : StoreLocation.CurrentUser;
            if (install && location == StoreLocation.LocalMachine)
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                        throw new InvalidOperationException("Для --machine запустите терминал от имени администратора.");
                }
            }

            Console.WriteLine("{0} TLS-сертификатов НУЦ Минцифры ({1})", install ? "Установка" : "Проверка", location);
            return ProcessCertificates(location, install);
        }
        catch (Exception error)
        {
            Console.Error.WriteLine("Ошибка. " + error.Message);
            return 1;
        }
        finally
        {
            if (interactive)
            {
                Console.WriteLine("Нажмите Enter, чтобы закрыть окно.");
                Console.ReadLine();
            }
        }
    }

    private static int ProcessCertificates(StoreLocation location, bool install)
    {
        using (X509Certificate2 root = Load(Root, "D26D2D0231B7C39F92CC738512BA54103519E4405D68B5BD703E9788CA8ECF31"))
        using (X509Certificate2 sub2022 = Load(Sub2022, "BBBDE2103E790B999EC62BD03CF625A5A2E7C316E10AFE6A490EEDEAD8B3FD9B"))
        using (X509Certificate2 sub2024 = Load(Sub2024, "2155785036C900DBB5F1BB2A1569C80C55595BD6BF94867A29BBDDBC7D88A3F2"))
        using (var roots = new X509Store(StoreName.Root, location))
        using (var intermediates = new X509Store(StoreName.CertificateAuthority, location))
        {
            DateTime now = DateTime.UtcNow;
            if (!IsValidAt(root, now))
                throw new InvalidOperationException("Корневой сертификат вне срока действия. Проверьте системное время и актуальность комплекта.");
            if (!IsValidAt(sub2022, now) && !IsValidAt(sub2024, now))
                throw new InvalidOperationException("Оба выпускающих сертификата вне срока действия. Проверьте системное время и актуальность комплекта.");

            OpenFlags access = install ? OpenFlags.ReadWrite : OpenFlags.ReadOnly;
            roots.Open(access | OpenFlags.OpenExistingOnly);
            intermediates.Open(access | OpenFlags.OpenExistingOnly);

            // Add the root after the intermediates so a failed intermediate import does not add trust.
            bool has2022 = ProcessCertificate(intermediates, sub2022, Sub2022, now, install);
            bool has2024 = ProcessCertificate(intermediates, sub2024, Sub2024, now, install);
            bool hasRoot = ProcessCertificate(roots, root, Root, now, install);
            return hasRoot && has2022 && has2024 ? 0 : 2;
        }
    }

    private static X509Certificate2 Load(string name, string expectedHash)
    {
        using (Stream resource = Assembly.GetExecutingAssembly().GetManifestResourceStream(name))
        using (var buffer = new MemoryStream())
        using (SHA256 sha256 = SHA256.Create())
        {
            if (resource == null)
                throw new InvalidDataException("Отсутствует встроенный сертификат " + name);
            resource.CopyTo(buffer);
            byte[] bytes = buffer.ToArray();
            string actual = BitConverter.ToString(sha256.ComputeHash(bytes)).Replace("-", "");
            if (actual != expectedHash)
                throw new InvalidDataException("Отпечаток SHA-256 не совпадает для " + name);
            return new X509Certificate2(bytes);
        }
    }

    private static bool IsValidAt(X509Certificate2 certificate, DateTime now)
    {
        return now >= certificate.NotBefore.ToUniversalTime() && now <= certificate.NotAfter.ToUniversalTime();
    }

    private static bool ProcessCertificate(X509Store store, X509Certificate2 certificate, string name, DateTime now, bool install)
    {
        string description = string.Format("{0}\\{1}  {2}", store.Location, store.Name, name);
        if (!IsValidAt(certificate, now))
        {
            Console.WriteLine("Пропущен (вне срока действия)  {0}", description);
            return true;
        }
        if (ContainsCertificate(store, certificate))
        {
            Console.WriteLine("Уже доступен  {0}", description);
            return true;
        }
        if (!install)
        {
            Console.WriteLine("Отсутствует   {0}", description);
            return false;
        }

        try
        {
            store.Add(certificate);
            if (!ContainsCertificate(store, certificate))
                throw new CryptographicException("Сертификат отсутствует после импорта.");
        }
        catch (CryptographicException error)
        {
            throw new InvalidOperationException(string.Format("Не удалось установить {0}. {1}", description, error.Message), error);
        }

        Console.WriteLine("Установлен    {0}", description);
        return true;
    }

    private static bool ContainsCertificate(X509Store store, X509Certificate2 certificate)
    {
        byte[] bytes = certificate.RawData;
        X509Certificate2Collection entries = store.Certificates;
        try
        {
            return entries.Cast<X509Certificate2>().Any(entry =>
                entry.Thumbprint == certificate.Thumbprint && entry.RawData.SequenceEqual(bytes));
        }
        finally
        {
            foreach (X509Certificate2 entry in entries)
                entry.Dispose();
        }
    }
}
