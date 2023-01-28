using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Aardvark.Base.Cryptography;

public class Secrets
{
    public const int Version = 1;

    #region Encrypt

    #region Stream

    /// <summary>
    /// Encrypts data to stream.
    /// Uses AES (Advanced Encryption Standard).
    /// The encryption key is derived according to RFC 2898 (https://www.ietf.org/rfc/rfc2898.txt).
    /// </summary>
    public static async Task EncryptAsync(Stream stream, byte[] data, string password, int iterations = 1000)
    {
        password ??= "";

        // generate salt
        byte[] salt = new byte[16];
        using (var rng = RandomNumberGenerator.Create()) { rng.GetBytes(salt); }

        // generate key
        var key = new Rfc2898DeriveBytes(password, salt, iterations);

        // encrypt
        var encAlg = Aes.Create();
        encAlg.Key = key.GetBytes(16);

        // write header
        await writeInt(Version);
        await writeInt(iterations);
        await writeBuffer(salt);
        await writeBuffer(encAlg.IV);

        // write encrypted data
        var encrypt = new CryptoStream(stream, encAlg.CreateEncryptor(), CryptoStreamMode.Write);
        encrypt.Write(data, 0, data.Length);
        encrypt.FlushFinalBlock();
        encrypt.Close();

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        async Task writeBuffer(byte[] buffer)
        {
            var size = BitConverter.GetBytes(buffer.Length);
            await stream.WriteAsync(size, 0, size.Length);
            await stream.WriteAsync(buffer, 0, buffer.Length);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        async Task writeInt(int x)
        {
            var buffer = BitConverter.GetBytes(x);
            await stream.WriteAsync(buffer, 0, buffer.Length);
        }
    }

    /// <summary>
    /// Encrypts string to stream.
    /// Uses AES (Advanced Encryption Standard).
    /// The encryption key is derived according to RFC 2898 (https://www.ietf.org/rfc/rfc2898.txt).
    /// </summary>
    public static Task EncryptAsync(Stream stream, string data, string password, int iterations = 1000)
        => EncryptAsync(stream, Encoding.UTF8.GetBytes(data), password, iterations);

    #endregion

    #region Buffer

    /// <summary>
    /// Encrypts data to byte array.
    /// Uses AES (Advanced Encryption Standard).
    /// The encryption key is derived according to RFC 2898 (https://www.ietf.org/rfc/rfc2898.txt).
    /// </summary>
    public static async Task<byte[]> EncryptAsync(byte[] data, string password, int iterations = 1000)
    {
        var ms = new MemoryStream();
        await EncryptAsync(ms, data, password, iterations);
        return ms.ToArray();
    }

    /// <summary>
    /// Encrypts string to byte array.
    /// Uses AES (Advanced Encryption Standard).
    /// The encryption key is derived according to RFC 2898 (https://www.ietf.org/rfc/rfc2898.txt).
    /// </summary>
    public static async Task<byte[]> EncryptAsync(string data, string password, int iterations = 1000)
    {
        var ms = new MemoryStream();
        await EncryptAsync(ms, data, password, iterations);
        return ms.ToArray();
    }

    #endregion

    #region File

    /// <summary>
    /// Encrypts data to a file.
    /// Uses AES (Advanced Encryption Standard).
    /// The encryption key is derived according to RFC 2898 (https://www.ietf.org/rfc/rfc2898.txt).
    /// </summary>
    public static Task EncryptToFileAsync(string path, byte[] data, string password, int iterations = 1000)
    {
        using var f = File.Open(path, FileMode.Create, FileAccess.Write, FileShare.None);
        return EncryptAsync(stream: f, data: data, password: password, iterations: iterations);
    }

    /// <summary>
    /// Encrypts string to a file.
    /// Uses AES (Advanced Encryption Standard).
    /// The encryption key is derived according to RFC 2898 (https://www.ietf.org/rfc/rfc2898.txt).
    /// </summary>
    public static Task EncryptToFileAsync(string path, string data, string password, int iterations = 1000)
    {
        using var f = File.Open(path, FileMode.Create, FileAccess.Write, FileShare.None);
        return EncryptAsync(stream: f, data: data, password: password, iterations: iterations);
    }

    #endregion

    #region Local app data

    /// <summary>
    /// Encrypts data to a file in local app data.
    /// Uses AES (Advanced Encryption Standard).
    /// The encryption key is derived according to RFC 2898 (https://www.ietf.org/rfc/rfc2898.txt).
    /// </summary>
    public static Task EncryptToLocalAppDataAsync(string appName, string filename, byte[] data, string password, int iterations = 1000)
    {
        if (string.IsNullOrWhiteSpace(appName)) throw new Exception($"App name must not be empty. Error 4a2ebe49-8400-4f55-bbb8-02a910ee6778.");
        if (string.IsNullOrWhiteSpace(filename)) throw new Exception($"File name must not be empty. Error fae005d6-b41a-4316-9252-650e22515b10.");

        var basePath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.Create);
        var path = Path.Combine(basePath, appName, filename);
        var dir = Path.GetDirectoryName(path);
        if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);

        using var f = File.Open(path, FileMode.Create, FileAccess.Write, FileShare.None);
        return EncryptAsync(stream: f, data: data, password: password, iterations: iterations);
    }

    /// <summary>
    /// Encrypts data to a file in local app data.
    /// Uses AES (Advanced Encryption Standard).
    /// The encryption key is derived according to RFC 2898 (https://www.ietf.org/rfc/rfc2898.txt).
    /// </summary>
    public static async Task EncryptToLocalAppDataAsync(string appName, string filename, string data, string password, int iterations = 1000)
    {
        if (string.IsNullOrWhiteSpace(appName)) throw new Exception($"App name must not be empty. Error 77593c2a-f40f-466b-90e7-f3f75c78c04b.");
        if (string.IsNullOrWhiteSpace(filename)) throw new Exception($"File name must not be empty. Error e33cf901-4fa8-4ec5-971b-8452de3488b5.");

        var basePath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.Create);
        var path = Path.Combine(basePath, appName, filename);
        var dir = Path.GetDirectoryName(path);
        if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);

        using var f = File.Open(path, FileMode.Create, FileAccess.Write, FileShare.None);
        await EncryptAsync(stream: f, data: data, password: password, iterations: iterations);
    }

    #endregion

    #endregion

    #region Decrypt

    #region Stream

    /// <summary>
    /// Decrypts byte array from stream.
    /// Uses AES (Advanced Encryption Standard).
    /// The encryption key is derived according to RFC 2898 (https://www.ietf.org/rfc/rfc2898.txt).
    /// </summary>
    public static async Task<byte[]> DecryptAsync(Stream stream, string password)
    {
        password ??= "";

        // read header
        var version = await readInt();
        if (version != Version) throw new Exception(
            $"Invalid version. Expected {Version} but found {version}. " +
            $"Error 122ab4bb-44fc-49bd-8ff8-67e4dc19a43e."
            );
        var iterations = await readInt();
        var salt = await readBuffer();
        var iv = await readBuffer();

        // regenerate key
        var key = new Rfc2898DeriveBytes(password, salt, iterations);

        // decrypt data
        var decAlg = Aes.Create();
        decAlg.Key = key.GetBytes(16);
        decAlg.IV = iv;
        using var decryptionStreamBacking = new MemoryStream();
        var decrypt = new CryptoStream(decryptionStreamBacking, decAlg.CreateDecryptor(), CryptoStreamMode.Write);
        if (!stream.CanRead) throw new Exception("a");
        if (!decrypt.CanWrite) throw new Exception("b");
        await stream.CopyToAsync(decrypt);
        decrypt.Flush();
        decrypt.Close();
        key.Reset();

        return decryptionStreamBacking.ToArray();

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        async Task<byte[]> read(int count)
        {
            var buffer = new byte[count];
            var offset = 0;
            var remaining = count;
            while (remaining > 0)
            {
                var readcount = await stream.ReadAsync(buffer, offset, remaining);
                offset += readcount;
                remaining -= readcount;
            }
            return buffer;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        async Task<int> readInt() => BitConverter.ToInt32(await read(4), 0);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        async Task<byte[]> readBuffer() => await read(await readInt());
    }

    /// <summary>
    /// Decrypts string from stream.
    /// Uses AES (Advanced Encryption Standard).
    /// The encryption key is derived according to RFC 2898 (https://www.ietf.org/rfc/rfc2898.txt).
    /// </summary>
    public static async Task<string> DecryptStringAsync(Stream stream, string password)
        => Encoding.UTF8.GetString(await DecryptAsync(stream, password));

    #endregion
    
    #region Buffer

    /// <summary>
    /// Decrypts byte array.
    /// Uses AES (Advanced Encryption Standard).
    /// The encryption key is derived according to RFC 2898 (https://www.ietf.org/rfc/rfc2898.txt).
    /// </summary>
    public static Task<byte[]> DecryptAsync(byte[] buffer, string password)
    {
        using var ms = new MemoryStream(buffer);
        return DecryptAsync(ms, password);
    }

    /// <summary>
    /// Decrypts string from byte array.
    /// Uses AES (Advanced Encryption Standard).
    /// The encryption key is derived according to RFC 2898 (https://www.ietf.org/rfc/rfc2898.txt).
    /// </summary>
    public static async Task<string> DecryptStringAsync(byte[] buffer, string password)
    {
        using var ms = new MemoryStream(buffer);
        return Encoding.UTF8.GetString(await DecryptAsync(ms, password));
    }

    #endregion

    #region File

    /// <summary>
    /// Decrypts from a file.
    /// Uses AES (Advanced Encryption Standard).
    /// The encryption key is derived according to RFC 2898 (https://www.ietf.org/rfc/rfc2898.txt).
    /// </summary>
    public static Task<byte[]> DecryptFromFileAsync(string path, string password)
    {
        using var f = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return DecryptAsync(f, password);
    }

    /// <summary>
    /// Decrypts string from a file.
    /// Uses AES (Advanced Encryption Standard).
    /// The encryption key is derived according to RFC 2898 (https://www.ietf.org/rfc/rfc2898.txt).
    /// </summary>
    public static async Task<string> DecryptStringFromFileAsync(string path, string password)
    {
        var f = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var result = await DecryptStringAsync(f, password);
        f.Close();
        return result;
    }

    #endregion

    #region Local app data

    /// <summary>
    /// Decrypts from a file in local app data.
    /// Uses AES (Advanced Encryption Standard).
    /// The encryption key is derived according to RFC 2898 (https://www.ietf.org/rfc/rfc2898.txt).
    /// </summary>
    public static Task<byte[]> DecryptBufferFromLocalAppDataAsync(string appName, string filename, string password)
    {
        if (string.IsNullOrWhiteSpace(appName)) throw new Exception($"App name must not be empty. Error 1cd51d92-c248-40e1-a639-1687da379e1d.");
        if (string.IsNullOrWhiteSpace(filename)) throw new Exception($"File name must not be empty. Error 8af466ab-72c8-40c9-b65b-4a9fd6305a36.");

        var basePath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.Create);
        var path = Path.Combine(basePath, appName, filename);

        using var f = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return DecryptAsync(f, password);
    }

    /// <summary>
    /// Decrypts string from a file in local app data.
    /// Uses AES (Advanced Encryption Standard).
    /// The encryption key is derived according to RFC 2898 (https://www.ietf.org/rfc/rfc2898.txt).
    /// </summary>
    public static async Task<string> DecryptStringFromLocalAppDataAsync(string appName, string filename, string password)
    {
        if (string.IsNullOrWhiteSpace(appName)) throw new Exception($"App name must not be empty. Error a6019666-6481-40d1-a875-1e5ab36da64e.");
        if (string.IsNullOrWhiteSpace(filename)) throw new Exception($"File name must not be empty. Error 2bec330b-f1df-473e-802a-2ffeb9be26a6.");

        var basePath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.Create);
        var path = Path.Combine(basePath, appName, filename);

        var f = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var result = await DecryptStringAsync(f, password);
        f.Close();
        return result;
    }

    /// <summary>
    /// Deletes encrypted file in local app data.
    /// </summary>
    public static void DeleteFromLocalAppDataAsync(string appName, string filename)
    {
        if (string.IsNullOrWhiteSpace(appName)) throw new Exception($"App name must not be empty. Error a82f65b1-b3e2-4c99-a44d-7b64949b2945.");
        if (string.IsNullOrWhiteSpace(filename)) throw new Exception($"File name must not be empty. Error eae048f7-1871-4ed3-a5ba-426dc5189683.");

        var basePath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.Create);
        var path = Path.Combine(basePath, appName, filename);

        if (File.Exists(path)) File.Delete(path);
    }

    #endregion

    #endregion
}
