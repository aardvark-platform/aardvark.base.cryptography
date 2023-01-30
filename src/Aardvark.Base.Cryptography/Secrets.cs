using System;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Aardvark.Base.Cryptography;

/// <summary>
/// Uses AES (Advanced Encryption Standard).
/// The encryption key is derived according to RFC 2898 (https://www.ietf.org/rfc/rfc2898.txt).
/// </summary>
public class Secrets
{
    public const int Version = 1;

    private static Stream GetFileWriteStream(string targetFile)
    {
        var dir = Path.GetDirectoryName(targetFile);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
        return File.Open(targetFile, FileMode.Create, FileAccess.Write, FileShare.None);
    }

    private static Stream GetFileReadStream(string sourceFile)
    {
        return File.Open(sourceFile, FileMode.Open, FileAccess.Read, FileShare.Read);
    }

    public static string GetLocalAppDataFilePath(string targetAppName, string targetFileName)
    {
        if (string.IsNullOrWhiteSpace(targetAppName)) throw new Exception(
            $"Target app name must not be empty. Error 77593c2a-f40f-466b-90e7-f3f75c78c04b."
            );

        if (string.IsNullOrWhiteSpace(targetFileName)) throw new Exception(
            $"Target file name must not be empty. Error e33cf901-4fa8-4ec5-971b-8452de3488b5."
            );

        if (Path.IsPathRooted(targetAppName)) throw new Exception(
            $"Target app name must not be an absolute path, but is \"{targetAppName}\". " +
            $"Error af4d1af7-9d0d-46bd-b09d-ddde05a629d7."
            );

        if (Path.IsPathRooted(targetFileName)) throw new Exception(
            $"Target file name must not be an absolute path, but is \"{targetFileName}\". " +
            $"Error 9ca126fb-a697-483f-b081-36b90372ae3b."
            );

        var basePath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.Create);
        var path = Path.Combine(basePath, targetAppName, targetFileName);
        return path;
    }

    #region Encrypt

    /// <summary>
    /// Encrypt stream to stream.
    /// </summary>
    public static async Task EncryptStreamToStreamAsync(Stream source, Stream target, string password, int iterations = 1000)
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
        writeInt(Version);
        writeInt(iterations);
        writeBuffer(salt);
        writeBuffer(encAlg.IV);

        // write encrypted data
        using var encrypt = new CryptoStream(target, encAlg.CreateEncryptor(), CryptoStreamMode.Write);
        await source.CopyToAsync(encrypt);
        encrypt.FlushFinalBlock();
        encrypt.Clear();

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        void writeBuffer(byte[] buffer)
        {
            var size = BitConverter.GetBytes(buffer.Length);
            target.Write(size, 0, size.Length);
            target.Write(buffer, 0, buffer.Length);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        void writeInt(int x)
        {
            var buffer = BitConverter.GetBytes(x);
            target.Write(buffer, 0, buffer.Length);
        }
    }

    /// <summary>
    /// Encrypt stream to buffer.
    /// </summary>
    public static async Task<byte[]> EncryptStreamToBufferAsync(Stream source, string password, int iterations = 1000)
    {
        var targetStream = new MemoryStream();
        await EncryptStreamToStreamAsync(source, targetStream, password, iterations);
        var result = targetStream.ToArray();
        targetStream.Dispose();
        return result;
    }

    /// <summary>
    /// Encrypt stream to a file.
    public static async Task EncryptStreamToFileAsync(Stream source, string targetFile, string password, int iterations = 1000)
    {
        var targetStream = GetFileWriteStream(targetFile);
        await EncryptStreamToStreamAsync(source, targetStream, password, iterations);
        targetStream.Dispose();
    }



    /// <summary>
    /// Encrypt buffer to stream.
    /// </summary>
    public static async Task EncryptBufferToStreamAsync(byte[] source, Stream target, string password, int iterations = 1000)
    {
        var sourceStream = new MemoryStream(source);
        await EncryptStreamToStreamAsync(source: sourceStream, target, password, iterations);
        sourceStream.Dispose();
    }

    /// <summary>
    /// Encrypt buffer to buffer.
    /// </summary>
    public static async Task<byte[]> EncryptBufferToBufferAsync(byte[] source, string password, int iterations = 1000)
    {
        var sourceStream = new MemoryStream(source);
        var targetStream = new MemoryStream();
        await EncryptStreamToStreamAsync(sourceStream, targetStream, password, iterations);
        var result = targetStream.ToArray();
        sourceStream.Dispose();
        targetStream.Dispose();
        return result;
    }

    /// <summary>
    /// Encrypt buffer to a file.
    /// </summary>
    public static async Task EncryptBufferToFileAsync(byte[] source, string targetFile, string password, int iterations = 1000)
    {
        var sourceStream = new MemoryStream(source);
        var targetStream = GetFileWriteStream(targetFile);
        await EncryptStreamToStreamAsync(sourceStream, targetStream, password, iterations);
        sourceStream.Dispose();
        targetStream.Dispose();
    }



    /// <summary>
    /// Encrypt string to stream.
    /// </summary>
    public static async Task EncryptStringToStreamAsync(string source, Stream target, string password, int iterations = 1000)
    {
        var sourceStream = new MemoryStream(Encoding.UTF8.GetBytes(source));
        await EncryptStreamToStreamAsync(sourceStream, target, password, iterations);
        sourceStream.Dispose();
    }

    /// <summary>
    /// Encrypt string to buffer.
    /// </summary>
    public static async Task<byte[]> EncryptStringToBufferAsync(string source, string password, int iterations = 1000)
    {
        var sourceStream = new MemoryStream(Encoding.UTF8.GetBytes(source));
        var targetStream = new MemoryStream();
        await EncryptStreamToStreamAsync(sourceStream, targetStream, password, iterations);
        var result = targetStream.ToArray();
        sourceStream.Dispose();
        targetStream.Dispose();
        return result;
    }

    /// <summary>
    /// Encrypt string to a file.
    /// </summary>
    public static async Task EncryptStringToFileAsync(string source, string targetFile, string password, int iterations = 1000)
    {
        var sourceStream = new MemoryStream(Encoding.UTF8.GetBytes(source));
        var targetStream = GetFileWriteStream(targetFile);
        await EncryptStreamToStreamAsync(sourceStream, targetStream, password, iterations);
        sourceStream.Dispose();
        targetStream.Dispose();
    }



    /// <summary>
    /// Encrypt file to stream.
    /// </summary>
    public static async Task EncryptFileToStreamAsync(string sourceFile, Stream target, string password, int iterations = 1000)
    {
        var sourceStream = GetFileReadStream(sourceFile);
        await EncryptStreamToStreamAsync(source: sourceStream, target, password, iterations);
        sourceStream.Dispose();
    }

    /// <summary>
    /// Encrypt file to buffer.
    /// </summary>
    public static async Task<byte[]> EncryptFileToBufferAsync(string sourceFile, string password, int iterations = 1000)
    {
        var sourceStream = GetFileReadStream(sourceFile);
        var targetStream = new MemoryStream();
        await EncryptStreamToStreamAsync(sourceStream, targetStream, password, iterations);
        var result = targetStream.ToArray();
        sourceStream.Dispose();
        targetStream.Dispose();
        return result;
    }

    /// <summary>
    /// Encrypt file to a file.
    /// </summary>
    public static async Task EncryptFileToFileAsync(string sourceFile, string targetFile, string password, int iterations = 1000)
    {
        var sourceStream = GetFileReadStream(sourceFile);
        var targetStream = GetFileWriteStream(targetFile);
        await EncryptStreamToStreamAsync(sourceStream, targetStream, password, iterations);
        sourceStream.Dispose();
        targetStream.Dispose();
    }

    #endregion

    #region Decrypt

    /// <summary>
    /// Decrypt stream to stream.
    /// </summary>
    public static async Task DecryptStreamToStreamAsync(Stream source, Stream target, string password)
    {
        password ??= "";

        // read header
        var version = readInt();
        if (version != Version) throw new Exception(
            $"Invalid version. Expected {Version} but found {version}. " +
            $"Error 122ab4bb-44fc-49bd-8ff8-67e4dc19a43e."
            );
        var iterations = readInt();
        var salt = readBuffer();
        var iv = readBuffer();

        // regenerate key
        var key = new Rfc2898DeriveBytes(password, salt, iterations);

        // decrypt data
        var decAlg = Aes.Create();
        decAlg.Key = key.GetBytes(16);
        decAlg.IV = iv;
        using var decrypt = new CryptoStream(target, decAlg.CreateDecryptor(), CryptoStreamMode.Write);
        await source.CopyToAsync(decrypt);
        decrypt.Flush();
        decrypt.Clear();

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        byte[] read(int count)
        {
            var buffer = new byte[count];
            var offset = 0;
            var remaining = count;
            while (remaining > 0)
            {
                var readcount = source.Read(buffer, offset, remaining);
                offset += readcount;
                remaining -= readcount;
            }
            return buffer;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        int readInt() => BitConverter.ToInt32(read(4), 0);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        byte[] readBuffer() => read(readInt());
    }

    /// <summary>
    /// Decrypt stream to buffer.
    /// </summary>
    public static async Task<byte[]> DecryptStreamToBufferAsync(Stream source, string password)
    {
        var targetStream = new MemoryStream();
        await DecryptStreamToStreamAsync(source, targetStream, password);
        var result = targetStream.ToArray();
        targetStream.Close();
        return result;
    }

    /// <summary>
    /// Decrypt stream to string.
    /// </summary>
    public static async Task<string> DecryptStreamToStringAsync(Stream source, string password)
        => Encoding.UTF8.GetString(await DecryptStreamToBufferAsync(source, password));

    /// <summary>
    /// Decrypt stream to file.
    /// </summary>
    public static Task DecryptStreamToFileAsync(Stream source, string targetFile, string password)
    {
        using var targetStream = GetFileWriteStream(targetFile);
        return DecryptStreamToStreamAsync(source, targetStream, password);
    }

    /// <summary>
    /// Decrypt buffer to stream.
    /// </summary>
    public static Task DecryptBufferToStreamAsync(byte[] source, Stream target, string password)
    {
        using var sourceStream = new MemoryStream(source);
        return DecryptStreamToStreamAsync(sourceStream, target, password);
    }

    /// <summary>
    /// Decrypt buffer to buffer.
    /// </summary>
    public static Task<byte[]> DecryptBufferToBufferAsync(byte[] source, string password)
    {
        using var sourceStream = new MemoryStream(source);
        return DecryptStreamToBufferAsync(sourceStream, password);
    }

    /// <summary>
    /// Decrypt buffer to string.
    /// </summary>
    public static async Task<string> DecryptBufferToStringAsync(byte[] source, string password)
    {
        using var sourceStream = new MemoryStream(source);
        return Encoding.UTF8.GetString(await DecryptStreamToBufferAsync(sourceStream, password));
    }

    /// <summary>
    /// Decrypt buffer to file.
    /// </summary>
    public static Task DecryptBufferToFileAsync(byte[] source, string targetFile, string password)
    {
        using var sourceStream = new MemoryStream(source);
        using var targetStream = GetFileWriteStream(targetFile);
        return DecryptStreamToStreamAsync(sourceStream, targetStream, password);
    }



    /// <summary>
    /// Decrypt file to stream.
    /// </summary>
    public static Task DecryptFileToStreamAsync(string sourceFile, Stream target, string password)
    {
        using var sourceStream = GetFileReadStream(sourceFile);
        return DecryptStreamToStreamAsync(sourceStream, target, password);
    }

    /// <summary>
    /// Decrypt file to buffer.
    /// </summary>
    public static Task<byte[]> DecryptFileToBufferAsync(string sourceFile, string password)
    {
        using var sourceStream = GetFileReadStream(sourceFile);
        return DecryptStreamToBufferAsync(sourceStream, password);
    }

    /// <summary>
    /// Decrypt file to string.
    /// </summary>
    public static async Task<string> DecryptFileToStringAsync(string sourceFile, string password)
    {
        using var sourceStream = GetFileReadStream(sourceFile);
        return await DecryptStreamToStringAsync(sourceStream, password);
    }

    /// <summary>
    /// Decrypt file to file.
    /// </summary>
    public static Task DecryptFileToFileAsync(string sourceFile, string targetFile, string password)
    {
        using var sourceStream = GetFileReadStream(sourceFile);
        using var targetStream = GetFileWriteStream(targetFile);
        return DecryptStreamToStreamAsync(sourceStream, targetStream, password);
    }

    #endregion
}
