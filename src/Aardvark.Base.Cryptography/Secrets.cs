using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Aardvark.Base.Cryptography;

public interface IPlainData
{
    Stream GetReadStream();
}

public interface IEncryptedData
{
    Stream GetReadStream();
    Stream GetWriteStream();
}

public interface IDecryptedData
{
    Stream GetWriteStream();
}

public class PlainStream : IPlainData
{
    private readonly Stream _value;
    private bool _isConsumed;
    
    public PlainStream(Stream value)
    {
        _value = value;
        _isConsumed = false;
    }
    
    public Stream GetReadStream()
    {
        lock (_value)
        {
            if (_isConsumed) throw new Exception("Already consumed. Error 5dacedaf-df4e-4ef7-a12a-2e65b5657f69.");
            _isConsumed = true;
            return _value;
        }
    }
}

public class PlainBuffer : IPlainData
{
    private readonly byte[] _value;

    public PlainBuffer(byte[] value)
    {
        _value = value;
    }

    public Stream GetReadStream() => new MemoryStream(_value);
}

public class PlainString : IPlainData
{
    private readonly string _value;

    public PlainString(string value)
    {
        _value = value;
    }

    public Stream GetReadStream() => new MemoryStream(Encoding.UTF8.GetBytes(_value));
}

public class EncryptedStream : IEncryptedData
{
    private readonly object _lock = new();
    private readonly Stream _value;
    private bool _isConsumed;

    public EncryptedStream(Stream value)
    {
        _value = value;
        _isConsumed = false;
    }

    public Stream GetReadStream()
    {
        lock (_lock)
        {
            if (_isConsumed) throw new Exception("Already consumed. Error 9dfab973-6b39-4480-8977-678a49f9d8a3.");
            _isConsumed = true;
            return _value;
        }
    }

    public Stream GetWriteStream()
    {
        lock (_lock)
        {
            if (_isConsumed) throw new Exception("Already consumed. Error aff5af4b-e553-47fc-bf83-d7e6b9ce68cd.");
            _isConsumed = true;
            return _value;
        }
    }
}

public class EncryptedBuffer : IEncryptedData
{
    private readonly MemoryStream _value = new();
    private bool _isWritten = false;

    public Stream GetReadStream()
    {
        if (!_isWritten) throw new Exception("Buffer has not yet been written. Error f2e57d9b-4b80-49be-a66c-d2cd17118d99.");
        _value.Position = 0;
        return _value;
    }

    public Stream GetWriteStream()
    {
        _isWritten = true;
        return _value;
    }
}

public class EncryptedFile : IEncryptedData
{
    private readonly string _filename;

    public EncryptedFile(string filename)
    {
        _filename = filename;
    }

    public Stream GetReadStream() => File.Open(_filename, FileMode.Open, FileAccess.Read, FileShare.Read);
    public Stream GetWriteStream() => File.Open(_filename, FileMode.OpenOrCreate, FileAccess.Write, FileShare.None);
}

public class EncryptedLocalAppDataFile : IEncryptedData
{
    private readonly string _appName;
    private readonly string _fileName;

    public EncryptedLocalAppDataFile(string appName, string fileName)
    {
        if (string.IsNullOrWhiteSpace(appName)) throw new Exception(
            $"Target app name must not be empty. Error 3dbce0ed-1ea5-4008-96c0-cbba5b4d1fe1."
            );

        if (string.IsNullOrWhiteSpace(fileName)) throw new Exception(
            $"Target file name must not be empty. Error 3045f823-8001-4747-a0dd-00fb4187bb4b."
            );

        if (Path.IsPathRooted(appName)) throw new Exception(
            $"Target app name must not be an absolute path, but is \"{appName}\". " +
            $"Error 0267aaff-58a2-43b8-8525-1392f566f671."
            );

        if (Path.IsPathRooted(fileName)) throw new Exception(
            $"Target file name must not be an absolute path, but is \"{fileName}\". " +
            $"Error 437ea637-377e-414f-90be-c05f9c0ee00a."
            );

        _appName = appName;
        _fileName = fileName;
    }

    public Stream GetReadStream()
    {
        var basePath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.Create);
        var path = Path.Combine(basePath, _appName, _fileName);
        var dir = Path.GetDirectoryName(path);
        if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);

        return File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read);
    }

    public Stream GetWriteStream()
    {
        var basePath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.Create);
        var path = Path.Combine(basePath, _appName, _fileName);
        var dir = Path.GetDirectoryName(path);
        if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);

        return File.Open(path, FileMode.OpenOrCreate, FileAccess.Write, FileShare.None);
    }
}

/// <summary>
/// Uses AES (Advanced Encryption Standard).
/// The encryption key is derived according to RFC 2898 (https://www.ietf.org/rfc/rfc2898.txt).
/// </summary>
public class Secrets
{
    public const int Version = 1;

    public static Task EncryptAsync(IPlainData source, IEncryptedData target, string password, int iterations = 1000)
    {
        using var sourceStream = source.GetReadStream();
        using var targetStream = target.GetWriteStream();
        return EncryptAsync(sourceStream, targetStream, password, iterations);
    }

    public static Task DecryptAsync(IEncryptedData source, IDecryptedData target, string password)
    {
        using var sourceStream = source.GetReadStream();
        using var targetStream = target.GetWriteStream();
        return DecryptAsync(sourceStream, targetStream, password);
    }

    #region Encrypt

    #region Stream

    /// <summary>
    /// Encrypt stream to stream.
    /// </summary>
    public static async Task EncryptAsync(Stream source, Stream target, string password, int iterations = 1000)
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
    /// Encrypt buffer to stream.
    /// </summary>
    public static Task EncryptAsync(byte[] source, Stream target, string password, int iterations = 1000)
    {
        using var sourceStream = new MemoryStream(source);
        return EncryptAsync(source: sourceStream, target, password, iterations);
    }

    /// <summary>
    /// Encrypt string to stream.
    /// </summary>
    public static Task EncryptAsync(string source, Stream target, string password, int iterations = 1000)
        => EncryptAsync(Encoding.UTF8.GetBytes(source), target, password, iterations);

    #endregion

    #region Buffer

    /// <summary>
    /// Encrypt stream to buffer.
    /// </summary>
    public static async Task<byte[]> EncryptToBufferAsync(Stream source, string password, int iterations = 1000)
    {
        var targetStream = new MemoryStream();
        await EncryptAsync(source, target: targetStream, password, iterations);
        return targetStream.ToArray();
    }

    /// <summary>
    /// Encrypt buffer to buffer.
    /// </summary>
    public static async Task<byte[]> EncryptToBufferAsync(byte[] source, string password, int iterations = 1000)
    {
        var targetStream = new MemoryStream();
        await EncryptAsync(source, targetStream, password, iterations);
        return targetStream.ToArray();
    }

    /// <summary>
    /// Encrypt string to buffer.
    /// </summary>
    public static async Task<byte[]> EncryptToBufferAsync(string source, string password, int iterations = 1000)
    {
        var targetStream = new MemoryStream();
        await EncryptAsync(source, targetStream, password, iterations);
        return targetStream.ToArray();
    }

    #endregion

    #region File

    /// <summary>
    /// Encrypt stream to a file.
    public static Task EncryptToFileAsync(Stream source, string targetFile, string password, int iterations = 1000)
    {
        using var targetStream = File.Open(targetFile, FileMode.Create, FileAccess.Write, FileShare.None);
        return EncryptAsync(source: source, target: targetStream, password: password, iterations: iterations);
    }

    /// <summary>
    /// Encrypt buffer to a file.
    /// </summary>
    public static Task EncryptToFileAsync(byte[] source, string targetFile, string password, int iterations = 1000)
    {
        using var targetStream = File.Open(targetFile, FileMode.Create, FileAccess.Write, FileShare.None);
        return EncryptAsync(source: source, target: targetStream, password: password, iterations: iterations);
    }

    /// <summary>
    /// Encrypt string to a file.
    /// </summary>
    public static Task EncryptToFileAsync(string source, string targetPath, string password, int iterations = 1000)
    {
        using var targetStream = File.Open(targetPath, FileMode.Create, FileAccess.Write, FileShare.None);
        return EncryptAsync(source: source, target: targetStream, password: password, iterations: iterations);
    }

    #endregion

    #region Local app data

    /// <summary>
    /// Encrypt stream to a local app data file.
    /// </summary>
    public static Task EncryptToLocalAppDataAsync(Stream source, string targetAppName, string targetFileName, string password, int iterations = 1000)
    {
        using var targetStream = GetLocalAppDataFileWriteStream(targetAppName: targetAppName, targetFileName: targetFileName);
        return EncryptAsync(source: source, target: targetStream, password: password, iterations: iterations);
    }

    /// <summary>
    /// Encrypt buffer to a local app data file.
    /// </summary>
    public static Task EncryptToLocalAppDataAsync(byte[] source, string targetAppName, string targetFileName, string password, int iterations = 1000)
    {
        using var targetStream = GetLocalAppDataFileWriteStream(targetAppName: targetAppName, targetFileName: targetFileName);
        return EncryptAsync(source: source, target: targetStream, password: password, iterations: iterations);
    }

    /// <summary>
    /// Encrypt string to a local app data file.
    /// </summary>
    public static async Task EncryptToLocalAppDataAsync(string source, string targetAppName, string targetFileName, string password, int iterations = 1000)
    {
        using var targetStream = GetLocalAppDataFileWriteStream(targetAppName: targetAppName, targetFileName: targetFileName);
        await EncryptAsync(source: source, target: targetStream, password: password, iterations: iterations);
    }

    private static Stream GetLocalAppDataFileWriteStream(string targetAppName, string targetFileName)
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
        var dir = Path.GetDirectoryName(path);
        if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);

        return File.Open(path, FileMode.Create, FileAccess.Write, FileShare.None);
    }

    #endregion

    #endregion

    #region Decrypt

    #region Stream

    /// <summary>
    /// Decrypt stream to stream.
    /// </summary>
    public static async Task DecryptAsync(Stream source, Stream target, string password)
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
    public static async Task<byte[]> DecryptToBufferAsync(Stream source, string password)
    {
        var target = new MemoryStream();
        await DecryptAsync(source, target, password);
        var result = target.ToArray();
        target.Close();
        return result;
    }

    /// <summary>
    /// Decrypt stream to string.
    /// </summary>
    public static async Task<string> DecryptToStringAsync(Stream source, string password)
        => Encoding.UTF8.GetString(await DecryptToBufferAsync(source, password));

    #endregion

    #region Buffer

    /// <summary>
    /// Decrypt buffer to stream.
    /// </summary>
    public static Task DecryptAsync(byte[] source, Stream target, string password)
    {
        using var sourceStream = new MemoryStream(source);
        return DecryptAsync(sourceStream, target, password);
    }

    /// <summary>
    /// Decrypt buffer to buffer.
    /// </summary>
    public static Task<byte[]> DecryptToBufferAsync(byte[] source, string password)
    {
        using var sourceStream = new MemoryStream(source);
        return DecryptToBufferAsync(sourceStream, password);
    }

    /// <summary>
    /// Decrypt buffer to string.
    /// </summary>
    public static async Task<string> DecryptToStringAsync(byte[] source, string password)
    {
        using var sourceStream = new MemoryStream(source);
        return Encoding.UTF8.GetString(await DecryptToBufferAsync(sourceStream, password));
    }

    #endregion

    #region File

    /// <summary>
    /// Decrypt file to stream.
    /// </summary>
    public static Task DecryptFileAsync(string sourceFile, Stream target, string password)
    {
        using var source = File.Open(sourceFile, FileMode.Open, FileAccess.Read, FileShare.Read);
        return DecryptAsync(source, target, password);
    }

    /// <summary>
    /// Decrypt file to buffer.
    /// </summary>
    public static Task<byte[]> DecryptFileToBufferAsync(string sourceFile, string password)
    {
        using var source = File.Open(sourceFile, FileMode.Open, FileAccess.Read, FileShare.Read);
        return DecryptToBufferAsync(source, password);
    }

    /// <summary>
    /// Decrypt file to string.
    /// </summary>
    public static async Task<string> DecryptFileToStringAsync(string sourceFile, string password)
    {
        using var source = File.Open(sourceFile, FileMode.Open, FileAccess.Read, FileShare.Read);
        return await DecryptToStringAsync(source, password);
    }

    #endregion

    #region Local app data

    /// <summary>
    /// Decrypt file in local app data to stream.
    /// </summary>
    public static Task DecryptLocalAppDataAsync(string sourceAppName, string sourceFileName, Stream target, string password)
    {
        using var source = GetLocalAppDataFileReadStream(sourceAppName, sourceFileName);
        return DecryptAsync(source, target, password);
    }

    /// <summary>
    /// Decrypt file in local app data to buffer.
    /// </summary>
    public static Task<byte[]> DecryptLocalAppDataToBufferAsync(string sourceAppName, string sourceFileName, string password)
    {
        using var source = GetLocalAppDataFileReadStream(sourceAppName, sourceFileName);
        return DecryptToBufferAsync(source, password);
    }

    /// <summary>
    /// Decrypt file in local app data to string.
    /// </summary>
    public static Task<string> DecryptLocalAppDataToStringAsync(string sourceAppName, string sourceFileName, string password)
    {
        var source = GetLocalAppDataFileReadStream(sourceAppName, sourceFileName);
        var result = DecryptToStringAsync(source, password);
        source.Close();
        return result;
    }

    /// <summary>
    /// Delete encrypted file in local app data.
    /// </summary>
    public static void DeleteFromLocalAppDataAsync(string appName, string fileName)
    {
        if (string.IsNullOrWhiteSpace(appName)) throw new Exception($"App name must not be empty. Error a82f65b1-b3e2-4c99-a44d-7b64949b2945.");
        if (string.IsNullOrWhiteSpace(fileName)) throw new Exception($"File name must not be empty. Error eae048f7-1871-4ed3-a5ba-426dc5189683.");

        var basePath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.Create);
        var path = Path.Combine(basePath, appName, fileName);

        if (File.Exists(path)) File.Delete(path);
    }

    private static Stream GetLocalAppDataFileReadStream(string sourceAppName, string sourceFileName)
    {
        if (string.IsNullOrWhiteSpace(sourceAppName)) throw new Exception(
            $"Target app name must not be empty. Error 25b07fc3-1d73-4d9e-9944-ec8bc9a5e9f3."
            );

        if (string.IsNullOrWhiteSpace(sourceFileName)) throw new Exception(
            $"Target file name must not be empty. Error 89808258-ee6a-4d3c-bf6f-67093deff377."
            );

        if (Path.IsPathRooted(sourceAppName)) throw new Exception(
            $"Target app name must not be an absolute path, but is \"{sourceAppName}\". " +
            $"Error 4dd314b1-f42a-45ff-9da3-788b7d0f85ef."
            );

        if (Path.IsPathRooted(sourceFileName)) throw new Exception(
            $"Target file name must not be an absolute path, but is \"{sourceFileName}\". " +
            $"Error 52ec202d-0387-469d-805e-6af43d6a990c."
            );

        var basePath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.Create);
        var path = Path.Combine(basePath, sourceAppName, sourceFileName);

        return File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read);
    }

    #endregion

    #endregion
}
