using System.Text;
using System.Web;

namespace Aardvark.Base.Cryptography.Tests
{
    public class SecretsTests
    {
        private const string PWD = "a password";
        
        private static readonly string SRC_STRING = "This is my plain text.";
        private static readonly byte[] SRC_BUFFER = Encoding.UTF8.GetBytes(SRC_STRING);
        private static Stream SRC_STREAM => new MemoryStream(SRC_BUFFER);

        [Fact]
        public async Task RoundTrip_Stream_Stream_Stream()
        {
            var e0 = new MemoryStream();
            await Secrets.EncryptAsync(SRC_STREAM, e0, PWD);

            var e1 = new MemoryStream(e0.ToArray());
            var decryptedStream = new MemoryStream();
            await Secrets.DecryptAsync(e1, decryptedStream, PWD);

            var decrypted = Encoding.UTF8.GetString(decryptedStream.ToArray());
            Assert.True(SRC_STRING == decrypted);
        }

        [Fact]
        public async Task RoundTrip_String_Stream_String()
        {
            var e0 = new MemoryStream();
            await Secrets.EncryptAsync(SRC_STRING, e0, PWD);

            var e1 = new MemoryStream(e0.ToArray());
            var decrypted = await Secrets.DecryptToStringAsync(e1, PWD);

            Assert.True(SRC_STRING == decrypted);
        }

        [Fact]
        public async Task RoundTrip_String_Buffer_String()
        {
            var plaintext0 = "This is my plain text.";
            var password = "a password";

            var e = await Secrets.EncryptToBufferAsync(plaintext0, password);

            var plaintext1 = await Secrets.DecryptToStringAsync(e, password);

            Assert.True(plaintext0 == plaintext1);
        }

        [Fact]
        public async Task RoundTrip_String_File_String()
        {
            var plaintext0 = "This is my plain text.";
            var password = "a password";

            var path = Path.GetRandomFileName();

            try
            {
                await Secrets.EncryptToFileAsync(plaintext0, path, password);
                var exists = File.Exists(path);
                Assert.True(exists == true);
                var plaintext1 = await Secrets.DecryptFileToStringAsync(path, password);
                Assert.True(plaintext0 == plaintext1);
            }
            finally
            {
                File.Delete(path);
            }
        }

        [Fact]
        public async Task RoundTrip_String_LocalAppData_String()
        {
            var appname = "aardvark.base.cryptography_tests";
            var plaintext0 = "This is my plain text.";
            var password = "a password";

            var filename = Path.GetRandomFileName();

            try
            {
                await Secrets.EncryptToLocalAppDataAsync(plaintext0, appname, filename, password);
                var plaintext1 = await Secrets.DecryptLocalAppDataToStringAsync(appname, filename, password);
                Assert.True(plaintext0 == plaintext1);
            }
            finally
            {
                Secrets.DeleteFromLocalAppDataAsync(appname, filename);
            }
        }


        [Fact]
        public async Task RoundTrip_Buffer_Stream_Buffer()
        {
            var plaintext0 = "This is my plain text.";
            var password = "a password";

            var ms0 = new MemoryStream();
            await Secrets.EncryptAsync(Encoding.UTF8.GetBytes(plaintext0), ms0, password);

            var ms1 = new MemoryStream(ms0.ToArray());
            var plaintext1 = Encoding.UTF8.GetString(await Secrets.DecryptToBufferAsync(ms1, password));

            Assert.True(plaintext0 == plaintext1);
        }

        [Fact]
        public async Task RoundTrip_Buffer_Buffer_Buffer()
        {
            var plaintext0 = "This is my plain text.";
            var password = "a password";

            var buffer = await Secrets.EncryptToBufferAsync(Encoding.UTF8.GetBytes(plaintext0), password);
            var plaintext1 = Encoding.UTF8.GetString(await Secrets.DecryptToBufferAsync(buffer, password));

            Assert.True(plaintext0 == plaintext1);
        }

        [Fact]
        public async Task RoundTrip_Buffer_File_Buffer()
        {
            var plaintext0 = "This is my plain text.";
            var password = "a password";

            var path = Path.GetRandomFileName();

            try
            {
                await Secrets.EncryptToFileAsync(plaintext0, path, password);
                var exists = File.Exists(path);
                Assert.True(exists == true);
                var plaintext1 = await Secrets.DecryptFileToStringAsync(path, password);
                Assert.True(plaintext0 == plaintext1);
            }
            finally
            {
                File.Delete(path);
            }
        }

        [Fact]
        public async Task RoundTrip_Buffer_LocalAppData_Buffer()
        {
            var appname = "aardvark.base.cryptography_tests";
            var plaintext0 = "This is my plain text.";
            var password = "a password";

            var filename = Path.GetRandomFileName();

            try
            {
                await Secrets.EncryptToLocalAppDataAsync(plaintext0, appname, filename, password);
                var plaintext1 = await Secrets.DecryptLocalAppDataToStringAsync(appname, filename, password);
                Assert.True(plaintext0 == plaintext1);
            }
            finally
            {
                Secrets.DeleteFromLocalAppDataAsync(appname, filename);
            }
        }





        [Fact]
        public async Task RoundTrip_EmptyPassword_Success()
        {
            var plaintext0 = "This is my plain text.";
            var password = "";

            var e = await Secrets.EncryptToBufferAsync(plaintext0, password);

            var plaintext1 = await Secrets.DecryptToStringAsync(e, password);

            Assert.True(plaintext0 == plaintext1);
        }

        [Fact]
        public async Task RoundTrip_NullPassword_Success()
        {
            var plaintext0 = "This is my plain text.";
            var password = (string?)null;

            var e = await Secrets.EncryptToBufferAsync(plaintext0, password!);

            var plaintext1 = await Secrets.DecryptToStringAsync(e, password!);

            Assert.True(plaintext0 == plaintext1);
        }

        [Fact]
        public async Task RoundTrip_Fail_WrongSalt()
        {
            var plaintext0 = "This is my plain text.";
            var password = "a password";

            var e = await Secrets.EncryptToBufferAsync(plaintext0, password);

            e[8+4] ^= 1;

            try
            {
                var plaintext1 = await Secrets.DecryptToStringAsync(e, password);
                Assert.False(plaintext0 == plaintext1);
            }
            catch
            {
                Assert.True(true);
            }
        }

        [Fact]
        public async Task RoundTrip_Fail_WrongIV()
        {
            var plaintext0 = "This is my plain text.";
            var password = "a password";

            var e = await Secrets.EncryptToBufferAsync(plaintext0, password);

            e[8+(4+16)+4] ^= 1;

            try
            {
                var plaintext1 = await Secrets.DecryptToStringAsync(e, password);
                Assert.False(plaintext0 == plaintext1);
            }
            catch
            {
                Assert.True(true);
            }
        }

        [Fact]
        public async Task RoundTrip_Fail_WrongPassword()
        {
            var plaintext0 = "This is my plain text.";

            var e = await Secrets.EncryptToBufferAsync(plaintext0, "password0");

            try
            {
                var plaintext1 = await Secrets.DecryptToStringAsync(e, "password1");
                Assert.False(plaintext0 == plaintext1);
            }
            catch
            {
                Assert.True(true);
            }
        }

        [Fact]
        public async Task RoundTrip_Fail_WrongData()
        {
            var plaintext0 = "This is my plain text.";
            var password = "a password";

            var e = await Secrets.EncryptToBufferAsync(plaintext0, password);

            e[8 + (4 + 16) + (4 + 16)] ^= 1;

            try
            {
                var plaintext1 = await Secrets.DecryptToStringAsync(e, password);
                Assert.False(plaintext0 == plaintext1);
            }
            catch
            {
                Assert.True(true);
            }
        }

        [Fact]
        public async Task Roundtrip_UrlEncodedBase64()
        {
            var plaintext0 = "This is my plain text.";
            var password = "a password";

            // encrypt
            var e0 = await Secrets.EncryptToBufferAsync(plaintext0, password);

            // encode
            var encoded = HttpUtility.UrlEncode(Convert.ToBase64String(e0));

            // decode
            var e1 = Convert.FromBase64String(HttpUtility.UrlDecode(encoded));

            // decrypt
            var plaintext1 = await Secrets.DecryptToStringAsync(e1, password);

            Assert.True(plaintext0 == plaintext1);
        }
    }
}