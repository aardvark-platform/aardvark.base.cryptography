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
        private static TestFile SRC_FILE
        {
            get
            {
                var f = new TestFile();
                File.WriteAllText(f.Path, SRC_STRING);
                return f;
            }
        }

        private static readonly byte[] ENCRYPTED_BUFFER = Secrets.EncryptStringToBufferAsync(SRC_STRING, PWD).Result;
        private static Stream ENCRYPTED_STREAM => new MemoryStream(ENCRYPTED_BUFFER);
        private static TestFile ENCRYPTED_FILE
        {
            get
            {
                var f = new TestFile();
                Secrets.EncryptStringToFileAsync(SRC_STRING, f.Path, PWD).Wait();
                return f;
            }
        }

        private static async Task CheckEncryptedAsync(MemoryStream encrypted)
        {
            var decrypted = await Secrets.DecryptBufferToStringAsync(encrypted.ToArray(), PWD);
            Assert.True(decrypted == SRC_STRING);
        }
        private static async Task CheckEncryptedAsync(byte[] encrypted)
        {
            var decrypted = await Secrets.DecryptBufferToStringAsync(encrypted, PWD);
            Assert.True(decrypted == SRC_STRING);
        }
        private static async Task CheckEncryptedAsync(TestFile encrypted)
        {
            var decrypted = await Secrets.DecryptFileToStringAsync(encrypted.Path, PWD);
            Assert.True(decrypted == SRC_STRING);
        }

        private static void CheckDecrypted(string decrypted)
        {
            Assert.True(decrypted == SRC_STRING);
        }
        private static void CheckDecryptedAsync(MemoryStream decrypted)
        {
            CheckDecrypted(decrypted.ToArray());
        }
        private static void CheckDecrypted(byte[] decrypted)
        {
            CheckDecrypted(Encoding.UTF8.GetString(decrypted));
        }
        private static void CheckDecrypted(TestFile decrypted)
        {
            var s = File.ReadAllText(decrypted.Path);
            Assert.True(s == SRC_STRING);
        }

        class TestFile : IDisposable
        {
            public string Path { get; } = System.IO.Path.GetRandomFileName();
            public void Dispose() => File.Delete(Path);
        }



        [Fact]
        public async Task EncryptStreamToX()
        {
            using var target0 = new MemoryStream();
            await Secrets.EncryptStreamToStreamAsync(SRC_STREAM, target0, PWD);
            await CheckEncryptedAsync(target0);

            var target1 = await Secrets.EncryptStreamToBufferAsync(SRC_STREAM, PWD);
            await CheckEncryptedAsync(target1);

            using var target2 = new TestFile();
            await Secrets.EncryptStreamToFileAsync(SRC_STREAM, target2.Path, PWD);
            await CheckEncryptedAsync(target2);
        }

        [Fact]
        public async Task EncryptBufferToX()
        {
            using var target0 = new MemoryStream();
            await Secrets.EncryptBufferToStreamAsync(SRC_BUFFER, target0, PWD);
            await CheckEncryptedAsync(target0);

            var target1 = await Secrets.EncryptBufferToBufferAsync(SRC_BUFFER, PWD);
            await CheckEncryptedAsync(target1);

            using var target2 = new TestFile();
            await Secrets.EncryptBufferToFileAsync(SRC_BUFFER, target2.Path, PWD);
            await CheckEncryptedAsync(target2);
        }

        [Fact]
        public async Task EncryptStringToX()
        {
            using var target0 = new MemoryStream();
            await Secrets.EncryptStringToStreamAsync(SRC_STRING, target0, PWD);
            await CheckEncryptedAsync(target0);

            var target1 = await Secrets.EncryptStringToBufferAsync(SRC_STRING, PWD);
            await CheckEncryptedAsync(target1);

            using var target2 = new TestFile();
            await Secrets.EncryptStringToFileAsync(SRC_STRING, target2.Path, PWD);
            await CheckEncryptedAsync(target2);
        }

        [Fact]
        public async Task EncryptFileToX()
        {
            using var source0 = SRC_FILE;
            using var target0 = new MemoryStream();
            await Secrets.EncryptFileToStreamAsync(source0.Path, target0, PWD);
            await CheckEncryptedAsync(target0);

            using var source1 = SRC_FILE;
            var target1 = await Secrets.EncryptFileToBufferAsync(source1.Path, PWD);
            await CheckEncryptedAsync(target1);

            using var source2 = SRC_FILE;
            using var target2 = new TestFile();
            await Secrets.EncryptFileToFileAsync(source2.Path, target2.Path, PWD);
            await CheckEncryptedAsync(target2);
        }



        [Fact]
        public async Task DecryptStreamToX()
        {
            using var source0 = ENCRYPTED_STREAM;
            using var target0 = new MemoryStream();
            await Secrets.DecryptStreamToStreamAsync(source0, target0, PWD);
            CheckDecryptedAsync(target0);

            using var source1 = ENCRYPTED_STREAM;
            var target1 = await Secrets.DecryptStreamToBufferAsync(source1, PWD);
            CheckDecrypted(target1);

            using var source2 = ENCRYPTED_STREAM;
            var target2 = await Secrets.DecryptStreamToStringAsync(source2, PWD);
            CheckDecrypted(target2);

            using var source3 = ENCRYPTED_STREAM;
            using var target3 = new TestFile();
            await Secrets.DecryptStreamToFileAsync(source3, target3.Path, PWD);
            CheckDecrypted(target3);
        }

        [Fact]
        public async Task DecryptBufferToX()
        {
            using var target0 = new MemoryStream();
            await Secrets.DecryptBufferToStreamAsync(ENCRYPTED_BUFFER, target0, PWD);
            CheckDecryptedAsync(target0);

            var target1 = await Secrets.DecryptBufferToBufferAsync(ENCRYPTED_BUFFER, PWD);
            CheckDecrypted(target1);

            var target2 = await Secrets.DecryptBufferToStringAsync(ENCRYPTED_BUFFER, PWD);
            CheckDecrypted(target2);

            using var target3 = new TestFile();
            await Secrets.DecryptBufferToFileAsync(ENCRYPTED_BUFFER, target3.Path, PWD);
            CheckDecrypted(target3);
        }

        [Fact]
        public async Task DecryptFileToX()
        {
            using var source = ENCRYPTED_FILE;

            using var target0 = new MemoryStream();
            await Secrets.DecryptFileToStreamAsync(ENCRYPTED_FILE.Path, target0, PWD);
            CheckDecryptedAsync(target0);

            var target1 = await Secrets.DecryptFileToBufferAsync(ENCRYPTED_FILE.Path, PWD);
            CheckDecrypted(target1);

            var target2 = await Secrets.DecryptFileToStringAsync(ENCRYPTED_FILE.Path, PWD);
            CheckDecrypted(target2);

            using var target3 = new TestFile();
            await Secrets.DecryptFileToFileAsync(ENCRYPTED_FILE.Path, target3.Path, PWD);
            CheckDecrypted(target3);
        }



        [Fact]
        public async Task RoundTrip_EmptyPassword_Success()
        {
            var plaintext0 = "This is my plain text.";
            var password = "";

            var e = await Secrets.EncryptStringToBufferAsync(plaintext0, password);

            var plaintext1 = await Secrets.DecryptBufferToStringAsync(e, password);

            Assert.True(plaintext0 == plaintext1);
        }

        [Fact]
        public async Task RoundTrip_NullPassword_Success()
        {
            var plaintext0 = "This is my plain text.";
            var password = (string?)null;

            var e = await Secrets.EncryptStringToBufferAsync(plaintext0, password!);

            var plaintext1 = await Secrets.DecryptBufferToStringAsync(e, password!);

            Assert.True(plaintext0 == plaintext1);
        }

        [Fact]
        public async Task RoundTrip_Fail_WrongSalt()
        {
            var plaintext0 = "This is my plain text.";
            var password = "a password";

            var e = await Secrets.EncryptStringToBufferAsync(plaintext0, password);

            e[8+4] ^= 1;

            try
            {
                var plaintext1 = await Secrets.DecryptBufferToStringAsync(e, password);
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

            var e = await Secrets.EncryptStringToBufferAsync(plaintext0, password);

            e[8+(4+16)+4] ^= 1;

            try
            {
                var plaintext1 = await Secrets.DecryptBufferToStringAsync(e, password);
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

            var e = await Secrets.EncryptStringToBufferAsync(plaintext0, "password0");

            try
            {
                var plaintext1 = await Secrets.DecryptBufferToStringAsync(e, "password1");
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

            var e = await Secrets.EncryptStringToBufferAsync(plaintext0, password);

            e[8 + (4 + 16) + (4 + 16)] ^= 1;

            try
            {
                var plaintext1 = await Secrets.DecryptBufferToStringAsync(e, password);
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
            var e0 = await Secrets.EncryptStringToBufferAsync(plaintext0, password);

            // encode
            var encoded = HttpUtility.UrlEncode(Convert.ToBase64String(e0));

            // decode
            var e1 = Convert.FromBase64String(HttpUtility.UrlDecode(encoded));

            // decrypt
            var plaintext1 = await Secrets.DecryptBufferToStringAsync(e1, password);

            Assert.True(plaintext0 == plaintext1);
        }



        [Fact]
        public async Task RoundTrip_Large_File()
        {
            var sourceFile = Path.GetFullPath(@"../../../../../data/image.jpg");
            var encryptedFile = sourceFile + ".encrypted";
            var decryptedFile = sourceFile + ".decrypted.jpg";

            try
            {
                await Secrets.EncryptFileToFileAsync(sourceFile, encryptedFile, "password");
                await Secrets.DecryptFileToFileAsync(encryptedFile, decryptedFile, "password");

                var buffer0 = File.ReadAllBytes(sourceFile);
                var buffer1 = File.ReadAllBytes(decryptedFile);
                Assert.True(buffer0.Length == buffer1.Length);
                for (var i = 0; i < buffer0.Length; i++)
                {
                    if (buffer0[i] != buffer1[i]) Assert.Fail("Decrypted file is not identical to original file.");
                }
            }
            finally
            {
                File.Delete(encryptedFile);
                File.Delete(decryptedFile);
            }
        }
    }
}