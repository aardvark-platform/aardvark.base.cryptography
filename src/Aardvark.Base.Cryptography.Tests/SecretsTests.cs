using System.Text;
using System.Web;

namespace Aardvark.Base.Cryptography.Tests
{
    public class SecretsTests
    {
        [Fact]
        public async Task RoundTrip_Success()
        {
            var plaintext0 = "This is my plain text.";
            var password = "a password";

            var e = await Secrets.EncryptAsync(plaintext0, password);

            var plaintext1 = await Secrets.DecryptStringAsync(e, password);

            Assert.True(plaintext0 == plaintext1);
        }

        [Fact]
        public async Task RoundTrip_DirectStream_Success()
        {
            var plaintext0 = "This is my plain text.";
            var password = "a password";

            var ms = new MemoryStream();

            await Secrets.EncryptAsync(ms, Encoding.UTF8.GetBytes(plaintext0), password);

            var ms2 = new MemoryStream(ms.ToArray());

            var plaintext1 = Encoding.UTF8.GetString(await Secrets.DecryptAsync(ms2, password));

            Assert.True(plaintext0 == plaintext1);
        }

        [Fact]
        public async Task RoundTrip_EmptyPassword_Success()
        {
            var plaintext0 = "This is my plain text.";
            var password = "";

            var e = await Secrets.EncryptAsync(plaintext0, password);

            var plaintext1 = await Secrets.DecryptStringAsync(e, password);

            Assert.True(plaintext0 == plaintext1);
        }

        [Fact]
        public async Task RoundTrip_NullPassword_Success()
        {
            var plaintext0 = "This is my plain text.";
            var password = (string?)null;

            var e = await Secrets.EncryptAsync(plaintext0, password!);

            var plaintext1 = await Secrets.DecryptStringAsync(e, password!);

            Assert.True(plaintext0 == plaintext1);
        }

        [Fact]
        public async Task RoundTrip_Stream_Success()
        {
            var plaintext0 = "This is my plain text.";
            var password = "a password";

            var ms0 = new MemoryStream();
            await Secrets.EncryptAsync(ms0, plaintext0, password);

            var ms1 = new MemoryStream(ms0.ToArray());
            var plaintext1 = await Secrets.DecryptStringAsync(ms1, password);

            Assert.True(plaintext0 == plaintext1);
        }

        [Fact]
        public async Task RoundTrip_File_Success()
        {
            var plaintext0 = "This is my plain text.";
            var password = "a password";

            var path = Path.GetRandomFileName();

            try
            {
                await Secrets.EncryptToFileAsync(path, plaintext0, password);
                var exists = File.Exists(path);
                Assert.True(exists == true);
                var plaintext1 = await Secrets.DecryptStringFromFileAsync(path, password);
                Assert.True(plaintext0 == plaintext1);
            }
            finally
            {
                File.Delete(path);
            }
        }

        [Fact]
        public async Task RoundTrip_LocalAppData_Success()
        {
            var appname = "aardvark.base.cryptography_tests";
            var plaintext0 = "This is my plain text.";
            var password = "a password";

            var filename = Path.GetRandomFileName();

            try
            {
                await Secrets.EncryptToLocalAppDataAsync(appname, filename, plaintext0, password);
                var plaintext1 = await Secrets.DecryptStringFromLocalAppDataAsync(appname, filename, password);
                Assert.True(plaintext0 == plaintext1);
            }
            finally
            {
                Secrets.DeleteFromLocalAppDataAsync(appname, filename);
            }
        }



        [Fact]
        public async Task RoundTrip_Fail_WrongSalt()
        {
            var plaintext0 = "This is my plain text.";
            var password = "a password";

            var e = await Secrets.EncryptAsync(plaintext0, password);

            e[8+4] ^= 1;

            try
            {
                var plaintext1 = await Secrets.DecryptStringAsync(e, password);
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

            var e = await Secrets.EncryptAsync(plaintext0, password);

            e[8+(4+16)+4] ^= 1;

            try
            {
                var plaintext1 = await Secrets.DecryptStringAsync(e, password);
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

            var e = await Secrets.EncryptAsync(plaintext0, "password0");

            try
            {
                var plaintext1 = await Secrets.DecryptStringAsync(e, "password1");
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

            var e = await Secrets.EncryptAsync(plaintext0, password);

            e[40] ^= 1;

            try
            {
                var plaintext1 = await Secrets.DecryptStringAsync(e, password);
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
            var e0 = await Secrets.EncryptAsync(plaintext0, password);

            // encode
            var encoded = HttpUtility.UrlEncode(Convert.ToBase64String(e0));

            // decode
            var e1 = Convert.FromBase64String(HttpUtility.UrlDecode(encoded));

            // decrypt
            var plaintext1 = await Secrets.DecryptStringAsync(e1, password);

            Assert.True(plaintext0 == plaintext1);
        }
    }
}