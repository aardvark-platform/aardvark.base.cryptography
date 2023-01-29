Utilities for handling data in a cryptographically secure way.

Currently, a number of utility functions are provided to encrypt byte arrays and strings based on a password.

:bulb: If the password is unknown and sufficiently complex, it is unfeasible to break the encryption by brute force.

The implementation uses AES (Advanced Encryption Standard), with
the encryption key derived according to RFC 2898 (https://www.ietf.org/rfc/rfc2898.txt). 

Parameters stored with the encrypted data
- random salt
- IV (Initialization Vector)
- iteration count for password derivation

:warning: Always acquire passwords at runtime, e.g. by user input, environment variables, config files, secrets store, etc.

:warning: Never commit a password to source control.

# Examples

## Hello world

```csharp
using Aardvark.Base.Cryptography;

var plaintext = "Hello world!";
var encrypted = await Secrets.EncryptAsync(plaintext, "password");
var decrypted = await Secrets.DecryptStringAsync(encrypted, "password");

Console.WriteLine($"plaintext = {plaintext}");
Console.WriteLine($"encrypted = {Convert.ToBase64String(encrypted)}");
Console.WriteLine($"decrypted = {decrypted}");
```

Output:
```
plaintext = Hello world!
encrypted = AQAAAOgDAAAQAAAAegJ1maAIEOzecXeEIrZ9cxAAAAD8rLlCpkWSpyuTbXe6/wbeckFdA6EBQq6513D4J4t22A==
decrypted = Hello world!
```
## Data at rest



## Credentials

