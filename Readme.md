Cryptools: Simple cryptographic operations in Java
==================================================

This Java library offers a small set of classes to perform basic cryptographic operations (e.g. symmetric/asymmetric encryption, key generation, hashing).

The core package, called `ca.uqac.lif.crypto`, merely provides *interfaces* for these concepts (`Key`, `SymmetricCipher`, `HashFunction`, etc.), without being tied to any specific implementation (not even Java's own cryptographic classes). This core package can then be combined with any extension implementing these interfaces using an arbitrary encryption library. For example:

- The `Java` extension provides a package implementing ciphers using Java's internal cryptographic functionalities.
- The `Apache` extension implements alternate version of ciphers that rely on the [Apache Commons Crypto](https://commons.apache.org/proper/commons-crypto/) and [Codec](https://commons.apache.org/proper/commons-codec/) libraries instead.
- The `Stubs` extension contains ciphers that *simulate* encryption without actually performing it (more on that later). It can prove useful for development, testing and demonstration purposes.
- The `Azrael` extension

Basic Examples
--------------

Let us first look a examples of the common features one expects from a crypto library. As one shall see, most of these operations in Cryptools reduce to one-liners.

### Symmetric Encryption

Generate a key for the AES algorithm and encrypt a string, first converted to an array of bytes:

```java
AESKey k = AES.generator.generateKey();
byte[] encrypted = (byte[]) AES.instance.encrypt(k, "Hello world".getBytes());
```

Print the byte array as a hex string, then decypt it using the key created above:

```java
System.out.println(ByteArray.toHexString(encrypted));
String s = new String(AES.instance.decrypt(k, encrypted));
```

### Asymmetric Encryption

Generate an RSA key pair and encrypt a string with the public key:

```java
RSAKeyPair p = RSA.generator.generateKeyPair();
byte[] encrypted = (byte[]) RSA.instance.encrypt(p.getPublicKey(), "Hello world".getBytes());
```

### Hashing

Calculate the SHA-2 hash of a string:

```java
byte[] h = SHA2.instance.getDigest("Hello world".getBytes());
```

Hash the password for a shadow file, similar to [`mkpasswd`](https://linux.die.net/man/1/mkpasswd) command (requires the *Apache* extension):

```java
String h = GnuCrypt.instance.getDigest("thepassword", "$1$aFGiJR0E");
System.out.println(h); // $1$Z58Nnbh2$d.ScTU1V0DUw67QrwhqYL1
```

Advanced Features
-----------------

The previous operations correspond to standard usage of a cryptography library and are hardly surprising. In the following, we discuss some less common features that are provided by the Cryptools library.

### Mock Encryption and Hashing

The *Stubs* extension of Cryptools provides symmetric and asymmetric cipher classes that do not perform any encryption, and only "pretend" that an operation is done on the input. This can prove particularly useful for development and debugging, as it is possible to inspect the contents of the encrypted objects that are being exchanged, and ensure that the correct operations are done using the appropriate keys. For example:

```java
KeyPair p = DummyAsymmetricCipher.generator.generateKeyPair("X", "X");
Object encrypted = DummyAsymmetricCipher.instance.encrypt(p.getPublicKey(), "Hello world");
System.out.println(encrypted);
```

Here, the output of `encrypt` is an instance of `EncryptedObject`, which simply encapsulates the input with the key name used for the encryption. Printing this object to the console produces the output:

    E[PU_X,Hello world]

which indeed shows that what this object contains is the encryption of "Hello world" with the public key "PU_X". The object can then be "decrypted" in the same way; calling...

```java
String recovered = (String) DummyAsymmetricCipher.instance.decrypt(p.getPrivateKey(), encrypted);
```

...puts "Hello world" back into the variable.

Although no actual encryption is performed, those stubs still reproduce the properties of the encryption algorithms they replace. For example, trying to decrypt the object using the wrong key is impossible:

```java
// Throws a CryptoException, as we should use the private key to decrypt
String recovered = (String) DummyAsymmetricCipher.instance.decrypt(p.getPublicKey(), encrypted);

// Throws a CryptoException, as we use a key from the wrong key pair
KeyPair p2 = DummyAsymmetricCipher.generator.generateKeyPair("Y", "Y");
String recovered = (String) DummyAsymmetricCipher.instance.decrypt(p2.getPublicKey(), encrypted);
```

Values can also be sent to a dummy hash function:

```java
Object h = DummyHashFunction.instance.getDigest("Hello world");
```

The contents of `h` is an instance of `HashValue`, which again behaves as expected of a hash function:

```java
System.out.println(h);
System.out.println(h.equals(DummyHashFunction.instance.getDigest("foobarbaz")));
```

prints out:

    H(Hello world)
    false

That is, the hash of two different inputs produces two objects that are not equal.

These constructs can be nested at will:

```java
Object o = DummyAsymmetricCipher.encrypt(p.getPublicKey(),
  DummyHashFunction.instance.getDigest("Hello world"));
System.out.println(o);
```

produces:

    E[PU_X,H(Hello world)]

As mentioned, one of the main purposes of these mock classes is to use them as drop-in replacements of actual algorithms during the testing and development phase of a project.

### Encryption of Objects

The `encrypt` and `decrypt` methods of of `SymmetricCipher` and `AsymmetricCipher` accept arbitrary objects, and not ony byte arrays. As a matter of fact, some ciphers such as AES or RSA throw a `CryptoException` if given anything else. This can make encryption cumbersome, as everything needs to be converted to low-level byte arrays, effectively requiring manual serializtion of objects in order to be encrypted.

The *Azrael* extension provides the `AzraelSymmetricCipher`, which uses the [Azrael](https://github.com/sylvainhalle/Azrael) serialization library to convert objects to/from a serialized form which can be turned into a byte array and then passed to a "regular" cipher. Hence, the `AzraelJsonCipher` serializes an object into a JSON string, encrypts the byte contents of this string, and performs the reverse operation on decryption. Thus, given a class like the following:

```java
class C {
  public String foo;
  public int bar;
  public List<Integer> baz;
  public C(String foo, int bar, List<Integer> baz) {
    this.foo = foo;
    this.bar = bar;
    this.baz = baz;
  }
}
```

it is possible to perform the following:

```java
C obj = new C("hello", 42, Arrays.asList(3, 1, 4));
AzraelObjectCipher cipher = new AzraelJsonCipher(DES.instance);
byte[] encrypted = (byte[]) cipher.encrypt(k, obj);
```

This effectively serializes `obj` into JSON, and encrypts the byte array with DES. Recovering the object is possible:

```java
C recovered = (C) cipher.decrypt(k, encrypted);
System.out.println(recovered.baz); // Prints [3, 1, 4]
```

This technique makes it possible to apply an arbitrary symmetric cipher on arbitrary objects (provided they serialize properly with Azrael). The intermediate format to which objects are serialized is irrelevant; JSON was only used as an example.

### Saving and Loading Keys

With Java's `security` package, saving and loading keys is cumbersome. One must:

1. Instantiate a `KeyStore` object (keeping in mind that there are multiple versions of this object that are only distinguished by the *string* used to instantiate)
2. Load an empty key store (?!?)
3. Add a name-value entry containing the key to the key store
4. Serialize the key store to an `ObjectOutputStream`

`KeyStore` does provide a few more features (such as password protection of individual entries), but remains a complicated mechanism as far as dumping the contents of a key is concerned. What is more, the key's contents is entangled within the binary serialization of the key store itself, and native object serialization in Java is notoriously flaky (for example, objects cannot always be recovered if using a different JVM version than the one used for serialization).

Cryptools does away with this mechanism; many types of keys provided by the library can be serialized using [Azrael](https://github.com/sylvainhalle/Azrael). This is the case of all keys of the *Java* extension (which wraps Java's own keys into Cryptools objects). For instance:

```java
KeyPair p = RSA.generator.generateKeyPair();
String serialized = JsonStringPrinter.toJson(p);
```

The string `s` is a plain JSON object that can be saved wherever (suggestion: use a `FileSystem` object from the [lif-fs](https://github.com/liflab/lif-fs) library). Recovering the key pair is also possible:

```java
KeyPair p2 = (KeyPair) JsonStringReader.fromJson(serialized);
PublicKey pu = p2.getPublicKey(); // etc.
```

This mechanism does not rely on the binary serialization of a `KeyStore` object, and is thus exempt from the issues mentioned above.

### Custom Ciphers

Cryptools allows users to create their own ciphers. The *Examples* folder contains a [simple example]() showing how one can implement a transposition cipher in a few lines of code. The same can be done with hash functions and asymmetric encryption.

### Short Hash Function

One can build a "short" version of another hash function producing a byte array. The `ShortHashFunction` produces a "simpler" hash function by truncating the digest produced by another hash function:

```java
HashFunction f = new ShortHashFunction(MD5.instance);
System.out.println(ByteArray.toHexString(f.getDigest("Hello world".getBytes())));
```

produces `5EB63BBB` (the first 8 bytes of the MD5 digest of "Hello world").

Again, the main purpose of such a function is to avoid handling long byte arrays during development and testing.

About the Author
----------------

Cryptools was written by [Sylvain Hallé](https://leduotang.ca/sylvain), full professor at Université du Québec à Chicoutimi, Canada. Part of this work has been funded by the Canada Research Chair in Software Specification, Testing and Verification and the [Natural Sciences and Engineering Research Council
of Canada](https://nserc-crsng.gc.ca).

<!-- :wrap=soft: -->