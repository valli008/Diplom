using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using SharpCompress.Compressors.BZip2;
using SevenZip.Compression.LZMA;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

class Program
{
    static void Main(string[] args)
    {
        // Встановлюємо коректне кодування для консолі
        Console.InputEncoding = Encoding.UTF8;
        Console.OutputEncoding = Encoding.UTF8;

        Console.Write("Введіть текст для шифрування: ");
        string originalText = Console.ReadLine();

        // Вибір шифрувального алгоритму
        Console.WriteLine("Оберіть алгоритм шифрування: AES, DES, 3DES, Blowfish, RC4");
        string encryptionAlgorithm = Console.ReadLine().ToUpper();

        // Шифрування тексту
        byte[] encryptedData;
        byte[] key, iv = null;
        switch (encryptionAlgorithm)
        {
            case "AES":
                using (Aes aes = Aes.Create())
                {
                    aes.Key = GenerateAESKey();
                    aes.IV = aes.Key.Take(16).ToArray();
                    encryptedData = EncryptStringToBytes(originalText, aes.Key, aes.IV, aes.CreateEncryptor());
                    key = aes.Key;
                    iv = aes.IV;
                }
                break;
            case "DES":
                using (DES des = DES.Create())
                {
                    des.Key = GenerateDESKey();
                    des.IV = des.Key.Take(8).ToArray();
                    encryptedData = EncryptStringToBytes(originalText, des.Key, des.IV, des.CreateEncryptor());
                    key = des.Key;
                    iv = des.IV;
                }
                break;
            case "3DES":
                using (TripleDES tdes = TripleDES.Create())
                {
                    tdes.Key = Generate3DESKey();
                    tdes.IV = tdes.Key.Take(8).ToArray();
                    encryptedData = EncryptStringToBytes(originalText, tdes.Key, tdes.IV, tdes.CreateEncryptor());
                    key = tdes.Key;
                    iv = tdes.IV;
                }
                break;
            case "BLOWFISH":
                key = GenerateBlowfishKey();
                encryptedData = EncryptBlowfish(originalText, key);
                break;
            case "RC4":
                key = GenerateRC4Key();
                encryptedData = EncryptRC4(originalText, key);
                break;
            default:
                throw new ArgumentException("Невідомий алгоритм шифрування.");
        }

        Console.WriteLine($"Зашифрований текст (у байтах): {encryptedData.Length} байт");

        // Вибір алгоритму стиснення
        Console.WriteLine("Оберіть алгоритм стиснення: Deflate, LZ77, Bzip2, LZMA");
        string compressionAlgorithm = Console.ReadLine().ToUpper();

        byte[] compressedData;
        switch (compressionAlgorithm)
        {
            case "DEFLATE":
                compressedData = CompressWithDeflate(encryptedData);
                break;
            case "LZ77":
                compressedData = CompressWithGZip(encryptedData);
                break;
            case "BZIP2":
                compressedData = CompressWithBzip2(encryptedData);
                break;
            case "LZMA":
                compressedData = CompressWithLZMA(encryptedData);
                break;
            default:
                throw new ArgumentException("Невідомий алгоритм стиснення.");
        }

        Console.WriteLine($"Стиснений текст (у байтах): {compressedData.Length} байт");

        // Декодування та розшифрування (як приклад, демонстрація)
        byte[] decompressedData = null;
        switch (compressionAlgorithm)
        {
            case "DEFLATE":
                decompressedData = DecompressWithDeflate(compressedData);
                break;
            case "LZ77":
                decompressedData = DecompressWithGZip(compressedData);
                break;
            case "BZIP2":
                decompressedData = DecompressWithBzip2(compressedData);
                break;
            case "LZMA":
                decompressedData = DecompressWithLZMA(compressedData, encryptedData.Length);
                break;
        }

        string decryptedText = DecryptStringFromBytes(decompressedData, key, iv, encryptionAlgorithm);
        Console.WriteLine($"Розшифрований текст: {decryptedText}");
    }

    // Генерація ключів
    static byte[] GenerateAESKey()
    {
        using (Aes aes = Aes.Create())
        {
            aes.GenerateKey();
            return aes.Key;
        }
    }

    static byte[] GenerateDESKey()
    {
        using (DES des = DES.Create())
        {
            des.GenerateKey();
            return des.Key;
        }
    }

    static byte[] Generate3DESKey()
    {
        using (TripleDES tdes = TripleDES.Create())
        {
            tdes.GenerateKey();
            return tdes.Key;
        }
    }

    static byte[] GenerateBlowfishKey()
    {
        // Генерація ключа для Blowfish (32 байти)
        return new byte[32];
    }

    static byte[] GenerateRC4Key()
    {
        // Генерація ключа для RC4 (16 байт)
        return new byte[16];
    }

    // Шифрування та розшифрування
    static byte[] EncryptStringToBytes(string plainText, byte[] Key, byte[] IV, ICryptoTransform encryptor)
    {
        using (MemoryStream msEncrypt = new MemoryStream())
        {
            using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
            {
                using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                {
                    swEncrypt.Write(plainText);
                }
            }
            return msEncrypt.ToArray();
        }
    }

    static string DecryptStringFromBytes(byte[] cipherText, byte[] Key, byte[] IV, string algorithm)
    {
        ICryptoTransform decryptor;
        switch (algorithm)
        {
            case "AES":
                using (Aes aes = Aes.Create())
                {
                    aes.Key = Key;
                    aes.IV = IV;
                    decryptor = aes.CreateDecryptor();
                }
                break;
            case "DES":
                using (DES des = DES.Create())
                {
                    des.Key = Key;
                    des.IV = IV;
                    decryptor = des.CreateDecryptor();
                }
                break;
            case "3DES":
                using (TripleDES tdes = TripleDES.Create())
                {
                    tdes.Key = Key;
                    tdes.IV = IV;
                    decryptor = tdes.CreateDecryptor();
                }
                break;
            case "BLOWFISH":
                return DecryptBlowfish(cipherText, Key);
            case "RC4":
                return DecryptRC4(cipherText, Key);
            default:
                throw new ArgumentException("Невідомий алгоритм шифрування.");
        }

        using (MemoryStream msDecrypt = new MemoryStream(cipherText))
        {
            using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
            {
                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                {
                    return srDecrypt.ReadToEnd();
                }
            }
        }
    }

    // Реалізація Blowfish
    static byte[] EncryptBlowfish(string plainText, byte[] key)
    {
        BlowfishEngine engine = new BlowfishEngine();
        KeyParameter keyParam = new KeyParameter(key);
        engine.Init(true, keyParam);

        byte[] inputBytes = Encoding.UTF8.GetBytes(plainText);
        byte[] outputBytes = new byte[inputBytes.Length];
        engine.ProcessBlock(inputBytes, 0, outputBytes, 0);

        return outputBytes;
    }

    static string DecryptBlowfish(byte[] cipherText, byte[] key)
    {
        BlowfishEngine engine = new BlowfishEngine();
        KeyParameter keyParam = new KeyParameter(key);
        engine.Init(false, keyParam);

        byte[] outputBytes = new byte[cipherText.Length];
        engine.ProcessBlock(cipherText, 0, outputBytes, 0);

        return Encoding.UTF8.GetString(outputBytes);
    }

    // Реалізація RC4
    static byte[] EncryptRC4(string plainText, byte[] key)
    {
        RC4Engine engine = new RC4Engine();
        engine.Init(true, new KeyParameter(key));

        byte[] inputBytes = Encoding.UTF8.GetBytes(plainText);
        byte[] outputBytes = new byte[inputBytes.Length];
        engine.ProcessBytes(inputBytes, 0, inputBytes.Length, outputBytes, 0);

        return outputBytes;
    }

    static string DecryptRC4(byte[] cipherText, byte[] key)
    {
        RC4Engine engine = new RC4Engine();
        engine.Init(false, new KeyParameter(key));

        byte[] outputBytes = new byte[cipherText.Length];
        engine.ProcessBytes(cipherText, 0, cipherText.Length, outputBytes, 0);

        return Encoding.UTF8.GetString(outputBytes);
    }

    // Інші функції стиснення залишаються ті ж самі
    // Deflate стиснення
    static byte[] CompressWithDeflate(byte[] data)
    {
        using (var compressedStream = new MemoryStream())
        {
            using (var deflateStream = new DeflateStream(compressedStream, CompressionLevel.Optimal))
            {
                deflateStream.Write(data, 0, data.Length);
            }
            return compressedStream.ToArray();
        }
    }

    // Deflate розпакування
    static byte[] DecompressWithDeflate(byte[] compressedData)
    {
        using (var compressedStream = new MemoryStream(compressedData))
        using (var deflateStream = new DeflateStream(compressedStream, CompressionMode.Decompress))
        using (var resultStream = new MemoryStream())
        {
            deflateStream.CopyTo(resultStream);
            return resultStream.ToArray();
        }
    }

    // GZip стиснення
    static byte[] CompressWithGZip(byte[] data)
    {
        using (var compressedStream = new MemoryStream())
        {
            using (var gzipStream = new GZipStream(compressedStream, CompressionLevel.Optimal))
            {
                gzipStream.Write(data, 0, data.Length);
            }
            return compressedStream.ToArray();
        }
    }

    // GZip розпакування
    static byte[] DecompressWithGZip(byte[] compressedData)
    {
        using (var compressedStream = new MemoryStream(compressedData))
        using (var gzipStream = new GZipStream(compressedStream, CompressionMode.Decompress))
        using (var resultStream = new MemoryStream())
        {
            gzipStream.CopyTo(resultStream);
            return resultStream.ToArray();
        }
    }

    // BZip2 стиснення
    static byte[] CompressWithBzip2(byte[] data)
    {
        using (var compressedStream = new MemoryStream())
        {
            using (var bzip2Stream = new BZip2Stream(compressedStream, SharpCompress.Compressors.CompressionMode.Compress, true))
            {
                bzip2Stream.Write(data, 0, data.Length);
            }
            return compressedStream.ToArray();
        }
    }

    // BZip2 розпакування
    static byte[] DecompressWithBzip2(byte[] compressedData)
    {
        using (var compressedStream = new MemoryStream(compressedData))
        using (var bzip2Stream = new BZip2Stream(compressedStream, SharpCompress.Compressors.CompressionMode.Decompress, true))
        using (var resultStream = new MemoryStream())
        {
            bzip2Stream.CopyTo(resultStream);
            return resultStream.ToArray();
        }
    }

    // LZMA стиснення
    static byte[] CompressWithLZMA(byte[] data)
    {
        using (var compressedStream = new MemoryStream())
        {
            var encoder = new SevenZip.Compression.LZMA.Encoder();
            encoder.WriteCoderProperties(compressedStream);

            using (var inputStream = new MemoryStream(data))
            {
                encoder.Code(inputStream, compressedStream, inputStream.Length, -1, null);
            }
            return compressedStream.ToArray();
        }
    }

    // LZMA розпакування
    static byte[] DecompressWithLZMA(byte[] compressedData, long originalSize)
    {
        using (var compressedStream = new MemoryStream(compressedData))
        using (var resultStream = new MemoryStream())
        {
            var decoder = new SevenZip.Compression.LZMA.Decoder();

            // Read properties
            byte[] properties = new byte[5];
            compressedStream.Read(properties, 0, 5);
            decoder.SetDecoderProperties(properties);

            decoder.Code(compressedStream, resultStream, compressedStream.Length - 5, originalSize, null);
            return resultStream.ToArray();
        }
    }

}
