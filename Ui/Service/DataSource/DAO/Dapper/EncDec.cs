using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace _1RM.Service.DataSource.DAO.Dapper;

public class EncDec
{
    public static EncDec Instance { get; } = new();

    private readonly string? sqliteEncKey;
    private readonly byte[] key;
    private readonly byte[] iv;

    protected EncDec()
    {
        // Generate key and IV from SqliteEncKey
        sqliteEncKey = AppInitHelper.ConfigurationServiceObj?.General.SqliteEncKey;
        if (string.IsNullOrEmpty(sqliteEncKey))
        {
            sqliteEncKey = null;
            key = [];
            iv = [];
        }
        else
        {
            var gen = new Rfc2898DeriveBytes(sqliteEncKey, Encoding.UTF8.GetBytes("sugar"), 1234,
                HashAlgorithmName.SHA256);
            key = gen.GetBytes(32);
            iv = gen.GetBytes(16);
        }
    }

    public string Encrypt(string plaintext)
    {
        if (sqliteEncKey != null)
        {
            byte[] encrypted;
            using (var aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;
                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plaintext);
                        }
                    }

                    encrypted = msEncrypt.ToArray();
                }
            }

            return Convert.ToBase64String(encrypted);
        }
        else
        {
            return plaintext;
        }
    }

    public string Decrypt(string ciphertext)
    {
        if (sqliteEncKey != null)
        {
            var cipherBytes = Convert.FromBase64String(ciphertext);
            string plaintext = null;
            using (var aesAlg = Aes.Create())
            {
                aesAlg.Key =key;
                aesAlg.IV = iv;
                var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msDecrypt = new MemoryStream(cipherBytes))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }
        else
        {
            return ciphertext;
        }
    }
}