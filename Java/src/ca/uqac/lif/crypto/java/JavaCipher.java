/*
  Simple tools for cryptographic operations
  Copyright (C) 2022 Sylvain Hallé
  
  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package ca.uqac.lif.crypto.java;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import ca.uqac.lif.crypto.CryptoException;
import ca.uqac.lif.crypto.symmetric.SymmetricKey;

/**
 * A cipher using Java's {@link Cipher} class for encryption and decryption.
 * @author Sylvain Hallé
 */
abstract class JavaCipher 
{
	/**
	 * The instance of {@link Cipher} object used to perform encryption and
	 * decryption.
	 */
	/*@ null @*/ protected final Cipher m_cipher;
	
	/**
	 * Creates a new Java cipher.
	 * @param c The instance of {@link Cipher} object used to perform
	 * encryption and decryption.
	 */
	protected JavaCipher(/*@ null @*/ Cipher c)
	{
		super();
		m_cipher = c;
	}
	
	/**
	 * Uses the internal Java cipher object to encrypt the contents of a byte
	 * array using a secret key.
	 * @param k The key used to perform the encryption
	 * @param m The byte array to encrypt
	 * @return The encrypted contents
	 * @throws CryptoException Thrown if the encryption could not proceed
	 */
	protected byte[] cipherEncrypt(SecretKey k, byte[] m) throws CryptoException
	{
		try
		{
			m_cipher.init(Cipher.ENCRYPT_MODE, k);
			return m_cipher.doFinal(m);
		}
		catch (InvalidKeyException e) 
		{
			throw new CryptoException(e);
		}
		catch (IllegalBlockSizeException e)
		{
			throw new CryptoException(e);
		}
		catch (BadPaddingException e) 
		{
			throw new CryptoException(e);
		}
	}
	
	/**
	 * Uses the internal Java cipher object to decrypt the contents of a byte
	 * array using a secret key.
	 * @param k The key used to perform the decryption
	 * @param m The byte array to decrypt
	 * @return The decrypted contents
	 * @throws CryptoException Thrown if the decryption could not proceed
	 */
	protected byte[] cipherDecrypt(SecretKey k, byte[] m) throws CryptoException
	{
		try
		{
			m_cipher.init(Cipher.DECRYPT_MODE, k);
			return m_cipher.doFinal(m);
		}
		catch (InvalidKeyException e) 
		{
			throw new CryptoException(e);
		}
		catch (IllegalBlockSizeException e)
		{
			throw new CryptoException(e);
		}
		catch (BadPaddingException e) 
		{
			throw new CryptoException(e);
		}
	}
	
	/**
	 * Uses the internal Java cipher object to decrypt the contents of a byte
	 * array using a public key.
	 * @param k The key used to perform the decryption
	 * @param m The byte array to decrypt
	 * @return The decrypted contents
	 * @throws CryptoException Thrown if the decryption could not proceed
	 */
	protected byte[] cipherDecrypt(PublicKey k, byte[] m) throws CryptoException
	{
		try
		{
			m_cipher.init(Cipher.DECRYPT_MODE, k);
			return m_cipher.doFinal(m);
		}
		catch (InvalidKeyException e) 
		{
			throw new CryptoException(e);
		}
		catch (IllegalBlockSizeException e)
		{
			throw new CryptoException(e);
		}
		catch (BadPaddingException e) 
		{
			throw new CryptoException(e);
		}
	}
	
	/**
	 * Uses the internal Java cipher object to decrypt the contents of a byte
	 * array using a private key.
	 * @param k The key used to perform the decryption
	 * @param m The byte array to decrypt
	 * @return The decrypted contents
	 * @throws CryptoException Thrown if the decryption could not proceed
	 */
	protected byte[] cipherDecrypt(PrivateKey k, byte[] m) throws CryptoException
	{
		try
		{
			m_cipher.init(Cipher.DECRYPT_MODE, k);
			return m_cipher.doFinal(m);
		}
		catch (InvalidKeyException e) 
		{
			throw new CryptoException(e);
		}
		catch (IllegalBlockSizeException e)
		{
			throw new CryptoException(e);
		}
		catch (BadPaddingException e) 
		{
			throw new CryptoException(e);
		}
	}
	
	/**
	 * Uses the internal Java cipher object to encrypt the contents of a byte
	 * array using a public key.
	 * @param k The key used to perform the encryption
	 * @param m The byte array to encrypt
	 * @return The encrypted contents
	 * @throws CryptoException Thrown if the encryption could not proceed
	 */
	protected byte[] cipherEncrypt(PublicKey k, byte[] m) throws CryptoException
	{
		try
		{
			m_cipher.init(Cipher.ENCRYPT_MODE, k);
			return m_cipher.doFinal(m);
		}
		catch (InvalidKeyException e) 
		{
			throw new CryptoException(e);
		}
		catch (IllegalBlockSizeException e)
		{
			throw new CryptoException(e);
		}
		catch (BadPaddingException e) 
		{
			throw new CryptoException(e);
		}
	}
	
	/**
	 * Uses the internal Java cipher object to encrypt the contents of a byte
	 * array using a private key.
	 * @param k The key used to perform the encryption
	 * @param m The byte array to encrypt
	 * @return The encrypted contents
	 * @throws CryptoException Thrown if the encryption could not proceed
	 */
	protected byte[] cipherEncrypt(PrivateKey k, byte[] m) throws CryptoException
	{
		try
		{
			m_cipher.init(Cipher.ENCRYPT_MODE, k);
			return m_cipher.doFinal(m);
		}
		catch (InvalidKeyException e) 
		{
			throw new CryptoException(e);
		}
		catch (IllegalBlockSizeException e)
		{
			throw new CryptoException(e);
		}
		catch (BadPaddingException e) 
		{
			throw new CryptoException(e);
		}
	}
	
	@Override
	public String toString()
	{
		return m_cipher.getAlgorithm();
	}
	
	/**
	 * Gets the cipher object based on an algorithm name.
	 * @param algorithm The name of the hashing algorithm
	 * @return The instance, or <tt>null</tt> if no such algorithm exists
	 */
	protected static Cipher getInstance(String transformation)
	{
		try
		{
			return Cipher.getInstance(transformation);
		}
		catch (NoSuchAlgorithmException e)
		{
			return null;
		}
		catch (NoSuchPaddingException e)
		{
			return null;
		}
	}
	
	/**
	 * A symmetric key whose contents is a Java {@link SecretKey} object.
	 */
	abstract static class JavaSymmetricKey implements SymmetricKey<SecretKey>
	{
		/**
		 * The underlying {@link SecretKey} object which is the content
		 * of this key.
		 */
		/*@ non_null @*/ protected final SecretKey m_key;
		
		/**
		 * Creates a new symmetric key.
		 * @param k The underlying {@link SecretKey} object which is the
		 * content of this key.
		 */
		JavaSymmetricKey(/*@ non_null @*/ SecretKey k)
		{
			super();
			m_key = k;
		}
		
		@Override
		/*@ pure non_null @*/ public SecretKey getContents()
		{
			return m_key;
		}
	}
}
