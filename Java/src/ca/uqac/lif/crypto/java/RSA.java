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

import java.security.SecureRandom;

import ca.uqac.lif.crypto.CryptoException;
import ca.uqac.lif.crypto.asymmetric.AsymmetricCipher;
import ca.uqac.lif.crypto.asymmetric.KeyPair;
import ca.uqac.lif.crypto.asymmetric.PrivateKey;
import ca.uqac.lif.crypto.asymmetric.PublicKey;

/**
 * Manages the encryption and key generation process for the
 * <a href="https://en.wikipedia.org/wiki/RSA_(cryptosystem)">RSA</a>
 * algorithm.
 * 
 * @author Sylvain Hallé
 */
public class RSA extends JavaCipher implements AsymmetricCipher<ca.uqac.lif.crypto.java.RSA.RSAPublicKey,ca.uqac.lif.crypto.java.RSA.RSAPrivateKey>
{
	/**
	 * A single publicly visible instance of the hash function.
	 */
	public static final RSA instance = new RSA();
	
	/**
	 * A generator for RSA key pairs of 1024 bits with default settings.
	 */
	public static final RSAKeyPairGenerator generator = new RSAKeyPairGenerator(1024);
	
	/**
	 * Creates a new DES encryption function.
	 */
	protected RSA()
	{
		super(getInstance("RSA"));
	}

	@Override
	public byte[] encrypt(RSAPublicKey k, byte[] m) throws CryptoException
	{
		java.security.Key o_k = k.getContents();
		if (!(o_k instanceof java.security.PublicKey))
		{
			throw new CryptoException("Expected a public key");
		}
		return cipherEncrypt((java.security.PublicKey) k.getContents(), m);
	}
	
	@Override
	public byte[] encrypt(RSAPrivateKey k, byte[] m) throws CryptoException
	{
		java.security.Key o_k = k.getContents();
		if (!(o_k instanceof java.security.PrivateKey))
		{
			throw new CryptoException("Expected a private key");
		}
		return cipherEncrypt((java.security.PrivateKey) k.getContents(), m);
	}

	@Override
	public byte[] decrypt(RSAPublicKey k, byte[] m) throws CryptoException
	{
		java.security.Key o_k = k.getContents();
		if (!(o_k instanceof java.security.PublicKey))
		{
			throw new CryptoException("Expected a public key");
		}
		return cipherDecrypt((java.security.PublicKey) k.getContents(), m);
	}
	
	@Override
	public byte[] decrypt(RSAPrivateKey k, byte[] m) throws CryptoException
	{
		java.security.Key o_k = k.getContents();
		if (!(o_k instanceof java.security.PrivateKey))
		{
			throw new CryptoException("Expected a private key");
		}
		return cipherDecrypt((java.security.PrivateKey) k.getContents(), m);
	}
	/**
	 * A public key for the RSA algorithm.
	 */
	public static class RSAPublicKey implements PublicKey<java.security.PublicKey>
	{
		/**
		 * The underlying Java {@link PublicKey} object contained in this
		 * key.
		 */
		/*@ non_null @*/ protected final java.security.PublicKey m_key;
		
		/**
		 * Creates a new RSA public key.
		 * @param k The underlying Java {@link PublicKey} object contained in this
		 * key.
		 */
		public RSAPublicKey(/*@ non_null @*/ java.security.PublicKey k)
		{
			super();
			m_key = k;
		}

		@Override
		public java.security.PublicKey getContents()
		{
			return m_key;
		}
	}
	
	/**
	 * A private key for the RSA algorithm.
	 */
	public static class RSAPrivateKey implements PrivateKey<java.security.PrivateKey>
	{
		/**
		 * The underlying Java {@link PrivateKey} object contained in this
		 * key.
		 */
		/*@ non_null @*/ protected final java.security.PrivateKey m_key;
		
		/**
		 * Creates a new RSA private key.
		 * @param k The underlying Java {@link PrivateKey} object contained in this
		 * key.
		 */
		public RSAPrivateKey(/*@ non_null @*/ java.security.PrivateKey k)
		{
			super();
			m_key = k;
		}

		@Override
		public java.security.PrivateKey getContents()
		{
			return m_key;
		}
	}
	
	/**
	 * A key pair consisting of an RSA public and private key.
	 */
	public static class RSAKeyPair implements KeyPair<RSAPublicKey,RSAPrivateKey>
	{
		/**
		 * The RSA public key of this key pair.
		 */
		/*@ null @*/ protected final RSAPublicKey m_publicKey;
		
		/**
		 * The RSA private key of this key pair.
		 */
		/*@ null @*/ protected final RSAPrivateKey m_privateKey;
		
		/**
		 * Creates a new RSA key pair.
		 * @param public_key The RSA public key of this key pair
		 * @param private_key The RSA private key of this key pair
		 */
		public RSAKeyPair(RSAPublicKey public_key, RSAPrivateKey private_key)
		{
			super();
			m_publicKey = public_key;
			m_privateKey = private_key;
		}

		@Override
		public RSAPrivateKey getPrivateKey() throws CryptoException
		{
			return m_privateKey;
		}

		@Override
		public RSAPublicKey getPublicKey() throws CryptoException
		{
			return m_publicKey;
		}
	}
	
	/**
	 * A generator for RSA key pairs.
	 */
	public static class RSAKeyPairGenerator extends JavaKeyPairGenerator<RSAPublicKey,RSAPrivateKey>
	{
		/**
		 * The size of the keys to generate.
		 */
		protected final int m_keySize;
		
		public RSAKeyPairGenerator(int key_size, SecureRandom random)
		{
			super("RSA", random);
			m_keySize = key_size;
		}
		
		public RSAKeyPairGenerator(int key_size)
		{
			this(key_size, null);
		}
		
		@Override
		public RSAKeyPair generateKeyPair() throws CryptoException
		{
			if (m_random != null)
			{
				m_generator.initialize(m_keySize, m_random);
			}
			java.security.KeyPair j_pair = m_generator.generateKeyPair();
			return new RSAKeyPair(new RSAPublicKey(j_pair.getPublic()), new RSAPrivateKey(j_pair.getPrivate()));
		}
	}
}
