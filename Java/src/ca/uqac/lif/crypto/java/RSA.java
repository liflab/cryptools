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

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import ca.uqac.lif.azrael.ObjectPrinter;
import ca.uqac.lif.azrael.ObjectReader;
import ca.uqac.lif.azrael.PrintException;
import ca.uqac.lif.azrael.Printable;
import ca.uqac.lif.azrael.Readable;
import ca.uqac.lif.azrael.ReadException;
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
public class RSA extends JavaCipher implements AsymmetricCipher<ca.uqac.lif.crypto.java.RSA.RSAPublicKey,ca.uqac.lif.crypto.java.RSA.RSAPrivateKey,byte[]>
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
	 * A static instance of key factory.
	 */
	protected static final KeyFactory s_keyFactory = getFactory();
	
	/**
	 * Creates a new DES encryption function.
	 */
	protected RSA()
	{
		super(getInstance("RSA/ECB/PKCS1Padding"));
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
	public static class RSAPublicKey implements PublicKey<java.security.PublicKey>, Readable, Printable
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
		
		/**
		 * Creates an empty pblic key. This constructor is used only for
		 * deserialization.
		 */
		protected RSAPublicKey()
		{
			this(null);
		}

		@Override
		public java.security.PublicKey getContents()
		{
			return m_key;
		}

		@Override
		public Object print(ObjectPrinter<?> printer) throws PrintException
		{
			return printer.print(m_key.getEncoded());
		}

		@Override
		public Object read(ObjectReader<?> reader, Object o) throws ReadException
		{
			Object o_read = reader.read(o);
			if (!(o_read instanceof byte[]))
			{
				throw new ReadException("Expected a byte array");
			}
			byte[] key_contents = (byte[]) o_read;
			KeySpec keyspec = new X509EncodedKeySpec(key_contents);
			try
			{
				return new RSAPublicKey(s_keyFactory.generatePublic(keyspec));
			}
			catch (InvalidKeySpecException e)
			{
				throw new ReadException(e);
			}
		}
	}
	
	/**
	 * A private key for the RSA algorithm.
	 */
	public static class RSAPrivateKey implements PrivateKey<java.security.PrivateKey>, Readable, Printable
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
		
		/**
		 * Creates an empty private key. This constructor is used only for
		 * deserialization.
		 */
		protected RSAPrivateKey()
		{
			this(null);
		}

		@Override
		public java.security.PrivateKey getContents()
		{
			return m_key;
		}
		
		@Override
		public Object print(ObjectPrinter<?> printer) throws PrintException
		{
			return printer.print(m_key.getEncoded());
		}

		@Override
		public RSAPrivateKey read(ObjectReader<?> reader, Object o) throws ReadException
		{
			Object o_read = reader.read(o);
			if (!(o_read instanceof byte[]))
			{
				throw new ReadException("Expected a byte array");
			}
			byte[] key_contents = (byte[]) o_read;
			KeySpec keyspec = new PKCS8EncodedKeySpec(key_contents);
			try
			{
				return new RSAPrivateKey(s_keyFactory.generatePrivate(keyspec));
			}
			catch (InvalidKeySpecException e)
			{
				throw new ReadException(e);
			}
		}
	}
	
	/**
	 * A key pair consisting of an RSA public and private key.
	 */
	public static class RSAKeyPair implements KeyPair<RSAPublicKey,RSAPrivateKey>, Readable, Printable
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
		
		/**
		 * Creates an empty key pair
		 */
		protected RSAKeyPair()
		{
			this(null, null);
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

		@Override
		public Object print(ObjectPrinter<?> printer) throws PrintException
		{
			List<Object> list = new ArrayList<Object>();
			list.add(m_publicKey);
			list.add(m_privateKey);
			return printer.print(list);
		}

		@Override
		public Object read(ObjectReader<?> reader, Object o) throws ReadException
		{
			Object read = reader.read(o);
			if (!(read instanceof List))
			{
				throw new ReadException("Expected a list");
			}
			List<?> list = (List<?>) read;
			if (list.size() != 2)
			{
				throw new ReadException("Invalid list size");
			}
			Object e1 = list.get(0);
			Object e2 = list.get(1);
			RSAPublicKey pu = null;
			RSAPrivateKey pr = null;
			if (e1 != null)
			{
				if (!(e1 instanceof RSAPublicKey))
				{
					throw new ReadException("Expected an RSA public key");
				}
				pu = (RSAPublicKey) e1;
			}
			if (e2 != null)
			{
				if (!(e2 instanceof RSAPrivateKey))
				{
					throw new ReadException("Expected an RSA private key");
				}
				pr = (RSAPrivateKey) e2;
			}
			return new RSAKeyPair(pu, pr);
		}

		@Override
		public RSAKeyPair getOnlyPublic() throws CryptoException
		{
			return new RSAKeyPair(m_publicKey, null);
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
	
	/**
	 * Gets an instance of RSA key factory.
	 * @return The key factory, or <tt>null</tt> if the factory could not be
	 * obtained
	 */
	protected static KeyFactory getFactory()
	{
		try
		{
			return KeyFactory.getInstance("RSA");
		}
		catch (NoSuchAlgorithmException e)
		{
			return null;
		}
	}
}
