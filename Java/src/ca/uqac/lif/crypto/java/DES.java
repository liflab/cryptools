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

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import ca.uqac.lif.azrael.ObjectPrinter;
import ca.uqac.lif.azrael.ObjectReader;
import ca.uqac.lif.azrael.PrintException;
import ca.uqac.lif.azrael.Printable;
import ca.uqac.lif.azrael.ReadException;
import ca.uqac.lif.azrael.Readable;
import ca.uqac.lif.crypto.CryptoException;
import ca.uqac.lif.crypto.symmetric.ByteKeyConverter;
import ca.uqac.lif.crypto.symmetric.SymmetricCipher;
import ca.uqac.lif.crypto.symmetric.SymmetricKey;

/**
 * Manages the encryption and key generation process for the
 * <a href="https://en.wikipedia.org/wiki/Data_Encryption_Standard">DES</a>
 * algorithm.
 * 
 * @author Sylvain Hallé
 */
public class DES extends JavaCipher implements SymmetricCipher<byte[]>
{
	/**
	 * A single publicly visible instance of the hash function.
	 */
	/*@ non_null @*/ public static final DES instance = new DES();
	
	/**
	 * A static reference to an instance of DES key generator with default
	 * settings.
	 */
	/*@ non_null @*/ public static final DESKeyGenerator generator = new DESKeyGenerator();
	
	/**
	 * A static reference to an instance of DES byte key converter.
	 */
	/*@ non_null @*/ public static final DESByteKeyConverter converter = new DESByteKeyConverter();
	
	/**
	 * Creates a new DES encryption function.
	 */
	protected DES()
	{
		super(getInstance("DES"));
	}

	@Override
	public byte[] encrypt(SymmetricKey k, byte[] m) throws CryptoException
	{
		if (!(k instanceof DESKey))
		{
			throw new CryptoException("Expected a DESKey");
		}
		return cipherEncrypt(((DESKey) k).getContents(), m);
	}

	@Override
	public byte[] decrypt(SymmetricKey k, byte[] m) throws CryptoException 
	{
		if (!(k instanceof DESKey))
		{
			throw new CryptoException("Expected a DESKey");
		}
		return cipherDecrypt(((DESKey) k).getContents(), m);
	}
	
	public static DESKey readFrom(byte[] key_contents)
	{
		SecretKey sk = new SecretKeySpec(key_contents, "DES");
		return new DESKey(sk);
	}
	
	/**
	 * A symmetric key used by the DES algorithm.
	 */
	public static class DESKey extends JavaSymmetricKey implements Readable, Printable
	{
		/**
		 * The key's optional name.
		 */
		protected final String m_name;
		
		DESKey(SecretKey k, String name)
		{
			super(k);
			m_name = name;
		}
		
		DESKey(SecretKey k)
		{
			this(k, "");
		}
		
		protected DESKey()
		{
			this(null, "");
		}
		
		@Override
		public String getName()
		{
			return m_name;
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
			return readFrom(key_contents);
		}
	}
	
	/**
	 * A generator for DES keys.
	 */
	public static class DESKeyGenerator extends JavaKeyGenerator
	{
		public DESKeyGenerator(SecureRandom random)
		{
			super("DES", random);
		}
		
		public DESKeyGenerator()
		{
			super("DES");
		}
		
		@Override
		public DESKey generateKey(String name) throws CryptoException
		{
			if (m_random != null)
			{
				m_generator.init(m_random);
			}
			return new DESKey(m_generator.generateKey(), name);
		}
		
		@Override
		public DESKey generateKey() throws CryptoException
		{
			return generateKey("");
		}
	}
	
	/**
	 * Converts DES keys into byte arrays.
	 * @author Sylvain Hallé
	 */
	public static class DESByteKeyConverter implements ByteKeyConverter<DESKey>
	{
		@Override
		public byte[] getBytes(DESKey key)
		{
			SecretKey sk = key.getContents();
			return sk.getEncoded();
		}

		@Override
		public DESKey getKey(byte[] contents)
		{
			return DES.readFrom(contents);
		}
	}
}
