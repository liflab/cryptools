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
package ca.uqac.lif.crypto.stubs;

import ca.uqac.lif.crypto.CryptoException;
import ca.uqac.lif.crypto.Key;
import ca.uqac.lif.crypto.asymmetric.KeyPair;
import ca.uqac.lif.crypto.asymmetric.KeyPairGenerator;
import ca.uqac.lif.crypto.asymmetric.ObjectAsymmetricCipher;
import ca.uqac.lif.crypto.asymmetric.PrivateKey;
import ca.uqac.lif.crypto.asymmetric.PublicKey;

public class DummyAsymmetricCipher implements ObjectAsymmetricCipher<ca.uqac.lif.crypto.stubs.DummyAsymmetricCipher.DummyPublicKey,ca.uqac.lif.crypto.stubs.DummyAsymmetricCipher.DummyPrivateKey>
{
	/**
	 * A single publicly visible instance of the dummy asymmetric cipher.
	 */
	public static final DummyAsymmetricCipher instance = new DummyAsymmetricCipher();
	
	/**
	 * A static reference to an instance of key generator with default
	 * settings.
	 */
	public static final DummyKeyPairGenerator generator = new DummyKeyPairGenerator();
	
	/**
	 * Creates a new instance of the cipher.
	 */
	protected DummyAsymmetricCipher()
	{
		super();
	}
	
	@Override
	public Object encrypt(DummyPublicKey k, Object m) throws CryptoException
	{
		return dummyEncrypt(k, m);
	}

	@Override
	public Object encrypt(DummyPrivateKey k, Object m) throws CryptoException
	{
		return dummyEncrypt(k, m);
	}

	@Override
	public Object decrypt(DummyPublicKey k, Object m) throws CryptoException
	{
		return dummyDecrypt(k.getName(), m);
	}

	@Override
	public Object decrypt(DummyPrivateKey k, Object m) throws CryptoException
	{
		return dummyDecrypt(k.getName(), m);
	}
	
	/**
	 * Performs the "dummy" encryption of an object.
	 * @param k The key used to perform the encryption
	 * @param m The object to encrypt
	 * @return The encrypted object
	 * @throws CryptoException Thrown if the encryption could not proceed
	 */
	protected Object dummyEncrypt(Key k, Object m) throws CryptoException
	{
		return new EncryptedObject(k, m);
	}
	
	/**
	 * Performs the "dummy" decryption of an object.
	 * @param key_name The name of the key used to decrypt
	 * @param m The object to decrypt
	 * @return The decrypted object
	 * @throws CryptoException Thrown if the decryption could not proceed
	 */
	protected Object dummyDecrypt(String key_name, Object m) throws CryptoException
	{
		if (!(m instanceof EncryptedObject))
		{
			throw new CryptoException("Invalid input object type");
		}
		EncryptedObject eo = (EncryptedObject) m;
		if (!samePair(key_name, eo.getKeyName()))
		{
			throw new CryptoException("Cannot decrypt object");
		}
		return eo.m_object;
	}
	
	/**
	 * A dummy private key.
	 */
	public static class DummyPrivateKey implements PrivateKey
	{
		/**
		 * The name of the key's owner.
		 */
		/*@ non_null @*/ protected final String m_owner;
		
		/**
		 * Creates a new dummy private key.
		 * @param owner The owner of the key
		 * @throws CryptoException Thrown if owner is null or blank
		 */
		DummyPrivateKey(/*@ non_null @*/ String owner) throws CryptoException
		{
			super();
			if (owner == null || owner.isBlank())
			{
				throw new CryptoException("Owner cannot be empty");
			}
			m_owner = owner;
		}
		
		/**
		 * Gets the name of the key's owneré
		 * @return Tha name
		 */
		/*@ pure non_null @*/ String getOwner()
		{
			return m_owner;
		}
		
		@Override
		public String getName()
		{
			return "PR_" + m_owner;
		}
		
		@Override
		public int hashCode()
		{
			return m_owner.hashCode();
		}
		
		@Override
		public boolean equals(Object o)
		{
			if (!(o instanceof DummyPrivateKey))
			{
				return false;
			}
			return ((DummyPrivateKey) o).m_owner.compareTo(m_owner) == 0;
		}
		
		@Override
		public String toString()
		{
			return getName();
		}
	}
	
	/**
	 * A dummy public key.
	 */
	public static class DummyPublicKey implements PublicKey
	{
		/**
		 * The name of the key's owner.
		 */
		/*@ non_null @*/ protected final String m_owner;
		
		/**
		 * Creates a new dummy public key.
		 * @param owner The owner of the key
		 * @throws CryptoException Thrown if owner is null or blank
		 */
		DummyPublicKey(/*@ non_null @*/ String owner) throws CryptoException
		{
			super();
			if (owner == null || owner.isBlank())
			{
				throw new CryptoException("Owner cannot be empty");
			}
			m_owner = owner;
		}
		
		/**
		 * Gets the name of the key's owneré
		 * @return Tha name
		 */
		/*@ pure non_null @*/ String getOwner()
		{
			return m_owner;
		}
		
		@Override
		public String getName()
		{
			return "PU_" + m_owner;
		}
		
		@Override
		public int hashCode()
		{
			return m_owner.hashCode() + 1;
		}
		
		@Override
		public boolean equals(Object o)
		{
			if (!(o instanceof DummyPublicKey))
			{
				return false;
			}
			return ((DummyPublicKey) o).m_owner.compareTo(m_owner) == 0;
		}
		
		@Override
		public String toString()
		{
			return getName();
		}
	}
	
	/**
	 * A generator of dummy key pairs.
	 */
	public static class DummyKeyPairGenerator implements KeyPairGenerator<DummyPublicKey,DummyPrivateKey>
	{
		@Override
		public KeyPair<DummyPublicKey,DummyPrivateKey> generateKeyPair() throws CryptoException
		{
			return generateKeyPair("", "");
		}

		@Override
		public KeyPair<DummyPublicKey,DummyPrivateKey> generateKeyPair(String pu, String pr) throws CryptoException
		{
			return new DummyKeyPair(new DummyPublicKey(pu), new DummyPrivateKey(pr));
		}
	}
	
	/**
	 * A pair of dummy public and private keys.
	 */
	protected static class DummyKeyPair implements KeyPair<DummyPublicKey,DummyPrivateKey>
	{
		/**
		 * The private key of this key pair.
		 */
		protected final DummyPrivateKey m_privateKey;
		
		/**
		 * The public key of this key pair.
		 */
		protected final DummyPublicKey m_publicKey;
		
		/**
		 * Creates a new dummy key pair.
		 * @param pu The public key of this key pair
		 * @param pr The private key of this key pair
		 */
		public DummyKeyPair(DummyPublicKey pu, DummyPrivateKey pr)
		{
			super();
			m_publicKey = pu;
			m_privateKey = pr;
		}
		
		@Override
		public DummyPrivateKey getPrivateKey() throws CryptoException
		{
			return m_privateKey;
		}

		@Override
		public DummyPublicKey getPublicKey() throws CryptoException
		{
			return m_publicKey;
		}

		@Override
		public KeyPair<DummyPublicKey, DummyPrivateKey> getOnlyPublic() throws CryptoException
		{
			return new DummyKeyPair(m_publicKey, null);
		}
		
		@Override
		public String toString()
		{
			return "<" + m_publicKey + "," + m_privateKey + ">";
		}
	}
	
	/**
	 * Determines if two keys correspond to the private and public key of the
	 * same pair of <em>dummy</em> asymmetric keys.
	 * @param k1 The first key
	 * @param k2 The second key
	 * @return <tt>true</tt> if the keys are of the same pair, <tt>false</tt>
	 * otherwise
	 */
	protected static boolean samePair(Key k1, Key k2)
	{
		if (k1 instanceof DummyPrivateKey && k2 instanceof DummyPublicKey)
		{
			return ((DummyPrivateKey) k1).getOwner().compareTo(((DummyPublicKey) k2).getOwner()) == 0;
		}
		if (k1 instanceof DummyPublicKey && k2 instanceof DummyPrivateKey)
		{
			return ((DummyPublicKey) k1).getOwner().compareTo(((DummyPrivateKey) k2).getOwner()) == 0;
		}
		return false;
	}
	
	/**
	 * Determines if two strings correspond to names of the private and public
	 * key of the same pair of <em>dummy</em> asymmetric keys.
	 * @param name1 The first name
	 * @param name2 The second name
	 * @return <tt>true</tt> if the names correspond to keys are of the same
	 * pair, <tt>false</tt> otherwise
	 */
	protected static boolean samePair(String name1, String name2)
	{
		if ((name1.startsWith("PR_") && name2.startsWith("PU_")) || (name1.startsWith("PU_") && name2.startsWith("PR_")))
		{
			return name1.substring(3).compareTo(name2.substring(3)) == 0;
		}
		return false;
	}
}
