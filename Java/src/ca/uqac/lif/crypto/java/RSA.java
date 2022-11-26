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

import javax.crypto.SecretKey;

import ca.uqac.lif.crypto.CryptoException;
import ca.uqac.lif.crypto.symmetric.SymmetricCipher;
import ca.uqac.lif.crypto.symmetric.SymmetricKey;

/**
 * 
 * @author Sylvain Hallé
 *
 */
public class RSA extends JavaCipher implements SymmetricCipher<SecretKey>
{
	/**
	 * A single publicly visible instance of the hash function.
	 */
	public static final RSA instance = new RSA();
	
	/**
	 * Creates a new DES encryption function.
	 */
	protected RSA()
	{
		super(getInstance("RSA"));
	}

	@Override
	public byte[] encrypt(SymmetricKey<SecretKey> k, byte[] m) throws CryptoException
	{
		return cipherEncrypt(k.getContents(), m);
	}

	@Override
	public byte[] decrypt(SymmetricKey<SecretKey> k, byte[] m) throws CryptoException 
	{
		return cipherDecrypt(k.getContents(), m);
	}
}
