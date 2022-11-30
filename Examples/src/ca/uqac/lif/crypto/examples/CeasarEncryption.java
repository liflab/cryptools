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
package ca.uqac.lif.crypto.examples;

import ca.uqac.lif.crypto.CryptoException;
import ca.uqac.lif.crypto.symmetric.SymmetricCipher;
import ca.uqac.lif.crypto.symmetric.SymmetricKey;

/**
 * Implements a custom {@link SymmetricCipher} class performing a simple shift
 * cipher on character strings known as
 * <a href="https://en.wikipedia.org/wiki/Caesar_cipher">Ceasar cipher</a>.
 */
public class CeasarEncryption
{
	public static void main(String[] args) throws CryptoException
	{
		// Create a cipher, and a key that will offset characters by 3 positions
		CeasarCipher cipher = new CeasarCipher();
		CeasarKey k = new CeasarKey(3);

		// Encrypt a string and print it; should produce "KHOOR"
		String encrypted = cipher.encrypt(k, "HELLO");
		System.out.println(encrypted);

		// Decrypt the string
		String decrypted = cipher.decrypt(k, encrypted);
		System.out.println(decrypted);
	}

	/**
	 * Implementation of the Ceasar cipher on character strings.
	 */	
	public static class CeasarCipher implements SymmetricCipher<CeasarKey,String>
	{
		@Override
		public String encrypt(CeasarKey k, String m) throws CryptoException
		{
			StringBuilder out = new StringBuilder();
			for (int i = 0; i < m.length(); i++)
			{
				out.append((char) (m.charAt(i) + k.getOffset()));
			}
			return out.toString();
		}

		@Override
		public String decrypt(CeasarKey k, String m) throws CryptoException
		{
			StringBuilder out = new StringBuilder();
			for (int i = 0; i < m.length(); i++)
			{
				out.append((char) (m.charAt(i) - k.getOffset()));
			}
			return out.toString();
		}
	}

	/**
	 * A key used by the Ceasar cipher. In this case, the key is simply an
	 * integer number representing by how many characters forward or backward in
	 * the alphabet each input character should be shifted.
	 */
	public static class CeasarKey implements SymmetricKey
	{
		/**
		 * The number of characters by which to offset the original message.
		 */
		protected final int m_offset;

		/**
		 * Creates a new key with a given offset.
		 * @param offset The offset
		 */
		public CeasarKey(int offset)
		{
			super();
			m_offset = offset;
		}

		public Integer getOffset()
		{
			return m_offset;
		}
	}
}
