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
import ca.uqac.lif.crypto.java.MD5;
import ca.uqac.lif.crypto.util.ByteArray;

/**
 * Calculates and prints the MD5 digest of a character string.
 */
public class MD5Hashing
{
	public static void main(String[] args) throws CryptoException
	{
		// Convert a string to a byte array
		byte[] s_bytes = "kwyjibo".getBytes();
		
		// Compute the MD5 digest of this array
		byte[] digest = MD5.instance.getDigest(s_bytes);
		
		// Print this digest to the console as a hex string
		System.out.println(ByteArray.toHexString(digest));
	}
}
