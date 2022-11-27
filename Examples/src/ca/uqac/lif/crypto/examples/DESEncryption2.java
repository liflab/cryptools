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
import ca.uqac.lif.crypto.java.DES;
import ca.uqac.lif.crypto.java.DES.DESKey;
import ca.uqac.lif.crypto.java.DES.DESKeyGenerator;
import ca.uqac.lif.crypto.util.ByteArray;
import ca.uqac.lif.crypto.util.PredictableRandom;

/**
 * A variant of {@link DESEncryption1} using a predictable source of randomness
 * to generate the same key at every run. This example shows the utility of
 * {@link PredictableRandom} in a development or testing context. Passing an
 * instance of this class (with a fixed starting seed) to a key generator
 * ensures that the same key is used every time the program is executed, thus
 * producing predictable and repeatable encrypted strings.
 */
public class DESEncryption2 
{
	public static void main(String[] args) throws CryptoException
	{
		// Instantiate a key generator with a fixed seed
		DESKeyGenerator g = new DES.DESKeyGenerator(new PredictableRandom(0));
		
		// Generate a DES key
		DESKey k = g.generateKey();
		
		// Encrypt a string
		byte[] encrypted = DES.instance.encrypt(k, "Hello world".getBytes());
		
		// Show encrypted output
		System.out.println(ByteArray.toHexString(encrypted));
		
		// Decrypt the array
		byte[] decrypted = DES.instance.decrypt(k, encrypted);
		
		// Print message
		System.out.println(new String(decrypted));
	}
}
