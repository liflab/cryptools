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
import ca.uqac.lif.crypto.java.RSA;
import ca.uqac.lif.crypto.java.RSA.RSAKeyPair;
import ca.uqac.lif.crypto.util.ByteArray;

/**
 * Generates a key pair, encrypts a message using RSA, then decrypts it.
 */
public class RSAEncryption 
{
	public static void main(String[] args) throws CryptoException
	{
		// Generate an RSA key pair
		RSAKeyPair p = RSA.generator.generateKeyPair();
		
		// Encrypt a string with the public key
		byte[] encrypted = RSA.instance.encrypt(p.getPublicKey(), "Hello world".getBytes());
		
		// Show encrypted output
		System.out.println(ByteArray.toHexString(encrypted));
		
		// Decrypt the array using the private key
		byte[] decrypted = RSA.instance.decrypt(p.getPrivateKey(), encrypted);
		
		// Print message
		System.out.println(new String(decrypted));
	}
}
