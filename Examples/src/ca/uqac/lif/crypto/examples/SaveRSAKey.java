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

import ca.uqac.lif.azrael.PrintException;
import ca.uqac.lif.azrael.ReadException;
import ca.uqac.lif.azrael.json.JsonPrinter;
import ca.uqac.lif.azrael.json.JsonReader;
import ca.uqac.lif.crypto.CryptoException;
import ca.uqac.lif.crypto.java.RSA;
import ca.uqac.lif.crypto.java.RSA.RSAKeyPair;
import ca.uqac.lif.crypto.java.RSA.RSAPublicKey;
import ca.uqac.lif.json.JsonElement;

/**
 * Generates an RSA encryption key pair and saves it to a JSON object,
 * then retrieves the pair back from this JSON object and decrypts a
 * message. 
 */
public class SaveRSAKey
{
	public static void main(String[] args) throws CryptoException, PrintException, ReadException
	{
		// Generate an RSA key pair and encrypt a string
		RSAKeyPair p = RSA.generator.generateKeyPair();
		byte[] encrypted = RSA.instance.encrypt(p.getPrivateKey(), "Hello world".getBytes());
		
		// Serialize the public key in a JSON object and print it at the console
		JsonPrinter jp = new JsonPrinter();
		JsonElement je = jp.print(p);
		System.out.println(je);
		
		// Retrieve the key from the JSON object
		JsonReader jr = new JsonReader();
		RSAPublicKey k2 = ((RSAKeyPair) jr.read(je)).getPublicKey();
		
		// Decrypt the message using the retrieved key
		byte[] decrypted = RSA.instance.decrypt(k2, encrypted);
		System.out.println(new String(decrypted));
	}

}
