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
import ca.uqac.lif.crypto.java.DES;
import ca.uqac.lif.crypto.java.DES.DESKey;
import ca.uqac.lif.json.JsonElement;

/**
 * Generates a DES encryption key and saves it to a JSON object,
 * then retrieves the key back from this JSON object and decrypts a
 * message. 
 */
public class SaveDESKey
{
	public static void main(String[] args) throws CryptoException, PrintException, ReadException
	{
		// Generate a DES key and encrypt a string
		DESKey k1 = DES.generator.generateKey();
		byte[] encrypted = DES.instance.encrypt(k1, "Hello world".getBytes());
		
		// Serialize it in a JSON object and print it at the console
		JsonPrinter jp = new JsonPrinter();
		JsonElement je = jp.print(k1);
		System.out.println(je);
		
		// Retrieve the key from the JSON object
		JsonReader jr = new JsonReader();
		DESKey k2 = (DESKey) jr.read(je);
		
		// Decrypt the message using the retrieved key
		byte[] decrypted = DES.instance.decrypt(k2, encrypted);
		System.out.println(new String(decrypted));
	}

}
