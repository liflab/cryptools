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

import java.io.IOException;

import ca.uqac.lif.azrael.PrintException;
import ca.uqac.lif.azrael.json.JsonStringPrinter;
import ca.uqac.lif.crypto.CryptoException;
import ca.uqac.lif.crypto.java.DES;
import ca.uqac.lif.crypto.java.DES.DESKey;
import ca.uqac.lif.crypto.java.DES.DESKeyGenerator;
import ca.uqac.lif.crypto.java.JavaKeyChain;
import ca.uqac.lif.crypto.util.ByteArray;
import ca.uqac.lif.crypto.util.PredictableRandom;
import ca.uqac.lif.fs.FileSystem;
import ca.uqac.lif.fs.FileSystemException;
import ca.uqac.lif.fs.FileUtils;
import ca.uqac.lif.fs.HardDisk;

/**
 * Creates a simple key chain of encryption keys, saves it to a local file by
 * serializing it as a JSON string, and uses one of the keys to encrypt a
 * message. A follow-up to this program is {@link LoadKeyChain} which performs
 * the reverse operations.
 * <p>
 * The example creates symmetric encryption keys to keep the example simple.
 */
public class SaveKeyChain
{
	public static void main(String[] args) throws CryptoException, PrintException, FileSystemException, IOException
	{
		/* Create an empty key chain for DES keys */
		JavaKeyChain<String,DESKey> kc = new JavaKeyChain<>();
		
		/* Generate a few keys and add them to the keychain. We use a predictable
		 * random source so that the program generates the same keys on every run
		 * of the program. This way LoadKeyChain can correctly decrypt the
		 * message. */
		DESKeyGenerator g = new DES.DESKeyGenerator(new PredictableRandom(0));
		kc.add("Alice", g.generateKey());
		kc.add("Bob", g.generateKey());
		kc.add("Carl", g.generateKey());
		
		/* Encrypt a message using Bob's key */
		System.out.println(ByteArray.toHexString(DES.instance.encrypt(kc.getKey("Bob"), "Hello world".getBytes())));
		
		/* Save the JSON file into a file on the local drive */
		FileSystem fs = new HardDisk().open();
		FileUtils.writeStringTo(fs, JsonStringPrinter.toJson(kc), "keychain.json");
		fs.close();
	}
}
