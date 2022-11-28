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

import ca.uqac.lif.azrael.ReadException;
import ca.uqac.lif.azrael.json.JsonStringReader;
import ca.uqac.lif.crypto.CryptoException;
import ca.uqac.lif.crypto.java.DES;
import ca.uqac.lif.crypto.java.DES.DESKey;
import ca.uqac.lif.crypto.java.JavaKeyChain;
import ca.uqac.lif.crypto.util.ByteArray;
import ca.uqac.lif.fs.FileSystem;
import ca.uqac.lif.fs.FileSystemException;
import ca.uqac.lif.fs.FileUtils;
import ca.uqac.lif.fs.HardDisk;

/**
 * Loads the key chain produced by the {@link SaveKeyChain} example and uses
 * one of its keys to decrypt a message.
 */
public class LoadKeyChain
{
	@SuppressWarnings("unchecked")
	public static void main(String[] args) throws CryptoException, FileSystemException, IOException, ReadException
	{
		/* Load a JSON file */
		FileSystem fs = new HardDisk().open();
		String s = FileUtils.readStringFrom(fs, "keychain.json");
		fs.close();
		
		/* Obtain a keychain out of this JSON string */
		JavaKeyChain<String,DESKey> kc = (JavaKeyChain<String,DESKey>) JsonStringReader.fromJson(s);
		
		/* Decrypt a message using Bob's key */
		byte[] decrypted = DES.instance.decrypt(kc.getKey("Bob"), ByteArray.fromHexString("79EAE9C547CBF53A9EB74A93DA037A9A"));
		System.out.println(new String(decrypted));
	}
}
