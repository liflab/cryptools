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
package ca.uqac.lif.crypto.io;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.util.Map;

import ca.uqac.lif.crypto.CryptoException;
import ca.uqac.lif.crypto.Key;
import ca.uqac.lif.crypto.KeyChain;
import ca.uqac.lif.crypto.KeySerializer;
import ca.uqac.lif.fs.FileSystem;
import ca.uqac.lif.fs.FileSystemException;
import ca.uqac.lif.fs.FileUtils;

/**
 * Manages the storage of a key chain as elements of an external
 * {@link FileSystem} object.
 * @author Sylvain Hallé
 *
 * @param <K> The type of the keys stored in the key chain
 */
public class KeyChainSerializer<T>
{
	/*@ non_null @*/ protected final KeySerializer<T> m_serializer;
	
	public KeyChainSerializer(/*@ non_null @*/ KeySerializer<T> serializer)
	{
		super();
		m_serializer = serializer;
	}
	
	/**
	 * Saves the contents of the key chain to a file system.
	 * @param kc The key chain to serialize
	 * @param fs The file system to save the key chain to
	 * @throws CryptoException Thrown if the keys cannot be converted to byte
	 * arrays
	 * @throws FileSystemException Thrown if the keys cannot be saved to the
	 * file system
	 * @throws IOException Thrown if the keys cannot be saved to the
	 * file system  
	 */
	public void save(/*@ non_null @*/ KeyChain<String,T> kc, /*@ non_null @*/ FileSystem fs) throws CryptoException, FileSystemException, IOException
	{
		for (Map.Entry<String,Key<T>> entry : kc.entrySet())
		{
			String filename = entry.getKey().toString();
			byte[] key_contents = m_serializer.getBytes(entry.getValue());
			BufferedOutputStream bos = new BufferedOutputStream(fs.writeTo(filename));
			bos.write(key_contents);
			bos.close();
		}
	}
	
	/**
	 * Populates the contents of a key chain from a file system.
	 * @param kc The key chain to populate
	 * @param fs The file system to read the key chain from
	 * @throws CryptoException Thrown if the keys cannot be obtained from byte
	 * arrays
	 * @throws FileSystemException Thrown if the keys cannot be read from the
	 * file system
	 * @throws IOException Thrown if the keys cannot be read from the
	 * file system
	 */
	public void load(/*@ non_null @*/ KeyChain<String,T> kc, /*@ non_null @*/ FileSystem fs) throws CryptoException, FileSystemException, IOException
	{
		for (String filename : fs.ls())
		{
			BufferedInputStream bis = new BufferedInputStream(fs.readFrom(filename));
			byte[] key_contents = FileUtils.toBytes(bis);
			bis.close();
			Key<T> k = m_serializer.getKey(key_contents);
			kc.add(filename, k);
		}
	}
}
