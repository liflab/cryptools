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
package ca.uqac.lif.crypto.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;

/**
 * Utilities to manipulate and display byte arrays.
 * 
 * @author Sylvain Hallé
 */
public abstract class ByteArray
{
	/**
	 * Prints the content of a byte array as a hexadecimal string into an
	 * output stream.
	 * @param os The output stream to write to
	 * @param array The byte array to write
	 */
	public static void printHexString(/*@ non_null @*/ OutputStream os, /*@ non_null @*/ byte[] array)
	{
		PrintStream ps = new PrintStream(os);
		for (byte b : array)
		{
			ps.print(String.format("%02X", b));
		}
	}

	/**
	 * Returns the contents of a byte array as a hexadecimal string.
	 * @param array The byte array to convert
	 * @return The hexadecimal string
	 */
	/*@ non_null @*/ public static String toHexString(/*@ non_null @*/ byte[] array)
	{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		printHexString(baos, array);
		return baos.toString();
	}

	public static byte[] readHexString(/*@ non_null @*/ InputStream is)
	{
		byte[] s_bytes;
		try
		{
			s_bytes = is.readAllBytes();
		}
		catch (IOException e) 
		{
			return new byte[0];
		}
		String s = new String(s_bytes);
		byte[] ans = new byte[s.length() / 2];;
		for (int i = 0; i < ans.length; i++) 
		{
			int index = i * 2;
			int val = Integer.parseInt(s.substring(index, index + 2), 16);
			ans[i] = (byte)val;
		}
		return ans;
	}
	
	public static byte[] fromHexString(String s)
	{
		return readHexString(new ByteArrayInputStream(s.getBytes()));
	}
	
	
}
