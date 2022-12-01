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
package ca.uqac.lif.crypto.stubs;

import static org.junit.Assert.*;

import org.junit.Test;

import ca.uqac.lif.crypto.CryptoException;
import ca.uqac.lif.crypto.stubs.DummySymmetricCipher.DummySymmetricKey;
import ca.uqac.lif.crypto.symmetric.SymmetricKey;

/**
 * Unit tests for {@link DummySymmetricCipher}.
 */
public class DummySymmetricCipherTest
{
	@Test
	public void testKeys1() throws CryptoException
	{
		SymmetricKey k1 = DummySymmetricCipher.generator.generateKey("k1");
		SymmetricKey k2 = DummySymmetricCipher.generator.generateKey("k2");
		assertNotEquals(k1, k2);
	}
	
	@Test
	public void testKeys2() throws CryptoException
	{
		SymmetricKey k1 = DummySymmetricCipher.generator.generateKey("k1");
		SymmetricKey k2 = DummySymmetricCipher.generator.generateKey("k1");
		assertEquals(k1, k2);
	}
	
	@Test(expected = CryptoException.class)
	public void testKeys3() throws CryptoException
	{
		DummySymmetricCipher.generator.generateKey();
	}
	
	@Test
	public void testEncryption1() throws CryptoException
	{
		DummySymmetricKey k1 = DummySymmetricCipher.generator.generateKey("k1");
		Object o1 = DummySymmetricCipher.instance.encrypt(k1, "abc");
		assertEquals("abc", DummySymmetricCipher.instance.decrypt(k1, o1));
	}
	
	@Test(expected = CryptoException.class)
	public void testEncryption2() throws CryptoException
	{
		DummySymmetricKey k1 = DummySymmetricCipher.generator.generateKey("k1");
		DummySymmetricKey k2 = DummySymmetricCipher.generator.generateKey("k2");
		Object o1 = DummySymmetricCipher.instance.encrypt(k1, "abc");
		DummySymmetricCipher.instance.decrypt(k2, o1);
	}
	
	@Test(expected = CryptoException.class)
	public void testEncryption3() throws CryptoException
	{
		DummySymmetricKey k1 = DummySymmetricCipher.generator.generateKey("k1");
		DummySymmetricCipher.instance.decrypt(k1, "abc");
	}
	
	@Test
	public void testEncryption4() throws CryptoException
	{
		DummySymmetricKey k1 = DummySymmetricCipher.generator.generateKey("k1");
		Object o1 = DummySymmetricCipher.instance.encrypt(k1, "abc");
		assertTrue(o1 instanceof EncryptedObject);
		assertEquals("E[k1,abc]", o1.toString());
	}
}
