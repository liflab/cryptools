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
import ca.uqac.lif.crypto.stubs.DummyHashFunction.HashValue;

/**
 * Unit tests for {@link DummyHashFunction}.
 */
public class DummyHashFunctionTest
{
	@Test
	public void test1() throws CryptoException
	{
		Object h1 = DummyHashFunction.instance.getDigest("abc");
		Object h2 = DummyHashFunction.instance.getDigest("def");
		assertNotEquals(h1, h2);
	}
	
	@Test
	public void test2() throws CryptoException
	{
		Object h1 = DummyHashFunction.instance.getDigest("abc");
		Object h2 = DummyHashFunction.instance.getDigest("abc");
		assertEquals(h1, h2);
	}
	
	@Test
	public void test3() throws CryptoException
	{
		Object h1 = DummyHashFunction.instance.getDigest("abc");
		assertTrue(h1 instanceof HashValue);
		assertEquals("H(abc)", h1.toString());
	}
}
