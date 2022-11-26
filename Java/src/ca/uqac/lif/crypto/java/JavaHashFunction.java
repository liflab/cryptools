package ca.uqac.lif.crypto.java;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import ca.uqac.lif.crypto.hash.HashFunction;

abstract class JavaHashFunction implements HashFunction
{
	/**
	 * The MessageDigest object used to compute hash values.
	 */
	/*@ null @*/ protected final MessageDigest m_digest;
	
	/**
	 * Creates a new Java hash function.
	 * @param digest The MessageDigest object used to compute hash values
	 */
	protected JavaHashFunction(/*@ non_null @*/ MessageDigest digest)
	{
		super();
		m_digest = digest;
	}
	
	@Override
	public byte[] getDigest(byte[] m)
	{
		m_digest.update(m);
		return m_digest.digest();
	}
	
	@Override
	public String toString()
	{
		return m_digest.getAlgorithm();
	}
	
	/**
	 * Gets the message digest object based on an algorithm name.
	 * @param algorithm The name of the hashing algorithm
	 * @return The instance, or <tt>null</tt> if no such algorithm exists
	 */
	protected static MessageDigest getInstance(String algorithm)
	{
		try
		{
			return MessageDigest.getInstance(algorithm);
		}
		catch (NoSuchAlgorithmException e)
		{
			return null;
		}
	}
}
