/*
 *   Policy-Based Redactable Set Signature Schemes
 *   Copyright (C) 2022  Zachary A. Kissel
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package crypto.accumulator;

import java.math.BigInteger;
import java.util.ArrayList;
import util.DerEncoder;
import util.DerDecoder;

/**
 * This class represents the RSA accumulator private key as described in
 * "Collision-Free Accumulators and Fail-Stop Signature Schemes Without Trees"
 * By Niko Baric and Birgit Pfitzmann.
 *
 * @author Zach Kissel
 */
public class AccumulatorPrivateKey
{
  BigInteger modulus;
  BigInteger primeP;
  BigInteger primeQ;
  BigInteger generator;

  /**
   * Constructs a private key with primes {@code p} and {@code q} and
   * group generator {@code g}.
   * @param p a large prime number.
   * @param q a large prime number.
   * @param g the generator of the group.
   */
  public AccumulatorPrivateKey(BigInteger p, BigInteger q, BigInteger g)
  {
    modulus = p.multiply(q);
    primeP = p;
    primeQ = q;
    generator = g;
  }

  /**
   * Loads an encoded private key.
   * @param encoded A valid encoded private key.
   * @throws IllegalArgumentException if the encoded string is not
   * of the correct format.
   */
  public AccumulatorPrivateKey(byte[] encoded) throws IllegalArgumentException
  {
    ArrayList<byte[]> parts = new ArrayList<>();

    if (!DerDecoder.isEncodedSequence(encoded))
      throw new IllegalArgumentException("Invalid Accumulator Key.");

    parts = DerDecoder.decodeSequence(encoded);

    if (parts.size() != 3)
      throw new IllegalArgumentException("Invalid Accumulator Key Components");

    generator = DerDecoder.decodeBigInteger(parts.get(0));
    primeP = DerDecoder.decodeBigInteger(parts.get(1));
    primeQ = DerDecoder.decodeBigInteger(parts.get(2));

    // Compute the modulus since we don't need to store it.
    modulus = primeP.multiply(primeQ);
  }

  /**
   * Gets the prime number {@code p}.
   * @return the prime number {@code p}.
   */
  public BigInteger getP()
  {
    return primeP;
  }

  /**
   * Gets the prime number {@code q}.
   * @return the prime number {@code q}.
   */
  public BigInteger getQ()
  {
    return primeQ;
  }

  /**
   * Gets the modulus of the group.
   * @return the modulus of the group.
   */
  public BigInteger getModulus()
  {
    return modulus;
  }

  /**
   * Gets the generator of the group.
   * @return the generator of the group.
   */
  public BigInteger getGenerator()
  {
    return generator;
  }

  /**
   * Gets a string representation of the private key.
   * @return a string representation of the private key.
   */
  @Override
  public String toString()
  {
    return "PrivKey:\n\tGenerator: " + generator + "\n\tModulus: " + modulus +
        "\n\tP: " + primeP + "\n\tQ: " + primeQ;
  }

  /**
   * Gets a base64 encoded version of this key.
   * @return the private key in DER encoding.
   */
  public byte[] getEncoded()
  {
    ArrayList<byte[]> lst = new ArrayList<>();
    byte[] rv;
    lst.add(DerEncoder.encodeBigInteger(generator));
    lst.add(DerEncoder.encodeBigInteger(primeP));
    lst.add(DerEncoder.encodeBigInteger(primeQ));

    return DerEncoder.encodeSequence(lst);
  }
}
