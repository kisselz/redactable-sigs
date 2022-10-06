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
import util.DerEncoder;
import util.DerDecoder;
import java.util.ArrayList;

/**
 * This class represents the RSA accumulator public key as described in
 * "Collision-Free Accumulators and Fail-Stop Signature Schemes Without Trees"
 * By Niko Baric and Birgit Pfitzmann.
 *
 * @author Zach Kissel
 */
public class AccumulatorPublicKey
{
  BigInteger modulus;
  BigInteger generator;

  /**
   * Constructs a new public key with modulus {@code n} and generator
   * {@code g}.
   * @param n the modulus of the group.
   * @param g the generator of the group.
   */
  public AccumulatorPublicKey(BigInteger n, BigInteger g)
  {
    modulus = n;
    generator = g;
  }

  /**
   * Loads an encoded public key.
   * @param encoded A valid encoded private key.
   * @throws IllegalArgumentException if the encoded string is not
   * of the correct format.
   */
  public AccumulatorPublicKey(byte[] encoded) throws IllegalArgumentException
  {
    ArrayList<byte[]> parts = new ArrayList<>();

    if (!DerDecoder.isEncodedSequence(encoded))
      throw new IllegalArgumentException("Invalid Accumulator Key.");

    parts = DerDecoder.decodeSequence(encoded);

    if (parts.size() != 2)
      throw new IllegalArgumentException("Invalid Accumulator Key Components");

    generator = DerDecoder.decodeBigInteger(parts.get(0));
    modulus = DerDecoder.decodeBigInteger(parts.get(1));
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
   * Gets the modulus of the group.
   * @return the modulus of the group.
   */
  public BigInteger getModulus()
  {
    return modulus;
  }

  /**
   * Gets a string representation of the public key.
   * @return a string representation of the public key.
   */
  @Override
  public String toString()
  {
    return "PubKey:\n\tGenerator: " + generator + "\n\tModulus: " + modulus;
  }

  /**
   * Gets a DER encoded version of this key.
   * @return a base 64 encoded version of the key.
   */
  public byte[] getEncoded()
  {
    ArrayList<byte[]> lst = new ArrayList<>();
    byte[] rv;
    lst.add(DerEncoder.encodeBigInteger(generator));
    lst.add(DerEncoder.encodeBigInteger(modulus));

    return DerEncoder.encodeSequence(lst);

  }
}
