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

// JPBC
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * This class represents a basic ECC-Pairing based accumulator private key.
 *
 * @author Zach Kissel
 */
public class ECCAccumulatorPrivateKey
{
  Element g;          // The generator of G.
  Element sk;         // A random element in Z_n

  /**
   * Constructs a private key with primes {@code p} and {@code q} and
   * group generator {@code g}.
   * @param sk the private key element.
   * @param g the generator of the group.
   */
  public ECCAccumulatorPrivateKey(Element sk, Element g)
  {
    this.sk = sk;
    this.g = g;
  }

  /**
   * Loads an encoded private key.
   * @param encoded A valid encoded private key.
   * @throws IllegalArgumentException if the encoded string is not
   * of the correct format.
   */
  public ECCAccumulatorPrivateKey(byte[] encoded) throws IllegalArgumentException
  {
    ArrayList<byte[]> parts = new ArrayList<>();
    Pairing pairing = PairingFactory.getPairing("pairing.params");

    if (!DerDecoder.isEncodedSequence(encoded))
      throw new IllegalArgumentException("Invalid Accumulator Key.");

    parts = DerDecoder.decodeSequence(encoded);

    if (parts.size() != 2)
      throw new IllegalArgumentException("Invalid Accumulator Key Components");

    this.g = pairing.getG1().newElementFromBytes(
       DerDecoder.decodeOctets(parts.get(0)));
    this.sk = pairing.getZr().newElementFromBytes(
       DerDecoder.decodeOctets(parts.get(1)));
  }

  /**
   * Gets the secret portion of the key.
   * @return the secret portion of the key.
   */
  public Element getSecret()
  {
    return sk;
  }


  /**
   * Gets the generator of the group.
   * @return the generator of the group.
   */
  public Element getGenerator()
  {
    return g;
  }

  /**
   * Gets a string representation of the private key.
   * @return a string representation of the private key.
   */
  @Override
  public String toString()
  {
    return "PrivKey:\n\tGenerator: " + g + "\n\tSecret: " + sk;
  }

  /**
   * Gets a  encoded version of this key.
   * @return the private key in DER encoding.
   */
  public byte[] getEncoded()
  {
    ArrayList<byte[]> lst = new ArrayList<>();
    byte[] rv;

    lst.add(DerEncoder.encodeOctets(this.g.toBytes()));
    lst.add(DerEncoder.encodeOctets(this.sk.toBytes()));

    return DerEncoder.encodeSequence(lst);
  }
}
