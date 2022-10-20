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

// JPBC
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import util.DerEncoder;
import util.DerDecoder;
import java.util.ArrayList;

/**
 * This class represents a basic ECC-Pairing based accumulator private key.
 *
 * @author Zach Kissel
 */

public class ECCAccumulatorPublicKey
{
  Element g;            // The generator.
  Element pk;           // the public key element.

  /**
   * Constructs a new public key with public key value {@code pk} and generator
   * {@code g}.
   * @param pk the public key value.
   * @param g the generator of the group.
   */
  public ECCAccumulatorPublicKey(Element pk, Element g)
  {
    this.pk = pk;
    this.g = g;
  }

  /**
   * Loads an encoded public key.
   * @param encoded A valid encoded private key.
   * @throws IllegalArgumentException if the encoded string is not
   * of the correct format.
   */
  public ECCAccumulatorPublicKey(byte[] encoded) throws IllegalArgumentException
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
      this.pk = pairing.getG1().newElementFromBytes(
         DerDecoder.decodeOctets(parts.get(1)));
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
   * Gets the public key value.
   * @return the public key value.
   */
  public Element getPublic()
  {
    return pk;
  }

  /**
   * Gets a string representation of the public key.
   * @return a string representation of the public key.
   */
  @Override
  public String toString()
  {
    return "PubKey:\n\tGenerator: " + g + "\n\tPublic: " + pk;
  }

  /**
   * Gets a DER encoded version of this key.
   * @return a base 64 encoded version of the key.
   */
  public byte[] getEncoded()
  {
    ArrayList<byte[]> lst = new ArrayList<>();

    lst.add(DerEncoder.encodeOctets(this.g.toBytes()));
    lst.add(DerEncoder.encodeOctets(this.pk.toBytes()));


    return DerEncoder.encodeSequence(lst);

  }
}
