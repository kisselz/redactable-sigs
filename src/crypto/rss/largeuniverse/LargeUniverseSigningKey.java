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
package crypto.rss.largeuniverse;

import crypto.rss.SigningKey;
import crypto.accumulator.AccumulatorPrivateKey;
import util.DerEncoder;
import util.DerDecoder;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.KeyFactory;
import java.util.Base64;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;

/**
 * Defines the signing key for the large universe construction.
 * @author Zach Kissel
 */
public class LargeUniverseSigningKey implements SigningKey
{
  private AccumulatorPrivateKey ask;
  private PrivateKey sk;

  /**
   * Constructs a new signing key with accumulator private key {@code ask}
   * and private key {@code sk}.
   * @param ask the accumulator private key.
   * @param sk the private key for the signature algorithm.
   */
  public LargeUniverseSigningKey(AccumulatorPrivateKey ask, PrivateKey sk)
  {
    this.ask = ask;
    this.sk = sk;
  }

  /**
   * Loads the encoded key from the encoded string.
   * @param encoded the encoded verification key.
   * @throws IllegalArgumentException if the key is invalid.
   */
  public LargeUniverseSigningKey(byte[] encoded)
     throws IllegalArgumentException
  {
    if (!DerDecoder.isEncodedSequence(encoded))
      throw new IllegalArgumentException("Invalid key");

    ArrayList<byte[]> subkeys = DerDecoder.decodeSequence(encoded);
    ask = new AccumulatorPrivateKey(subkeys.get(0));

    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(subkeys.get(1));
    try
    {
      sk = KeyFactory.getInstance("EC").generatePrivate(spec);
    }
    catch (NoSuchAlgorithmException nsa)
    {
      System.out.println("Internal Error: Elliptic curve signing not supported.");
      System.exit(1);
    }
    catch (InvalidKeySpecException iks)
    {
      System.out.println("Bad ECDS private key.");
      System.exit(1);
    }
  }
  /**
   * Gets the accumulator private key.
   * @return the accumulator private key.
   */
  public AccumulatorPrivateKey getAccumulatorKey()
  {
    return ask;
  }

  /**
   * Gets the signing private key.
   * @return the signature algorithm private key.
   */
  public PrivateKey getSignatureKey()
  {
    return sk;
  }

  /**
   * Gets the algorithm this key is associated with.
   * @return the algorithm name.
   */
  public String getAlgorithm()
  {
    return "large-universe-set";
  }

  /**
   * Get the encoded version of the key.
   * @return the DER encoded key.
   */
   public byte[] getEncoded()
   {
     ArrayList<byte[]> seq = new ArrayList<>();
     seq.add(ask.getEncoded());
     seq.add(sk.getEncoded());
     return DerEncoder.encodeSequence(seq);
   }

}
