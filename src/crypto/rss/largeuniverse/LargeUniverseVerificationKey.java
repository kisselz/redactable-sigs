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

import crypto.rss.VerificationKey;
import crypto.accumulator.ECCAccumulatorPublicKey;
import util.DerEncoder;
import util.DerDecoder;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.security.KeyFactory;
import java.util.Base64;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;

/**
 * Defines the verification key for the large universe construction.
 * @author Zach Kissel
 */
public class LargeUniverseVerificationKey implements VerificationKey
{

  private ECCAccumulatorPublicKey apk;
  private PublicKey pk;

  /**
   * Initializes the verification key with accumlator public key {@code apk}
   * and signature public key {@code pk}.
   * @param apk the accumulator public key.
   * @param pk the signing public key.
   */
  public LargeUniverseVerificationKey(ECCAccumulatorPublicKey apk, PublicKey pk)
  {
    this.apk = apk;
    this.pk = pk;
  }

  /**
   * Loads the encoded key from the encoded string.
   * @param encoded the encoded verification key.
   * @throws IllegalArgumentException if the key is invalid.
   */
  public LargeUniverseVerificationKey(byte[] encoded)
     throws IllegalArgumentException
  {
    if (!DerDecoder.isEncodedSequence(encoded))
      throw new IllegalArgumentException("Invalid key");

    ArrayList<byte[]> subkeys = DerDecoder.decodeSequence(encoded);
    apk = new ECCAccumulatorPublicKey(subkeys.get(0));

    X509EncodedKeySpec spec = new X509EncodedKeySpec(subkeys.get(1));
    try
    {
      pk = KeyFactory.getInstance("EC").generatePublic(spec);
    }
    catch (NoSuchAlgorithmException nsa)
    {
      System.out.println("Internal Error: Elliptic curve signing not supported.");
      System.exit(1);
    }
    catch (InvalidKeySpecException iks)
    {
      System.out.println("Bad ECDS public key.");
      System.exit(1);
    }
  }

  /**
   * Gets the accumulator public key.
   * @return the accumulator public key.
   */
  public ECCAccumulatorPublicKey getAccumulatorKey()
  {
    return apk;
  }

  /**
   * Gets the signing public key.
   * @return the signing public key.
   */
  public PublicKey getSignatureKey()
  {
    return pk;
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
     seq.add(getAccumulatorKey().getEncoded());
     seq.add(getSignatureKey().getEncoded());
     return DerEncoder.encodeSequence(seq);
   }
}
