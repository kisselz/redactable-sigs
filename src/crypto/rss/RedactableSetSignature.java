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
package crypto.rss;

import java.util.Set;
import java.util.HashMap;
import java.security.SignatureException;
import java.security.InvalidKeyException;

/**
 * This class serves as the super class for all redactable signature schemes
 * on sets.
 * @author Zach Kissel
 */
public abstract class RedactableSetSignature
{
  /**
   * Generates a keypair.
   * @return the signature key pair.
   */
  public abstract SignatureKeyPair keyGen();

  /**
   * Generates a keypair.
   * @param universe the unvirse of elements associated with the sets.
   * @return the signature key pair.
   */
  public abstract SignatureKeyPair keyGen(HashMap<String, Integer> universe);

  /**
   * Intializes the signature for signing.
   * @param sk the signing key.
   */
   public abstract void initSign(SigningKey sk);

   /**
    * Initialize the signature for redaction and verify.
    * @param vk the verification key.
    */
  public abstract void initRedactVerify(VerificationKey vk);

  /**
   * Signs the set {@code set} with signing key {@code sk}.
   * @param set the set of elements to sign.
   * @param policy the policy statement (may be {@code null}).
   * @return the signature on the set.
   * @throws InvalidKeyException if the signing key is invalid.
   * @throws SignatureException if the DSA signing algorithm fails.
   */
  public abstract SetSignature sign(Set<String> set,
      String policy) throws InvalidKeyException, SignatureException;

  /**
   * Redacts the set {@code set} to {@code subset} producing the new signature
   * from {@code sig} without the signing key.
   * @param set the original set.
   * @param subset the redacted set.
   * @param sig the signature generated on set1.
   * @param policy a possibly {@code null} policy to update to.
   * @return the signature on {@code subset}.
   */
  public abstract SetSignature redact(Set<String> set,
      Set<String> subset, SetSignature sig, String policy);

  /**
   * Verifies the signature {@code sig} on set {@code set}.
   * @param sig the purported signature on {@code set}.
   * @param set the purported set associated with the signature {@code sig}.
   * @return true if the signature is valid; otherwise, false.
   * @throws InvalidKeyException if the signing key is invalid.
   * @throws SignatureException if the DSA signing algorithm fails.
   */
  public abstract boolean vrfy(SetSignature sig,
      Set<String> set) throws InvalidKeyException, SignatureException;
}
