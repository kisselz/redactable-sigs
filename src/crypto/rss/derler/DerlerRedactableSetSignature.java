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
package crypto.rss.derler;

import util.Pair;
import util.Tuple;
import crypto.rss.SetSignature;
import crypto.rss.SignatureKeyPair;
import crypto.rss.SigningKey;
import crypto.rss.VerificationKey;
import crypto.rss.RedactableSetSignature;
import crypto.accumulator.ECCAccumulatorKeyPair;
import crypto.accumulator.ECCAccumulator;

import java.math.BigInteger;
import java.util.Set;
import java.util.HashSet;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.BitSet;
import java.security.Signature;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.InvalidKeyException;
import java.security.spec.ECGenParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;


/**
 * This class implements the Derler et. al redactable set signature scheme
 * found in:
 * <p>
 * "A General Framework for Redactable Signatures and New Constructions"
 * <br />
 * David Derler, Henrich C. Pohls, Kai Samelin, Daniel Slamanig
 * </p>
 *
 * @author Zach Kissel
 */
public class DerlerRedactableSetSignature extends RedactableSetSignature
{
  private DerlerSigningKey sk;
  private DerlerVerificationKey vk;
  private Signature signScheme;

  /**
   * Constructs a new redactable set signature.
   */
  public DerlerRedactableSetSignature()
  {
    try
    {
      signScheme = Signature.getInstance("SHA256withECDSA");
    }
    catch(NoSuchAlgorithmException nsa)
    {
      System.out.println("Internal Error: ECDSA is not supported.");
      System.exit(1);
    }
  }

  /**
  * Generates a keypair. Generates an empty universe.
  * @param universe the universe to draw the values from.
  * @return the signature key pair.
  */
  public SignatureKeyPair keyGen(HashMap<String, Integer> universe)
  {
    return keyGen();
  }

  /**
   * Generates a keypair.
   * @return the signature key pair.
   */
  public SignatureKeyPair keyGen()
  {
    ECCAccumulatorKeyPair akp = ECCAccumulator.keyGen();
    KeyPairGenerator keygen = null;

    try
    {
      keygen = KeyPairGenerator.getInstance("EC");
      keygen.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
    }
    catch(NoSuchAlgorithmException nsa)
    {
      System.out.println("Internal Error: ECDSA is not supported.");
      System.exit(1);
    }
    catch(InvalidAlgorithmParameterException iap)
    {
      System.out.println("Internal Error: Curve P-256 not available.");
      System.exit(1);
    }

    KeyPair kp = keygen.genKeyPair();

    return new SignatureKeyPair(
        new DerlerSigningKey(akp.getPrivate(), kp.getPrivate()),
        new DerlerVerificationKey(akp.getPublic(), kp.getPublic()));
  }


  /**
   * Initializes the signature for signing.
   * @param sk the signing key.
   */
   public void initSign(SigningKey sk)
   {
      this.sk = (DerlerSigningKey) sk;
      this.vk = null;
   }

   /**
    * Initialize the signature for redaction and verify.
    * @param vk the verification key.
    */
  public void initRedactVerify(VerificationKey vk)
  {
    this.vk = (DerlerVerificationKey) vk;
    this.sk = null;
  }

  /**
   * Signs the set {@code set} with signing key {@code sk}.
   * @param set the set of elements to sign.
   * @param policy the policy statement written as a charactersistic
   * sequences separated by commas.
   * @return the signature on the set.
   * @throws InvalidKeyException if the signing key is invalid.
   * @throws SignatureException if the DSA signing algorithm fails.
   */
  public SetSignature sign(Set<String> set, String policy)
    throws InvalidKeyException, SignatureException
  {
    ECCAccumulator accumulator = new ECCAccumulator();
    HashMap<String, byte[]> witnesses = new HashMap<>();
    byte[] acc;

    if (policy != null)
      throw new SignatureException("Policy not supported.");

    // Build the accumulator.
    accumulator.initAccumulate(sk.getAccumulatorKey());
    acc = accumulator.eval(set);

    // Build the collection of witnesses.
    for (String ele : set)
      witnesses.put(ele, accumulator.getWitness(ele, acc));

    // Generate the signature on the accumulator value and secret.
    signScheme.initSign(sk.getSignatureKey());
    signScheme.update(acc);
    byte[] signature = signScheme.sign();

    return new DerlerSetSignature(acc, signature, witnesses);
  }

  /**
   * Redacts the set {@code set} to {@code subset} producing the new signature
   * from {@code sig} without the signing key.
   * @param set the original set.
   * @param subset the redacted set.
   * @param sig the signature generated on set1.
   * @param policy a possibly {@code null} policy to update to.
   * @return the signature on {@code subset}.
   */
  public SetSignature redact(Set<String> set,
      Set<String> subset, SetSignature sig, String policy)
  {
    DerlerSetSignature theSig = (DerlerSetSignature) sig;

    // Parse the components of the signature.
    HashMap<String, byte[]> witnesses = theSig.getWitnesses();

    // Verify that setubst is a subset of set
    if (!set.containsAll(subset))
      return null;

    for (String ele : subset)
      if (!witnesses.containsKey(ele))
        return null;

    // At this point we know that we have a valid redaction.
    // We no proceed to perform the redaction by removing the
    // witnesses that are no longer valid.
    Set<String> keys = witnesses.keySet();
    HashSet<String> toRemove = new HashSet<>();
    for (String key : set)
      if (!subset.contains(key))
        toRemove.add(key);

    for (String key : toRemove)
        witnesses.remove(key);

    return new DerlerSetSignature(theSig.getAccumulator(),
        theSig.getSignature(), witnesses);
  }

  /**
   * Verifies the signature {@code sig} on set {@code set}.
   * @param sig the purported signature on {@code set}.
   * @param set the purported set associated with the signature {@code sig}.
   * @return true if the signature is valid; otherwise, false.
   * @throws InvalidKeyException if the signing key is invalid.
   * @throws SignatureException if the DSA signing algorithm fails.
   */
  public boolean vrfy(SetSignature sig, Set<String> set)
    throws InvalidKeyException, SignatureException
  {
    DerlerSetSignature theSig = (DerlerSetSignature) sig;
    ECCAccumulator accumulator = new ECCAccumulator();
    String element;

    // Get the witness and share components of the signature.
    HashMap<String, byte[]> witnesses = theSig.getWitnesses();

    // Verify the set elements and shares are correct by building
    // the charactersitic sequence and checking and verifying the
    // witness.
    accumulator.initVerify(vk.getAccumulatorKey());

    // Verify the accumulator membership for each element in
    // the set.
    for (String ele : set)
    {
      if (!witnesses.containsKey(ele))
        return false;

      // Verify the witness for the accumulator.
      if (!accumulator.verify(theSig.getAccumulator(), witnesses.get(ele),
          ele))
        return false;
    }

    // Verify the signature on the accumulator.
    signScheme.initVerify(vk.getSignatureKey());
    signScheme.update(theSig.getAccumulator());

    return signScheme.verify(theSig.getSignature());
  }

}
