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

import util.Pair;
import util.Tuple;
import crypto.rss.SetSignature;
import crypto.rss.SignatureKeyPair;
import crypto.rss.SigningKey;
import crypto.rss.VerificationKey;
import crypto.rss.RedactableSetSignature;
import crypto.accumulator.AccumulatorKeyPair;
import crypto.accumulator.Accumulator;
import policylang.Policy;

import java.math.BigInteger;
import java.util.Set;
import java.util.HashSet;
import java.util.HashMap;
import java.util.ArrayList;
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
 * This class implements the large universe policy based redactable signature scheme
 * as discussed in:
 * "Policy-Based Redactable Set Signatures" by Zachary A. Kissel
 *
 * @author Zach Kissel
 */
public class LargeUniverseRedactableSetSignature extends RedactableSetSignature
{
  private LargeUniverseSigningKey sk;
  private LargeUniverseVerificationKey vk;
  private Signature signScheme;

  /**
   * Constructs a new redactable set signature.
   */
  public LargeUniverseRedactableSetSignature()
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
   * Generates a keypair.
   * @return the signature key pair.
   */
  public SignatureKeyPair keyGen()
  {
    AccumulatorKeyPair akp = Accumulator.keyGen();
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
        new LargeUniverseSigningKey(akp.getPrivate(), kp.getPrivate()),
        new LargeUniverseVerificationKey(akp.getPublic(), kp.getPublic()));
  }

  /**
   * Generates a keypair. The universe is ignored by this construction.
   * @param universe the unvirse of elements associated with the sets.
   * @return the signature key pair.
   */
  public SignatureKeyPair keyGen(HashMap<String, Integer> universe)
  {
    return keyGen();
  }

  /**
   * Intializes the signature for signing.
   * @param sk the signing key.
   */
   public void initSign(SigningKey sk)
   {
      this.sk = (LargeUniverseSigningKey) sk;
      this.vk = null;
   }

   /**
    * Initialize the signature for redaction and verify.
    * @param vk the verification key.
    */
  public void initRedactVerify(VerificationKey vk)
  {
    this.vk = (LargeUniverseVerificationKey) vk;
    this.sk = null;
  }

  /**
   * Signs the set {@code set} with signing key {@code sk}.
   * @param set the set of elements to sign.
   * @param policy the policy statement (may be {@code null}).
   * @return the signature on the set.
   * @throws InvalidKeyException if the signing key is invalid.
   * @throws SignatureException if the DSA signing algorithm fails.
   */
  public SetSignature sign(Set<String> set, String policy)
    throws InvalidKeyException, SignatureException
  {
    Accumulator accumulator = new Accumulator();
    HashMap<String, BigInteger> witnesses = new HashMap<>();
    BigInteger acc;

    if (policy == null || policy.isEmpty())
      throw new SignatureException("Policy required.");

    // Begin by obtain the shares for each element of the the set.
    Policy pol = new Policy(policy);
    HashMap<String,Pair<BigInteger>> shares = pol.generateShares();
    BigInteger secret = pol.reconstruct(shares);

    // Construct the accumulator that holds the elements and their associated
    // shares.
    HashSet<String> accSet = new HashSet<>();
    for (String ele : set)
    {
      // If the element is part of the policy
      // Add it with its share to the accumulator set.
      if (shares.containsKey(ele))
        accSet.add(ele + ":" + shares.get(ele));
      else
        accSet.add(ele + ":(0,0)");
    }
    accumulator.initAccumulate(sk.getAccumulatorKey());
    Tuple<BigInteger,ArrayList<Pair<BigInteger>>> rv = accumulator.eval(accSet);
    acc = rv.getFirst();

    // Build the collection of witnesses.
    for (String ele : accSet)
      witnesses.put(ele, accumulator.getWitness(ele, acc, rv.getSecond()));

    // Generate the signature on the accumulator value and secret.
    signScheme.initSign(sk.getSignatureKey());
    signScheme.update(acc.toByteArray());
    signScheme.update(secret.toByteArray());
    byte[] signature = signScheme.sign();

    return new LargeUniverseSetSignature(acc, policy, signature, witnesses, shares);
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
    LargeUniverseSetSignature theSig = (LargeUniverseSetSignature) sig;

    // Parse the components of the signature.
    HashMap<String, BigInteger> witnesses = theSig.getWitnesses();
    HashMap<String,Pair<BigInteger>> shares = theSig.getShares();

    // Verify that set2 is a subset of set1
    if (!set.containsAll(subset))
      return null;

    // Make sure our subset satisfies the existing policy.
    Policy existingPol = new Policy(theSig.getPolicy());
    ArrayList<String> elements = new ArrayList<>();
    elements.addAll(subset);

    // Make sure the policy is good.
    if (!existingPol.checkPolicy(elements))
      return null;

    // Make sure the new policy is also satisified.
    Policy newPol = new Policy(policy);
    if (!newPol.checkPolicy(elements))
      return null;

    // At this point we know that we have a valid redaction.
    // We no proceed to perform the redaction by removing the
    // witnesses and shares for elements that do not appear
    // in subset.
    for (String ele : set)
    {
      if (!subset.contains(ele))
      {
        witnesses.remove(ele + ":" + shares.get(ele));
        shares.remove(ele);
      }
    }

    return new LargeUniverseSetSignature(theSig.getAccumulator(), policy,
        theSig.getSignature(), witnesses, shares);
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
    LargeUniverseSetSignature theSig = (LargeUniverseSetSignature) sig;
    Accumulator accumulator = new Accumulator();
    String element;
    Policy pol;

    // Get the witness and share components of the signature.
    HashMap<String, BigInteger> witnesses = theSig.getWitnesses();
    HashMap<String,Pair<BigInteger>> shares = theSig.getShares();

    // Verify the set elements and shares are correct.
    accumulator.initVerify(vk.getAccumulatorKey());
    for (String ele : set)
    {
      // If the element is part of the policy
      // Add it with its share to the accumulator set.
      if (shares.containsKey(ele))
        element = ele + ":" + shares.get(ele);
      else
        element = ele + ":(0,0)";

      // Make sure there is an element for the witness.
      if (!witnesses.containsKey(element))
        return false;

      // Check the witness element pair.
      if (!accumulator.verify(theSig.getAccumulator(), witnesses.get(element),
          element))
        return false;
    }

    // At this point every element has a valid witness-share pairing.
    // Check the policy and recover the secret.
    pol = new Policy(theSig.getPolicy());
    ArrayList<Pair<BigInteger>> polShares;
    ArrayList<String> elements = new ArrayList<>();
    elements.addAll(set);

    // Make sure the policy is good.
    if (!pol.checkPolicy(elements))
      return false;

    // Use the policy tree to reconstruct the secret.
    BigInteger secret = pol.reconstruct(shares);

    // Verify the signature on the shares.
    signScheme.initVerify(vk.getSignatureKey());
    signScheme.update(theSig.getAccumulator().toByteArray());
    signScheme.update(secret.toByteArray());

    return signScheme.verify(theSig.getSignature());
  }
}
