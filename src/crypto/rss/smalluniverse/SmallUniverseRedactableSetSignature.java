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
package crypto.rss.smalluniverse;

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
 * This class implements the small universe policy based redactable signature scheme
 * as discussed in:
 * "Policy-Based Redactable Set Signatures" by Zachary A. Kissel
 *
 * @author Zach Kissel
 */
public class SmallUniverseRedactableSetSignature extends RedactableSetSignature
{
  private SmallUniverseSigningKey sk;
  private SmallUniverseVerificationKey vk;
  private Signature signScheme;

  /**
   * Constructs a new redactable set signature.
   */
  public SmallUniverseRedactableSetSignature()
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
  * @return the signature key pair.
  */
  public SignatureKeyPair keyGen()
  {
    System.out.println("Warning: small set using empty universe.");
    return keyGen(new HashMap<String, Integer>());
  }

  /**
   * Generates a keypair.
   * @param universe the unvirse of elements associated with the sets.
   * @return the signature key pair.
   */
  public SignatureKeyPair keyGen(HashMap<String, Integer> universe)
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
        new SmallUniverseSigningKey(akp.getPrivate(), kp.getPrivate(), universe),
        new SmallUniverseVerificationKey(akp.getPublic(), kp.getPublic(), universe));
  }


  /**
   * Intializes the signature for signing.
   * @param sk the signing key.
   */
   public void initSign(SigningKey sk)
   {
      this.sk = (SmallUniverseSigningKey) sk;
      this.vk = null;
   }

   /**
    * Initialize the signature for redaction and verify.
    * @param vk the verification key.
    */
  public void initRedactVerify(VerificationKey vk)
  {
    this.vk = (SmallUniverseVerificationKey) vk;
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
    SmallUniverseSigningKey skey = (SmallUniverseSigningKey) sk;
    Accumulator accumulator = new Accumulator();
    HashMap<String, BigInteger> witnesses = new HashMap<>();
    BigInteger acc;
    String[] charSeq;

    if (policy == null || policy.isEmpty())
      throw new SignatureException("Policy required.");

    // Split the characteristic sequences appart.
    charSeq = policy.split(",");

    String currCharSeq = computeCharSeq(set, skey.getUniverse());
    if (currCharSeq == null)
      throw new SignatureException("Set is not a subest of the universe.");

    // Construct the accumulator that holds all of the characteristic
    // strings that satisfy the policy
    HashSet<String> accSet = new HashSet<>();
    for (int i = 0; i < charSeq.length; i++)
      accSet.add(charSeq[i]);

    // Since it is easier now, we use the accSet to check to see if
    // our set satisfies the policy.
    if (!accSet.contains(currCharSeq))
      throw new SignatureException("Set does not satisify policy.");

    accumulator.initAccumulate(skey.getAccumulatorKey());
    Tuple<BigInteger,ArrayList<Pair<BigInteger>>> rv = accumulator.eval(accSet);
    acc = rv.getFirst();

    // Build the collection of witnesses.
    for (String ele : accSet)
      witnesses.put(ele, accumulator.getWitness(ele, acc, rv.getSecond()));

    // Generate the signature on the accumulator value and secret.
    signScheme.initSign(skey.getSignatureKey());
    signScheme.update(acc.toByteArray());
    byte[] signature = signScheme.sign();

    return new SmallUniverseSetSignature(acc, policy, signature, witnesses);
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
    SmallUniverseSetSignature theSig = (SmallUniverseSetSignature) sig;
    SmallUniverseVerificationKey vkey = (SmallUniverseVerificationKey) vk;
    String currCharSeq;
    String[] charSeq;

    // Parse the components of the signature.
    HashMap<String, BigInteger> witnesses = theSig.getWitnesses();

    // Verify that set2 is a subset of set1
    if (!set.containsAll(subset))
      return null;

    // Build the subset's characteristic sequence and
    // make sure we satisfy the policy.
    currCharSeq = computeCharSeq(subset, vkey.getUniverse());
    if (currCharSeq == null)
      return null;

    if (!witnesses.containsKey(currCharSeq))
      return null;

    // At this point we know that we have a valid redaction.
    // We no proceed to perform the redaction by removing the
    // witnesses that are no longer valid.
    Set<String> keys = witnesses.keySet();
    for (String key : keys)
      if (!orCharSeq(currCharSeq, key).equals(currCharSeq))
        witnesses.remove(key);

    return new SmallUniverseSetSignature(theSig.getAccumulator(), policy,
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
    SmallUniverseSetSignature theSig = (SmallUniverseSetSignature) sig;
    SmallUniverseVerificationKey vkey = (SmallUniverseVerificationKey) vk;
    Accumulator accumulator = new Accumulator();
    String element;
    String charSeq;

    // Get the witness and share components of the signature.
    HashMap<String, BigInteger> witnesses = theSig.getWitnesses();


    // Verify the set elements and shares are correct by building
    // the charactersitic sequence and checking and verifying the
    // witness.
    accumulator.initVerify(vkey.getAccumulatorKey());

    charSeq = computeCharSeq(set, vkey.getUniverse());

    // Make sure there is an element for the witness.
    if (!witnesses.containsKey(charSeq))
      return false;

    // Verify the witness for the accumulator.
    if (!accumulator.verify(theSig.getAccumulator(), witnesses.get(charSeq),
        charSeq))
      return false;

    // Verify the signature on the shares.
    signScheme.initVerify(vkey.getSignatureKey());
    signScheme.update(theSig.getAccumulator().toByteArray());

    return signScheme.verify(theSig.getSignature());
  }

  /********************************************************
   *
   * Private Methods
   *
   ********************************************************/

   /**
    * Computes the charactersitic sequence for a set given the
    * description of the universe.
    * @param set the set to compute the characteristic sequence of.
    * @param universe the universe the set should be drawn from.
    * @return the characteristic sequence.
    */
    private String computeCharSeq(Set<String> set,
       HashMap<String, Integer> universe)
    {
      BitSet seq = new BitSet(universe.size());

      for (String ele : set)
      {
        if (!universe.containsKey(ele))
          return null;
        seq.set(universe.get(ele));
      }

      return seq.toString();
    }

    /**
     * Computes the logical or of the two bit strings {@code cs1} and
     * {@code cs2}.
     * @param cs1 the first bit string.
     * @param cs2 the second bit string.
     * @param the logical or of the two bit strings.
     */
    private String orCharSeq(String cs1, String cs2)
    {
      String res = "";
      if (cs1.length() != cs2.length())
        return null;

      for (int i = 0; i < cs1.length(); i++)
      {
        if (cs1.charAt(i) == '0' && cs2.charAt(i) == '0')
          res += "0";
        else
          res += "1";
      }

      return res;
    }
}
