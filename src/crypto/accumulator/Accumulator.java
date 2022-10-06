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

import util.Pair;
import util.Tuple;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Set;
import java.security.NoSuchAlgorithmException;

/**
 * This class implements a basic RSA accumulator as described in
 * "Collision-Free Accumulators and Fail-Stop Signature Schemes Without Trees"
 * By Niko Baric and Birgit Pfitzmann.
 *
 * @author Zach Kissel
 */
 public class Accumulator
 {
   private MessageDigest hash;
   private BigInteger modulus;
   private AccumulatorPrivateKey sk;
   private AccumulatorPublicKey pk;
   private static SecureRandom random;

   /**
    * Constructor intializes the keys to null and constructs an
    * instance of a SHA-256 hash function.
    */
   public Accumulator()
   {
     sk = null;
     pk = null;
     random = new SecureRandom();

     try
     {
       hash = MessageDigest.getInstance("SHA-256");
     }
     catch (NoSuchAlgorithmException nsa)
     {
       System.err.println("Internal Error: Accumulator does not" +
            " have access to SHA2");
       System.exit(1);
     }
   }

  /**
   * Constructs a new KeyPair for the accumulator.
   * @return the accumulator's keypair.
   */
  public static AccumulatorKeyPair keyGen()
  {
    // Initialize the random number generator.
    random = new SecureRandom();

    // Two 2048 bit primes will result in a 4096 bit modulus.
    Pair<BigInteger> primes = genPrimes(2048);
    BigInteger modulus = primes.getFirst().multiply(primes.getSecond());
    BigInteger generator = getInRange(BigInteger.ONE, modulus);

    return new AccumulatorKeyPair(
        new AccumulatorPrivateKey(primes.getFirst(), primes.getSecond(),
        generator), new AccumulatorPublicKey(modulus, generator));
  }

  /**
   * Initializes the object for verification.
   * @param pk the public key for the accumulator.
   */
  public void initVerify(AccumulatorPublicKey pk)
  {
    this.sk = null;
    this.pk = pk;
  }

  /**
   * Initializes the object for accumulation.
   * @param sk the private key for the accumulator.
   */
  public void initAccumulate(AccumulatorPrivateKey sk)
  {
    this.pk = null;
    this.sk = sk;
  }

  /**
   * Takes a set of strings as input and produces the accumulator value.
   * @param set a linked list of strings to accumulate.
   * @return the accumulator value.
   * @throws UnsupportedOperationException if the object has not been
   * initialized for accumulation.
   */
  public Tuple<BigInteger, ArrayList<Pair<BigInteger>>> eval(Set<String> set)
     throws UnsupportedOperationException
  {
    ArrayList<Pair<BigInteger>> aux = new ArrayList<>();

    if (sk == null)
      throw new UnsupportedOperationException("Call initAccumulate first.");

    // Build all of the auxilliary information.
    for (String s : set)
      aux.add(hashToPrime(s));

    // Compute the product of the primes.
    BigInteger prod = BigInteger.ONE;
    for (Pair<BigInteger> p : aux)
      prod = prod.multiply(p.getFirst());

    return new Tuple<BigInteger, ArrayList<Pair<BigInteger>>>(
        sk.getGenerator().modPow(prod, sk.getModulus()), aux);
  }

  /**
   * Generates the witeness for a element ele.
   * @param ele the element to generate the witness for.
   * @param acc the accumulator value.
   * @param aux the auxilliary information output by eval.
   * @return the witness for the element.
   * @throws UnsupportedOperationException if the object has not been
   * initialized for accumulation.
   */
  public BigInteger getWitness(String ele, BigInteger acc,
     ArrayList<Pair<BigInteger>> aux) throws UnsupportedOperationException
  {
    BigInteger prod = BigInteger.ONE;

    if (sk == null)
      throw new UnsupportedOperationException("Call initAccumulate first.");

    Pair<BigInteger> val = hashToPrime(ele);

    // Compute the product without the element in question.
    for (int i = 0; i < aux.size(); i++)
      if (val.getFirst().compareTo(aux.get(i).getFirst()) != 0 ||
          val.getSecond().compareTo(aux.get(i).getSecond()) != 0)
            prod = prod.multiply(aux.get(i).getFirst());


    // The witness is an accumulator that does not contain
    // the element in question.
    return sk.getGenerator().modPow(prod, sk.getModulus());
  }

  /**
   * Determines if the element is in the accumulator given the witness.
   * @param acc the accumulator value.
   * @param witness the value of the witness.
   * @param ele the element associated with the witness.
   * @return true if the {@code ele} is in the accumulator; otherwise, false.
   * @throws UnsupportedOperationException if the object has not been
   * initialized for verification.
   */
  public boolean verify(BigInteger acc, BigInteger witness, String ele)
      throws UnsupportedOperationException
  {
    if (pk == null)
      throw new UnsupportedOperationException("Call initVerify first.");

    return witness.modPow(hashToPrime(ele).getFirst(),
        pk.getModulus()).compareTo(acc) == 0;
  }

  /*****************************************************
   *
   * Private Methods.
   *
   *****************************************************/

   /**
    * Hashes an element to a prime. We choose a common way to do this
    * which repeatedly computes PRG(SHA256(x) || i) with i starting at 1
    * until we end up with a prime.
    */
   private Pair<BigInteger> hashToPrime(String item)
   {
     BigInteger prime;
     BigInteger ctr = new BigInteger("0");

     prime = new BigInteger(1, joinArrays(hash.digest(item.getBytes()),
         ctr.toByteArray()));

    while (!prime.isProbablePrime(10))
    {
      ctr = ctr.add(BigInteger.ONE);
      prime = new BigInteger(1, joinArrays(hash.digest(item.getBytes()),
          ctr.toByteArray()));
    }

    return new Pair<BigInteger>(prime, ctr);
   }

   /**
    * Joins {@code array1} and {@code array2} together such
    * such that all elements of {@code array1} occur before
    * {@code array2}.
    * @param array1 the left half of the new array.
    * @param array2 the right half of the new array.
    * @return an array that consists of elements of {@code array1} followed by
    * the elements of{@code array2}.
    */
   private byte[] joinArrays(byte[] array1, byte[] array2)
   {
     byte[] rv = new byte[array1.length + array2.length];

     for (int i = 0; i < array1.length; i++)
      rv[i] = array1[i];
     for (int i = 0; i < array2.length; i++)
      rv[i + array1.length] = array2[i];

     return rv;
   }

   /**
    * Generates distinct primes of size {@code nbits}.
    * @param nbits the size in bits of the prime number.
    * @return a pair of primes.
    */
    private static Pair<BigInteger> genPrimes(int nbits)
    {
      BigInteger p = BigInteger.probablePrime(nbits, new SecureRandom());
      BigInteger q = BigInteger.probablePrime(nbits, new SecureRandom());

      while (p.compareTo(q) == 0)
        q = BigInteger.probablePrime(nbits, new SecureRandom());

      return new Pair<BigInteger>(p, q);
    }


    /**
     * Samples a random number in the range {@code (low, high)}.
     * @param low the lower bound number.
     * @param high the upper bound number.
     * @param a random number in the range.
     */
    private static BigInteger getInRange(BigInteger low, BigInteger high)
    {
      int lowBits = low.bitLength();
      int highBits = high.bitLength();
      int bitLen;
      BigInteger rv;

      if (highBits == lowBits)
        bitLen = highBits;
      else
        bitLen = random.nextInt(highBits - lowBits) + lowBits;

      do
      {
        rv = new BigInteger(bitLen, random);
      } while (rv.compareTo(low) <= 0 || rv.compareTo(high) >= 0);

      return rv;
    }

 }
