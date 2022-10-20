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
package cli;

import util.Tuple;
import util.Pair;
import crypto.accumulator.*;
import crypto.secretsharing.ThresholdSecretSharing;
import util.DerEncoder;
import util.DerDecoder;
import java.util.ArrayList;
import java.util.Base64;
import java.math.BigInteger;
import util.math.FieldFactory;
import util.math.Field;
import policylang.Policy;
import java.util.HashMap;
import java.util.HashSet;
import util.OptionParser;
import util.LongOption;

/**
 * This class runs the tests of the components of the system.
 * @author Zach Kissel
 */
 public class Test
 {

   /**
    * Runs the core tests.
    */
    public void testCore()
    {
      runAccumulatorTest();
      runECCAccumulatorTest();
      runThresholdSecretSharingTest();
      runPolicyLangTest();
    }

    /**
     * Tests the RSA accumulator.
     */
     public void runAccumulatorTest()
     {
       System.out.println("\n\n === RSA Accumulator ===");
       AccumulatorKeyPair akp = Accumulator.keyGen();
       Accumulator acc = new Accumulator();
       acc.initAccumulate(akp.getPrivate());

       HashSet<String> set = new HashSet<>();
       set.add("Hello");
       set.add("World");
       set.add("Bye");
       Tuple<BigInteger, ArrayList<Pair<BigInteger>>> accRes;
       System.out.print("Building accumulator . . . ");
       accRes = acc.eval(set);
       System.out.println("[ DONE ]");

       BigInteger[] witness = new BigInteger[set.size()];
       int ctr = 0;
       for (String ele : set)
          witness[ctr++] = acc.getWitness(ele, accRes.getFirst(), accRes.getSecond());
       BigInteger badWit = acc.getWitness("daemon", accRes.getFirst(), accRes.getSecond());


       acc.initVerify(akp.getPublic());
       ctr = 0;
       for (String ele : set)
       {
         System.out.print("Verifying \"" + ele +  "\" . . . ");
         if (acc.verify(accRes.getFirst(), witness[ctr++], ele))
          System.out.println("[ OK ]");
         else
          System.out.println("[ FAIL ]");
        }
       System.out.println("Bad Witness doesn't verify . . . " +
       ((acc.verify(accRes.getFirst(), badWit, "daemon"))? "[ FAIL ]" : "[ OK ]"));
     }

     /**
      * Tests threshold secret sharing.
      */
      public void runThresholdSecretSharingTest()
      {
        System.out.println("\n\n === Threshold Secret Sharing ===");
        ThresholdSecretSharing tss = new ThresholdSecretSharing(3, 3,
           FieldFactory.getField("test"));
        BigInteger secret = new BigInteger("13");
        System.out.println("Testing with secret: " + secret);
        System.out.println("Threshold: 3");
        System.out.println("Num Shares: 3");

        ArrayList<BigInteger> shares = tss.generateShares(secret);
        System.out.println("The shares are: ");
        for (int i = 0; i < shares.size(); i++)
         System.out.println("\tShare: " + shares.get(i));

        ArrayList<Pair<BigInteger>> points = new ArrayList<>();
        for (int i = 0; i < shares.size(); i++)
         points.add(new Pair<BigInteger>(new BigInteger(Integer.toString(i + 1)),
             shares.get(i)));
        System.out.println("Reconstructed Secret is correct . . . " +
        ((tss.reconstructSecret(points).compareTo(secret) == 0)? "[ OK ]" : "[ FAIL ]"));
      }

     /**
      * Tests the policy language.
      */
      public void runPolicyLangTest()
      {
        System.out.println("\n\n === Policy Language ===");
        System.out.println("Policy: (a and b) or c");
        Policy pol = new Policy("(a and b) or c");
        ArrayList<String> ele = new ArrayList<>();
        ele.add("a");
        ele.add("b");
        System.out.print("Valid policy check . . . ");
        if (pol.checkPolicy(ele))
          System.out.println("[ OK ]");
        else
          System.out.println("[ FAIL ]");

        HashMap<String, Pair<BigInteger>> policyShares = pol.generateShares();
        policyShares.remove("a");
        policyShares.remove("c");
        BigInteger reconstructedSecret = pol.reconstruct(policyShares);
        System.out.println("Reconstructed Value: " + reconstructedSecret);
      }

      /**
       * Tests getoption functionality -- a clone of unistd.h's getopt()
       */
      public void runGetOptTest()
      {
        System.out.println("\n\n === Get Option ===");
        Tuple<Character, String> currOpt;
        String[] argv = new String[4];
        argv[0] = "-abc";
        argv[1] = "-xfoo";
        argv[2] = "-y";
        argv[3] = "bar";
        OptionParser parser = new OptionParser(argv);
        parser.setOptString("abcx:y:");
        currOpt = parser.getOpt();
        while (currOpt != null && currOpt.getFirst() != '?')
        {
          System.out.println("Current Option: " + currOpt.getFirst());
          if (currOpt.getFirst() == 'x' || currOpt.getFirst() == 'y')
            System.out.println("Arg: " + currOpt.getSecond());
          currOpt = parser.getOpt();
        }
      }

     /**
      * Tests long option functionality -- a clone of unistd.h's getlongopt()
      */
     public void runGetLongOptTest()
     {
       System.out.println("\n\n === Get Long Option ===");
       Tuple<Character, String> currOpt;
       String[] argv = new String[2];
       argv[0] = "--sign";
       argv[1] = "--verify";

       LongOption[] lopt = new LongOption[4];
       lopt[0] = new LongOption("sign", false, 's');
       lopt[1] = new LongOption("verify", false, 'v');
       lopt[2] = new LongOption("redact", false, 'r');
       lopt[3] = new LongOption("keygen", false, 'g');

       OptionParser parser = new OptionParser(argv);
       parser.setLongOpts(lopt);
       currOpt = parser.getLongOpt(true);
       while (currOpt != null && currOpt.getFirst() != '?')
       {
         System.out.println("Current Option: " + currOpt.getFirst());
         currOpt = parser.getLongOpt(true);
       }
     }

    /**
     * Test DER Encoding.
     */
     public void runDERTest()
     {
       System.out.println("\n\n === DER Encoding/Decoding ===");
       BigInteger num = new BigInteger("123456");
       System.out.println("123456 encoded: " +
          Base64.getEncoder().encodeToString(DerEncoder.encodeBigInteger(num)));

       System.out.println("\nDecoding to: " + DerDecoder.decodeBigInteger(
          DerEncoder.encodeBigInteger(num)));

       BigInteger huge = new BigInteger("12345657891011123456789011876761789912" +
          "12342342352453463456457546756867896796979867012893572193475698713498" +
          "37529347528345283405928937450917293874983475973519273849173498571927" +
          "12345657891011123456789011876761789912" +
             "12342342352453463456457546756867896796979867012893572193475698713498" +
             "37529347528345283405928937450917293874983475973519273849173498571927" +
             "12345657891011123456789011876761789912");
       System.out.println("\nEncoded large number: " +
          Base64.getEncoder().encodeToString(DerEncoder.encodeBigInteger(huge)));


      System.out.println("\nDecoding to: " + DerDecoder.decodeBigInteger(
          DerEncoder.encodeBigInteger(huge)));

      ArrayList<byte[]> seq = new ArrayList<>();
      seq.add(DerEncoder.encodeBigInteger(num));
      seq.add(DerEncoder.encodeBigInteger(huge));
      System.out.println("\nEncoded sequence: " +
         Base64.getEncoder().encodeToString(DerEncoder.encodeSequence(seq)));

      seq = DerDecoder.decodeSequence(DerEncoder.encodeSequence(seq));
      System.out.println("Seq size is: " + seq.size());
      System.out.println("Decode ...");
      System.out.println("\tSeq[0] = " + DerDecoder.decodeBigInteger(seq.get(0)));
      System.out.println("\tSeq[1] = " + DerDecoder.decodeBigInteger(seq.get(1)));
     }

     /**
      * Test the ECC accumulator.
      */
     public void runECCAccumulatorTest()
     {
       System.out.println("\n\n === ECC Accumulator ===");

       ECCAccumulator acc = new ECCAccumulator();
       ECCAccumulatorKeyPair kp = ECCAccumulator.keyGen();


       acc.initAccumulate(kp.getPrivate());
       HashSet<String> set = new HashSet<>();
       set.add("Hello");
       set.add("World");
       set.add("Bye");
       set.add("cat:(0, 0)");
       System.out.print("Building accumulator . . . ");
       byte[] av  = acc.eval(set);
       System.out.println("[ DONE ]");

       // Test the verification.
       for (String ele : set)
       {
         acc.initAccumulate(kp.getPrivate());
         byte[] wit = acc.getWitness(ele, av);
         acc.initVerify(kp.getPublic());
         System.out.print("Verify \"" + ele + "\" . . . ");
         if (acc.verify(av, wit, ele))
          System.out.println("[ OK ]");
         else
          System.out.println("[ FAIL ]");
       }

    }
 }
