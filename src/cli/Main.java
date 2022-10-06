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
import crypto.rss.RedactableSetSignature;
import crypto.rss.RedactableSetSignatureFactory;
import crypto.rss.SignatureKeyPair;
import crypto.rss.SigningKey;
import crypto.rss.VerificationKey;
import crypto.rss.RedactableSetSignatureKeyFactory;
import crypto.rss.SetSignature;
import crypto.rss.largeuniverse.LargeUniverseSetSignature;
import crypto.rss.smalluniverse.SmallUniverseSetSignature;
import crypto.rss.derler.DerlerSetSignature;
import util.LongOption;
import util.OptionParser;
import util.exception.BadFileFormatException;
import java.util.HashMap;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;
import java.util.HashSet;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Base64;


/**
 * This is the front end for the redactable signature program.
 * it provides command line access to all of the operations supported
 * on a redactable signature scheme.
 * @author Zach Kissel
 */
public class Main
{

  /**
   * Displays the usage message to the screen and exits.
   */
   public static void displayUsage()
   {
     System.out.println("usage:");
     System.out.println("  rss {--help | --test }");
     System.out.println("  rss --perf {small | large | derler}");
     System.out.println("  rss --keygen {small universe_file | large | derler}");
     System.out.println("  rss --sign {small | large} sign_key_file set_file policy");
     System.out.println("  rss --sign derler sign_key_file set_file");
     System.out.println("  rss --redact {small | large} ver_key_file set_file subset_file policy sig_file");
     System.out.println("  rss --redact derler ver_key_file set_fie subset_file sig_file");
     System.out.println("  rss --verify {small | large | derler} ver_key_file set_file signature_file\n");
     System.out.println("options:");
     System.out.println("  -g, --keygen\t\tGenerates a key pair.");
     System.out.println("  -s, --sign\t\tSigns a set.");
     System.out.println("  -r, --redact\t\tRedacts a signature.");
     System.out.println("  -v, --verify\t\tVerifies a signature.");
     System.out.println("  -h, --help\t\tDisplays help message.");
     System.out.println("  -t, --test\t\tRuns sanity tests.");
     System.out.println("  -p, --perf\t\tFor performance analyzer.");
     System.exit(1);
   }

   /**
    * Prints an error message, shows usage and exits if {@code expected}
    * does not equal {@code actual}.
    * @param actual the actual argument count.
    * @param expected the expected argument count.
    */
   public static void printArgCountError(int actual, int expected)
   {
     if (actual < expected)
     {
      System.out.println("Too few arguments.");
      displayUsage();
     }
     else if (actual > expected)
     {
      System.out.println("Too many arguments.");
      displayUsage();
     }
   }

   /**
    * Loads a universe file.
    * @param uFile the name of the universe file.
    * @return a hash map of the universe.
    * @throws FileNotFoundException if the {@code uFile} is inaccessible.
    */
   public static HashMap<String, Integer> loadUniverseFile(String uFile)
     throws FileNotFoundException
   {
     Scanner scan = new Scanner(new File(uFile));
     HashMap<String, Integer> universe = new HashMap<>();
     int count = 0;

     // Load in each element of the set keeping track of its position.
     while(scan.hasNextLine())
        universe.put(scan.nextLine(), count++);

     return universe;
    }

   /**
    * Generates the necessary key pairs and displays them to the screen.
    * @param algo the redactable set signature algorithm type.
    * @param args the args passed to the command.
    */
   public static void handleKeyGen(String algo, String[] args)
   {
     RedactableSetSignature rss = null;
     HashMap<String, Integer> universe = null;
     String uFile = "";

     if (algo.equals("small"))
     {
       printArgCountError(args.length, 1);
       uFile = args[0];
       rss = RedactableSetSignatureFactory.getRedactableSetSignature(
          "small-universe");
        try
        {
          universe = loadUniverseFile(uFile);
        }
        catch (FileNotFoundException fnf)
        {
          System.out.println("Error: can't load universe file: " + uFile);
          System.exit(1);
        }
     }
     else if (algo.equals("large"))
     {
       printArgCountError(args.length, 0);
       rss = RedactableSetSignatureFactory.getRedactableSetSignature(
          "large-universe");
     }
     else if (algo.equals("derler"))
     {
       printArgCountError(args.length, 0);
       rss = RedactableSetSignatureFactory.getRedactableSetSignature(
          "derler-set");
     }
     else
     {
       System.out.println("unknown algorithm " + algo);
       displayUsage();
     }
     SignatureKeyPair kp = rss.keyGen(universe);
     System.out.println("=== Verification Key ===");
     System.out.println(Base64.getEncoder().encodeToString(
        kp.getVerificationKey().getEncoded()));
     if (!uFile.isEmpty())
      System.out.println(uFile);
     System.out.println("\t------------ 8< -----------");
     System.out.println("=== Signing Key ===");
     System.out.println(Base64.getEncoder().encodeToString(
        kp.getSigningKey().getEncoded()));
     if (!uFile.isEmpty())
      System.out.println(uFile);

   }

   /**
    * Loads a set from a file.
    * @param setFile the name of the set file.
    * @return a set containing the elements found in the file.
    * @throws FileNotFoundException if the file can not be accessed.
    */
    public static HashSet<String> loadSet(String setFile)
       throws FileNotFoundException
    {
      Scanner scan = new Scanner(new File(setFile));
      HashSet<String> set = new HashSet<String>();

      while(scan.hasNextLine())
        set.add(scan.nextLine());
      return set;
    }

   /**
    * Loads in the data from a key file.
    * @param keyFile the name of the key file.
    * @return a pair consisting of the key data and possible a universe file
    * name.
    * @throws FileNotFoundException if {@code keyFile} can not be loaded.
    * @throws BadFileFormatException if the file is improperly formatted.
    */
   public static Pair<String> loadKey(String keyFile)
      throws FileNotFoundException, BadFileFormatException
   {
     Scanner scan = new Scanner(new File(keyFile));
     String key = null;
     String universe = null;

     // Get the key data.
     if (scan.hasNextLine())
        key = scan.nextLine();
     else
        throw new BadFileFormatException();

     // Get the universe data if it exists.
     if (scan.hasNextLine())
      universe = scan.nextLine();

     return new Pair<String>(key, universe);
   }

   /**
    * Loads a signature froma file.
    * @param sigFile the name of the signature file.
    * @return the signature data.
    * @throws FileNotFoundException if {@code sigFile} can not be loaded.
    * @throws BadFileFormatException if the file is improperly formatted.
    */
    public static String loadSignature(String sigFile)
       throws FileNotFoundException, BadFileFormatException
    {
      Scanner scan = new Scanner(new File(sigFile));

      // Get the signature data.
      if (scan.hasNextLine())
         return scan.nextLine();
      else
         throw new BadFileFormatException();
    }

   /**
    * Performs the signing operation.
    * @param algo the rss algorithm.
    * @param args the arguments to the signing operation.
    */
   public static void handleSigning(String algo, String[] args)
   {
     RedactableSetSignature rss = null;
     HashMap<String, Integer> universe = null;
     Pair<String> keyData = null;
     HashSet<String> set = null;
     SigningKey sk = null;
     SetSignature sig = null;

     // Make sure we have enough arguments.
     if (algo.equals("derler"))
      printArgCountError(args.length, 2);
     else
      printArgCountError(args.length, 3);

     // Load the keydata
     try
     {
       keyData = loadKey(args[0]);
     }
     catch(FileNotFoundException | BadFileFormatException ex)
     {
       System.out.println("Key File: " + ex);
       System.exit(1);
     }

     // Load the set data.
     try
     {
        set = loadSet(args[1]);
     }
     catch(FileNotFoundException ex)
     {
       System.out.println("Set File: " + ex);
       System.exit(1);
     }


     if (algo.equals("small"))
     {
       if (keyData.getSecond() == null)
        System.out.println("Missing universe.");
       try
       {
         universe = loadUniverseFile(keyData.getSecond());
       }
       catch(FileNotFoundException fnf)
       {
         System.out.println("Could not load universe file.");
         System.exit(1);
       }

       sk = RedactableSetSignatureKeyFactory.getSigningKey("small-universe",
          Base64.getDecoder().decode(keyData.getFirst()), universe);

       rss = RedactableSetSignatureFactory.getRedactableSetSignature("small-universe");
     }
     else if (algo.equals("large"))
     {
        sk = RedactableSetSignatureKeyFactory.getSigningKey("large-universe",
          Base64.getDecoder().decode(keyData.getFirst()), null);
        rss = RedactableSetSignatureFactory.getRedactableSetSignature("large-universe");
     }
     else if (algo.equals("derler"))
     {
       sk = RedactableSetSignatureKeyFactory.getSigningKey("derler-set",
         Base64.getDecoder().decode(keyData.getFirst()), null);
       rss = RedactableSetSignatureFactory.getRedactableSetSignature("derler-set");
     }
     else
     {
       System.out.println("unknown algorithm " + algo);
       displayUsage();
     }

     try
     {
       rss.initSign(sk);
       if (algo.equals("derler"))
        sig = rss.sign(set, null);
       else
        sig = rss.sign(set, args[2]);
     }
     catch (InvalidKeyException | SignatureException ex)
     {
       System.out.println("RSS Sign: " + ex);
       System.exit(1);
     }
     System.out.println(Base64.getEncoder().encodeToString(sig.getEncoded()));
   }

   /**
    * Performs the redaction operation.
    * @param algo the rss algorithm.
    * @param args the arguments to the redaction operation.
    */
    public static void handleRedact(String algo, String[] args)
    {
      RedactableSetSignature rss = null;
      HashMap<String, Integer> universe = null;
      Pair<String> keyData = null;
      HashSet<String> set = null;
      HashSet<String> subset = null;
      VerificationKey vk = null;
      SetSignature sig = null;
      SetSignature rsig = null;
      String sigData = null;
      String policy = null;

      // Make sure we have enough arguments.
      if (algo.equals("derler"))
        printArgCountError(args.length, 4);
      else
        printArgCountError(args.length, 5);

      // Load the keydata
      try
      {
        keyData = loadKey(args[0]);
      }
      catch(FileNotFoundException | BadFileFormatException ex)
      {
        System.out.println("Key File: " + ex);
        System.exit(1);
      }


      // Load the set data.
      try
      {
         set = loadSet(args[1]);
      }
      catch(FileNotFoundException ex)
      {
        System.out.println("Set File: " + ex);
        System.exit(1);
      }

      // Load the subset data.
      try
      {
         subset = loadSet(args[2]);
      }
      catch(FileNotFoundException ex)
      {
        System.out.println("Set File: " + ex);
        System.exit(1);
      }

      // Set the policy.
      if (!algo.equals("derler"))
        policy = args[3];

      // Load the signature data.
      try
      {
        if (algo.equals("derler"))
          sigData = loadSignature(args[3]);
        else
          sigData = loadSignature(args[4]);
      }
      catch(FileNotFoundException | BadFileFormatException ex)
      {
        System.out.println("Verification Key File: " + ex);
        System.exit(1);
      }

      if (algo.equals("small"))
      {
        if (keyData.getSecond() == null)
         System.out.println("Missing universe.");
        try
        {
          universe = loadUniverseFile(keyData.getSecond());
        }
        catch(FileNotFoundException fnf)
        {
          System.out.println("Could not load universe file.");
          System.exit(1);
        }

        vk = RedactableSetSignatureKeyFactory.getVerificationKey("small-universe",
           Base64.getDecoder().decode(keyData.getFirst()), universe);
        rss = RedactableSetSignatureFactory.getRedactableSetSignature("small-universe");
        sig = new SmallUniverseSetSignature(Base64.getDecoder().decode(sigData));
      }
      else if (algo.equals("large"))
      {
         vk = RedactableSetSignatureKeyFactory.getVerificationKey("large-universe",
           Base64.getDecoder().decode(keyData.getFirst()), null);
         rss = RedactableSetSignatureFactory.getRedactableSetSignature("large-universe");
         sig = new LargeUniverseSetSignature(Base64.getDecoder().decode(sigData));
      }
      else if (algo.equals("derler"))
      {
        vk = RedactableSetSignatureKeyFactory.getVerificationKey("derler-set",
          Base64.getDecoder().decode(keyData.getFirst()), null);
        rss = RedactableSetSignatureFactory.getRedactableSetSignature("derler-set");
        sig = new DerlerSetSignature(Base64.getDecoder().decode(sigData));
      }
      else
      {
        System.out.println("unknown algorithm " + algo);
        displayUsage();
      }

      rss.initRedactVerify(vk);
      rsig = rss.redact(set, subset, sig, policy);

      if (rsig == null)
        System.out.println("Redacted set is not valid.");
      else
        System.out.println(Base64.getEncoder().encodeToString(rsig.getEncoded()));
    }

    /**
     * Performs the verification operation.
     * @param algo the rss algorithm.
     * @param args the arguments to the verification operation.
     */
     public static void handleVerify(String algo, String[] args)
     {
       RedactableSetSignature rss = null;
       HashMap<String, Integer> universe = null;
       Pair<String> keyData = null;
       HashSet<String> set = null;
       VerificationKey vk = null;
       SetSignature sig = null;
       String sigData = null;

       // Make sure we have enough arguments.
       printArgCountError(args.length, 3);

       // Load the keydata
       try
       {
         keyData = loadKey(args[0]);
       }
       catch(FileNotFoundException | BadFileFormatException ex)
       {
         System.out.println("Key File: " + ex);
         System.exit(1);
       }

       // Load the set data.
       try
       {
          set = loadSet(args[1]);
       }
       catch(FileNotFoundException ex)
       {
         System.out.println("Set File: " + ex);
         System.exit(1);
       }

       // Load the signature data.
       try
       {
         sigData = loadSignature(args[2]);
       }
       catch(FileNotFoundException | BadFileFormatException ex)
       {
         System.out.println("Verification Key File: " + ex);
         System.exit(1);
       }

       if (algo.equals("small"))
       {
         if (keyData.getSecond() == null)
          System.out.println("Missing universe.");
         try
         {
           universe = loadUniverseFile(keyData.getSecond());
         }
         catch(FileNotFoundException fnf)
         {
           System.out.println("Could not load universe file.");
           System.exit(1);
         }

         vk = RedactableSetSignatureKeyFactory.getVerificationKey("small-universe",
            Base64.getDecoder().decode(keyData.getFirst()), universe);
         rss = RedactableSetSignatureFactory.getRedactableSetSignature("small-universe");
         sig = new SmallUniverseSetSignature(Base64.getDecoder().decode(sigData));
       }
       else if (algo.equals("large"))
       {
          vk = RedactableSetSignatureKeyFactory.getVerificationKey("large-universe",
            Base64.getDecoder().decode(keyData.getFirst()), null);
          rss = RedactableSetSignatureFactory.getRedactableSetSignature("large-universe");
          sig = new LargeUniverseSetSignature(Base64.getDecoder().decode(sigData));
       }
       else if (algo.equals("derler"))
       {
         vk = RedactableSetSignatureKeyFactory.getVerificationKey("derler-set",
           Base64.getDecoder().decode(keyData.getFirst()), null);
         rss = RedactableSetSignatureFactory.getRedactableSetSignature("derler-set");
         sig = new DerlerSetSignature(Base64.getDecoder().decode(sigData));
       }
       else
       {
         System.out.println("unknown algorithm " + algo);
         displayUsage();
       }

       try
       {
         rss.initRedactVerify(vk);
         if (rss.vrfy(sig, set))
           System.out.println("\t=> \u001B[32mAccept.\u001B[0m");
         else
           System.out.println("\t=> \u001B[31mReject.\u001B[0m");
       }
       catch (InvalidKeyException | SignatureException ex)
       {
         System.out.println("RSS Sign: " + ex);
         System.exit(1);
       }
     }

   /**
    * Runs the performance tests for data collection purposes.
    * @param algo the algorithm to use for performance.
    * @param args the array of arguments to the command.
    */
   public static void handlePerf(String algo, String[] args)
   {
       RedactableSetSignature rss = null;
       HashMap<String, Integer> universe = null;
       HashSet<String> set = new HashSet<String>();
       HashSet<String> subset = new HashSet<String>();
       SetSignature sig = null;

       // Make sure we have no arguments.
       printArgCountError(args.length, 0);

       // Build up the set.
       set.add("hello");
       set.add("good");
       set.add("fun");
       set.add("dog");
       set.add("cat");

       // Build up the subset.
       subset.add("hello");
       subset.add("good");

       if (algo.equals("large"))
       {
           // Generate the keys
           rss = RedactableSetSignatureFactory.getRedactableSetSignature(
             "large-universe");
           SignatureKeyPair kp = rss.keyGen(universe);

           // Sign the set.
           rss.initSign(kp.getSigningKey());
           try
           {
            sig = rss.sign(set,
                   "(hello and good) or (fun and dog and cat)");
           }
           catch(InvalidKeyException | SignatureException ex)
           {
               System.out.println(ex);
           }

           // Redact to subset.
           rss.initRedactVerify(kp.getVerificationKey());
           sig = rss.redact(set, subset, sig, "hello and good");

           // Verify the signature on the subset.
           try
           {
            rss.vrfy(sig, subset);
           }
           catch (InvalidKeyException | SignatureException ex)
           {
               System.out.println(ex);
           }
       }
       else if (algo.equals("small"))
       {
           // Initialize the universe.
           universe = new HashMap<>();

           universe.put("hello", 0);
           universe.put("good", 1);
           universe.put("fun", 2);
           universe.put("dog", 3);
           universe.put("cat", 4);

          // Generate the keys
          rss = RedactableSetSignatureFactory.getRedactableSetSignature(
             "small-universe");
          SignatureKeyPair kp = rss.keyGen(universe);

           // Sign the set.
           rss.initSign(kp.getSigningKey());
           try
           {
            sig = rss.sign(set, "11111, 11000, 00111");
           }
           catch(InvalidKeyException | SignatureException ex)
           {
               System.out.println(ex);
           }

           // Redact to subset.
           rss.initRedactVerify(kp.getVerificationKey());
           sig = rss.redact(set, subset, sig, "11000");

           // Verify the signature on the subset.
           try
           {
            rss.vrfy(sig, subset);
           }
           catch (InvalidKeyException | SignatureException ex)
           {
               System.out.println(ex);
           }
       }
       else if (algo.equals("derler"))
       {
         // Generate the keys
         rss = RedactableSetSignatureFactory.getRedactableSetSignature(
            "derler-set");
         SignatureKeyPair kp = rss.keyGen(universe);

         // Sign the set.
         rss.initSign(kp.getSigningKey());
         try
         {
          sig = rss.sign(set, null);
         }
         catch(InvalidKeyException | SignatureException ex)
         {
             System.out.println(ex);
         }

         // Redact to subset.
         rss.initRedactVerify(kp.getVerificationKey());
         sig = rss.redact(set, subset, sig, null);

         // Verify the signature on the subset.
         try
         {
          rss.vrfy(sig, subset);
         }
         catch (InvalidKeyException | SignatureException ex)
         {
             System.out.println(ex);
         }
       }
       else
       {
           System.out.println("unknown algorithm " + algo);
           displayUsage();
       }
   }

   /**
    * Processes the command line arguemnts.
    * @param args the array of command line arguments.
    */
   public static void processCommand(String[] args)
   {
     OptionParser optParser = new OptionParser(args);
     LongOption[] lopt = new LongOption[7];
     Tuple<Character, String> currOpt;

     // Set the short option names.
     optParser.setOptString("p:htg:s:r:v:");

     // Set the long option names.
     lopt[0] = new LongOption("sign", true, 's');
     lopt[1] = new LongOption("verify", true, 'v');
     lopt[2] = new LongOption("redact", true, 'r');
     lopt[3] = new LongOption("keygen", true, 'g');
     lopt[4] = new LongOption("test", false, 't');
     lopt[5] = new LongOption("help", false, 'h');
     lopt[6] = new LongOption("perf", true, 'p');

     optParser.setLongOpts(lopt);

     // Determine the option and do the work.
     currOpt = optParser.getLongOpt(false);
     switch (currOpt.getFirst())
     {
       case 'g': // Generate signature key pair.
        handleKeyGen(currOpt.getSecond(), optParser.getNonOpts());
       return;

       case 's':  // Sign a set.
        handleSigning(currOpt.getSecond(), optParser.getNonOpts());
       break;

       case 'r':  // Redact a signature on a set to one on a subset.
        handleRedact(currOpt.getSecond(), optParser.getNonOpts());
       break;

       case 'v':  // Verify a signature on a set.
        handleVerify(currOpt.getSecond(), optParser.getNonOpts());
       break;

       case 't':  // run internal sanity tests.
        printArgCountError(optParser.getNonOpts().length, 0);
        Test t = new Test();
        t.runDERTest();
       break;

       case 'h':  // Display help.
        printArgCountError(optParser.getNonOpts().length, 0);
        displayUsage();
       break;

       case 'p': // For performance analyzer.
         handlePerf(currOpt.getSecond(), optParser.getNonOpts());
       break;

       default:
        System.out.println("Unknown option " + currOpt.getFirst());
        displayUsage();
      }
   }

  /**
   * The entry point.
   * @param args the command line arguments.
   */
  public static void main(String[] args)
  {
    if (args.length < 1)
      displayUsage();
    processCommand(args);

  }
}
