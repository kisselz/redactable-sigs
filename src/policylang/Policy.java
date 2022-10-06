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
package policylang;

import policylang.Parser;
import policylang.lexer.Token;
import policylang.lexer.TokenType;
import policylang.Environment;
import policylang.ast.SyntaxTree;
import util.Tuple;
import util.Pair;
import util.math.FieldFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.math.BigInteger;

/**
 * This class provides the frontend for the montone circuit policy langauge.
 * @author Zach Kissel
 */
 public class Policy
 {
   private String policy;
   private SyntaxTree ast;

   /**
    * Constructs a new policy {@code policy}.
    * @param policy a string writeen in the policy language.
    * @throws IllegalArgumentException if the {@code policy} is not
    * a valid string in the policy language.
    */
   public Policy(String policy) throws IllegalArgumentException
   {
     this.policy = policy;

     // Parse the policy and generate the abstract syntax tree.
     Parser parser = new Parser(this.policy);
     ast = parser.parse();
     if (parser.hasError())
      throw new IllegalArgumentException("Badly formatted policy.");
   }

   /**
    * Determines if the given elements satisfy the policy.
    * @param ele a list of elements.
    * @return true if the policy verifies; otherwise, false.
    */
   public Boolean checkPolicy(ArrayList<String> ele)
   {
     Environment env = new Environment();

     // Add all of the elements to the environment as identifiers
     // with the value true.
     for (String e : ele)
      env.updateEnvironment(new Token(TokenType.ID, e), true);
     ast.setEnvironment(env);

     // Evaluate the policy.
     return (Boolean) ast.evaluate();
   }

   /**
    * Generates the shares of the secret such that when the literals present
    * satsify the formula the secret is recovered.
    * @return A map between the literals and their shares.
    */
   @SuppressWarnings("unchecked")
   public HashMap<String, Pair<BigInteger>> generateShares()
   {
     HashMap<String, Pair<BigInteger>> shares = new HashMap<>();
     BigInteger rootSecret = FieldFactory.getField("FFDHE2048").sampleElement();
     Environment env = ast.getShares(rootSecret);
     ArrayList<String> ids = env.getAllIdentifiers();

     for(String id : ids)
     {
       Object data = env.lookup(new Token(TokenType.ID, id));
       shares.put(id, (Pair<BigInteger>)data);
     }
     return shares;
   }

   /**
    * Takes a set of shares and reconstructs the secret according to the
    * policy.
    * @param shares the shares and their associated literals.
    * @return the secret or {@code null} if the secret can't be recovered.
    */
   public BigInteger reconstruct(HashMap<String, Pair<BigInteger>> shares)
   {
     // Build the environment where each literal has a value associated with
     // it's share.
     Environment env = new Environment();
     for (String id : shares.keySet())
      env.updateEnvironment(new Token(TokenType.ID, id), shares.get(id));

     return ast.reconstructSecret(env);

   }
 }
