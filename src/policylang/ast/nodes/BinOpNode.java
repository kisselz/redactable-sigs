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
package policylang.ast.nodes;

import policylang.lexer.Token;
import policylang.lexer.TokenType;
import policylang.Environment;
import java.math.BigInteger;
import util.Pair;
import crypto.secretsharing.ThresholdSecretSharing;
import java.util.ArrayList;

/**
 * This node represents a binary operation.
 * @author Zach Kissel
 */
 public class BinOpNode extends SyntaxNode
 {
   private TokenType op;
   private SyntaxNode leftTerm;
   private SyntaxNode rightTerm;

   /**
    * Constructs a new binary operation syntax node.
    * @param lterm the left operand.
    * @param op the binary operation to perform.
    * @param rterm the right operand.
    */
    public BinOpNode(SyntaxNode lterm, TokenType op, SyntaxNode rterm)
    {
      this.op = op;
      this.leftTerm = lterm;
      this.rightTerm = rterm;
    }

    /**
     * Evaluate the node if the environment does not have a value bound to
     * an identifier we will ignore it. This allows the evaluator to
     * ouptut false when a literal is missing.
     *
     * @param env the executional environment we should evaluate the
     * node under.
     * @return the object representing the result of the evaluation.
     */
     public Object evaluate(Environment env)
     {
        Object lval;
        Object rval;

        lval = leftTerm.evaluate(env);
        rval = rightTerm.evaluate(env);


       // if (lval == null && rval == null)
       //    return null;

        // Make sure the type is sound.
        // if(lval != null && !(lval instanceof Integer || lval instanceof Double || lval instanceof Boolean) &&
        //    rval != null && !(rval instanceof Double || rval instanceof Integer || lval instanceof Boolean))
        //   return null;


        // if (lval.getClass() !=  rval.getClass())
        // {
        //   System.out.println("Error: mixed type expression.");
        //   return null;
        // }


        // Perform the operation based on the type.
        switch(op)
        {
          case AND:
            if (lval == null || rval == null)
              return (Boolean) false;
            return (Boolean) lval && (Boolean) rval;
          case OR:
            if (lval != null && lval.equals(true))
              return (Boolean) true;
            else if (rval != null && rval.equals(true))
              return (Boolean) true;
            else
              return (Boolean) false;
          default:
            return null;
        }
     }

     /**
      * Determines the secret share for the given node.
      * @param env the executional environment we should generate shares under.
      * @param secret the secret to share among the children.
      * @return a map of identifiers to shares.
      */
     public Environment getShares(Environment env, Pair<BigInteger> secret)
     {
       ThresholdSecretSharing tss;
       ArrayList<BigInteger> shares;
       BigInteger two = new BigInteger("2");
       ArrayList<String> ids;
       Environment env1;
       Environment env2;

       switch(op)
       {
         case AND:
          tss = new ThresholdSecretSharing(2, 2);
          shares = tss.generateShares(secret.getSecond());
          env1 = leftTerm.getShares(env, new Pair<BigInteger>(BigInteger.ONE, shares.get(0)));
          env2 = rightTerm.getShares(env, new Pair<BigInteger>(two, shares.get(1)));
          ids = env2.getAllIdentifiers();
          for (String id : ids)
            env1.updateEnvironment(new Token(TokenType.ID, id), env2.lookup(new Token(TokenType.ID, id)));
          return env1;

         case OR:
          env1 = leftTerm.getShares(env, new Pair<BigInteger>(BigInteger.ONE, secret.getSecond()));
          env2 = rightTerm.getShares(env, new Pair<BigInteger>(two, secret.getSecond()));
          ids = env2.getAllIdentifiers();
          for (String id : ids)
           env1.updateEnvironment(new Token(TokenType.ID, id), env2.lookup(new Token(TokenType.ID, id)));
          return env1;

         default:
          return env;
       }
     }

     /**
      * Reconstructs the secret from the values given in the policy.
      * @param env the executional environment we should generate shares under.
      * @return the secret.
      */
     @SuppressWarnings("unchecked")
     public Pair<BigInteger> reconstruct(Environment env)
     {
       Pair<BigInteger> lval;
       Pair<BigInteger> rval;
       ArrayList<Pair<BigInteger>> shares = new ArrayList<>();
       BigInteger two = new BigInteger("2");
       ThresholdSecretSharing tss;

       lval = (Pair<BigInteger>) leftTerm.reconstruct(env);
       rval = (Pair<BigInteger>) rightTerm.reconstruct(env);

       switch(op)
       {
         case AND:
          if (lval == null || rval == null)
            return null;

          tss = new ThresholdSecretSharing(2, 2);
          shares.add(new Pair<BigInteger>(BigInteger.ONE, lval.getSecond()));
          shares.add(new Pair<BigInteger>(two, rval.getSecond()));
          return new Pair<BigInteger>(BigInteger.ZERO, tss.reconstructSecret(shares));

         case OR:
          if (lval != null)
            return lval;
          else if (rval != null)
            return rval;
          else
            return null;

         default:
          return null;
       }
     }
 }
