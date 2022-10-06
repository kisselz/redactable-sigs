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

import policylang.lexer.TokenType;
import policylang.lexer.Token;
import policylang.Environment;
import java.math.BigInteger;
import util.Pair;

/**
 * This node represents the a token in the grammar.
 * @author Zach Kissel
 */
 public class TokenNode extends SyntaxNode
 {
   private Token token;   // The token type.

   /**
    * Constructs a new token node.
    * @param token the token to associate with the node.
    */
    public TokenNode(Token token)
    {
      this.token = token;
    }

    /**
     * Evaluate the node.
     * @param env the executional environment we should evaluate the
     * node under.
     * @return the object representing the result of the evaluation.
     */
     public Object evaluate(Environment env)
     {
       switch(token.getType())
       {
         case INT:
          return Integer.valueOf(token.getValue());
         case REAL:
          return Double.valueOf(token.getValue());
         case TRUE:
          return Boolean.valueOf(true);
         case FALSE:
          return Boolean.valueOf(false);
         case ID:
          Object val = env.lookup(token);
          // if (val == null)
          //   System.out.println("Undefined variable " + token.getValue());
          return val;
         default:
          return token;
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
       env.updateEnvironment(token, secret);
       return env;
     }

     /**
      * Reconstructs the secret from the values given in the policy.
      * @param env the executional environment we should generate shares under.
      * @return the secret.
      */
     @SuppressWarnings("unchecked")
     public Pair<BigInteger> reconstruct(Environment env)
     {
       return (Pair<BigInteger>)env.lookup(token);
     }
 }
