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

import java.util.LinkedList;
import policylang.lexer.Lexer;
import policylang.lexer.TokenType;
import policylang.lexer.Token;
import policylang.ast.SyntaxTree;
import policylang.ast.nodes.*;
import java.io.File;
import java.io.FileNotFoundException;

/**
 * Implements a generic super class for parsing files.
 * @author Zach Kissel
 */
public class Parser
{
  private Lexer lex;            // The lexer for the parser.
  private boolean errorFound;   // True if ther was a parser error.
  private boolean doTracing;    // True if we should run parser tracing.
  private Token nextTok;        // The current token being analyzed.

  /**
   * Constructs a new parser for the file {@code source} by
   * setting up lexer.
   * @param src the source code file to parse.
   * @throws FileNotFoundException if the file can not be found.
   */
  public Parser(File src) throws FileNotFoundException
  {
    lex = new Lexer(src);
    errorFound = false;
    doTracing = false;
  }

  /**
   * Construct a parser that parses the string {@code str}.
   * @param str the code to evaluate.
   */
  public Parser(String str)
  {
    lex = new Lexer(str);
    errorFound = false;
    doTracing = false;
  }

  /**
   * Turns tracing on an off.
   */
  public void toggleTracing()
  {
    doTracing = !doTracing;
  }

  /**
   * Determines if the program has any errors that would prevent
   * evaluation.
   * @return true if the program has syntax errors; otherwise, false.
   */
  public boolean hasError()
  {
    return errorFound;
  }

  /**
   * Parses the file according to the grammar.
   * @return the abstract syntax tree representing the parsed program.
   */
  public SyntaxTree parse()
  {
    SyntaxTree ast;

    nextToken();    // Get the first token.
    ast = new SyntaxTree(evalExpr());   // Start processing at the root of the tree.

    if (nextTok.getType() != TokenType.EOF)
      logError("Parse error, unexpected token " + nextTok);
    return ast;
  }


  /************
   * Private Methods.
   *
   * It is important to remember that all of our non-terminal processing methods
   * maintain the invariant that each method leaves the next unprocessed token
   * in {@code nextTok}. This means each method can assume the value of
   * {@code nextTok} has not yet been processed when the method begins.
   ***********/

   /**
    * Method to handle the expression non-terminal
    *
    * <expr> -> <expr> (and | or) <expr>
    */
    private SyntaxNode evalExpr()
    {
        trace("Enter <expr>");
        SyntaxNode rexpr;
        TokenType op;
        SyntaxNode expr = null;

          expr = evalFactor();

          while (nextTok.getType() == TokenType.AND ||
            nextTok.getType() == TokenType.OR)
          {
            op = nextTok.getType();
            nextToken();
            rexpr = evalFactor();
            expr = new BinOpNode(expr, op, rexpr);
          }

        trace("Exit <expr>");

        return expr;
    }


     /**
      * Method to handle the factor non-terminal.
      *
      * <factor> -> <id> | <int> | <real> | ( <expr> )
      */
      private SyntaxNode evalFactor()
      {
        trace("Enter <factor>");
        SyntaxNode fact = null;

        if (nextTok.getType() == TokenType.ID ||
            nextTok.getType() == TokenType.INT ||
            nextTok.getType() == TokenType.REAL ||
            nextTok.getType() == TokenType.TRUE ||
            nextTok.getType() == TokenType.FALSE)
        {
            fact = new TokenNode(nextTok);
            nextToken();
        }
        else if (nextTok.getType() == TokenType.LPAREN)
        {
          nextToken();
          fact = evalExpr();

          if (nextTok.getType() == TokenType.RPAREN)
            nextToken();
          else
            logError("Expected \")\" received " + nextTok +".");
        }
        else
        {
          logError("Unexpected token " + nextTok);

          // Recover from poorly formed expression.
          // if (nextTok.getType() == TokenType.RPAREN)
          //   nextToken();
        }

        trace("Exit <factor>");
        return fact;
      }

  /**
   * Logs an error to the console.
   * @param msg the error message to dispaly.
   */
   private void logError(String msg)
   {
     System.err.println("Error (" + lex.getLineNumber() + "): " + msg);
     errorFound = true;
   }

   /**
    * This prints a message to the screen on if {@code doTracing} is
    * true.
    * @param msg the message to display to the screen.
    */
    private void trace(String msg)
    {
      if (doTracing)
        System.out.println(msg);
    }

    /**
     * Gets the next token from the lexer potentially logging that
     * token to the screen.
     */
    private void nextToken()
    {
      nextTok = lex.nextToken();

      if (doTracing)
        System.out.println("nextToken: " + nextTok);

    }

}
