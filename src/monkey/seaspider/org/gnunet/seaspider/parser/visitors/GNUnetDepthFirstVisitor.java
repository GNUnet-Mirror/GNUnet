package org.gnunet.seaspider.parser.visitors;
import java.util.ArrayList;

import org.gnunet.seaspider.parser.LineNumberInfo;
import org.gnunet.seaspider.parser.nodes.AssignmentOperator;
import org.gnunet.seaspider.parser.nodes.CompoundStatement;
import org.gnunet.seaspider.parser.nodes.Expression;


public class GNUnetDepthFirstVisitor extends DepthFirstVisitor {
	/* Inner utilities classes */
	private class Scope {
		public Scope(int scopeStart, int scopeEnd) {
			this.scopeStart = scopeStart;
			this.scopeEnd = scopeEnd;
		}
		public int scopeStart;
		public int scopeEnd;
	}

	private class ExpressionEntry {
		public ArrayList<ExpressionEntry> expressionComponents= new ArrayList<ExpressionEntry>();
		public LineNumberInfo lineNumberInfo;
		public Scope expressionScope;
	}
	
	/* Fields */
	private int current_endline;
	private Scope currentScope;
	private ExpressionEntry currentExpression;
	
	/* Methods */
	/**
    * f0 -> ConditionalExpression()
    * f1 -> [ AssignmentOperator() Expression() ]
    */
	public void visit(Expression n) {
		currentExpression = new ExpressionEntry();
		currentExpression.lineNumberInfo = LineNumberInfo.get(n);
		currentExpression.expressionScope = currentScope;
		
		n.f0.accept(this);
		n.f1.accept(this);
	}
	
	public void visit(AssignmentOperator n) {
	    n.f0.accept(this);
	}
	   
	/**
    * <PRE>
    * f0 -> "{"
    * f1 -> ( LocalVariableDeclaration() | Statement() )*
    * f2 -> "}"
    * </PRE>
    */
    public void visit(CompoundStatement n) {    	
    	currentScope.scopeStart = n.f0.endLine;
    	currentScope.scopeEnd = n.f2.endLine;
    	n.f0.accept(this);
    	n.f1.accept(this);
    	n.f2.accept(this);
    }
}
