package org.gnunet.seaspider.parser;
import org.gnunet.seaspider.parser.nodes.AssignmentOperator;
import org.gnunet.seaspider.parser.nodes.CompoundStatement;
import org.gnunet.seaspider.parser.nodes.Expression;
import org.gnunet.seaspider.parser.nodes.NodeToken;
import org.gnunet.seaspider.parser.visitors.DepthFirstVisitor;

public class GNUnetDepthFirstVisitor extends DepthFirstVisitor {
	private int current_endline;
	private int blockStart;
	private int blockEnd;
	
	 public void visit(Expression n) {
		n.f0.accept(this);
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
    	int old_ll = current_endline;
    	current_endline = n.f2.endLine;
    	System.out.println("Scope starts at line:" + n.f0.endLine + " and ends at line:" + n.f2.endLine);
    	n.f0.accept(this);
    	n.f1.accept(this);
    	n.f2.accept(this);
    	current_endline = old_ll;
    }
}
