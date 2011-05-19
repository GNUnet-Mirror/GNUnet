package org.gnunet.seaspider;

import org.gnunet.seaspider.parser.nodes.ANDExpression;
import org.gnunet.seaspider.parser.nodes.AdditiveExpression;
import org.gnunet.seaspider.parser.nodes.ArgumentExpressionList;
import org.gnunet.seaspider.parser.nodes.AssignmentExpression;
import org.gnunet.seaspider.parser.nodes.AssignmentOperator;
import org.gnunet.seaspider.parser.nodes.CastExpression;
import org.gnunet.seaspider.parser.nodes.CompoundStatement;
import org.gnunet.seaspider.parser.nodes.ConditionalExpression;
import org.gnunet.seaspider.parser.nodes.ConstantExpression;
import org.gnunet.seaspider.parser.nodes.DoWhileStatement;
import org.gnunet.seaspider.parser.nodes.EqualityExpression;
import org.gnunet.seaspider.parser.nodes.ExclusiveORExpression;
import org.gnunet.seaspider.parser.nodes.Expression;
import org.gnunet.seaspider.parser.nodes.ExpressionStatement;
import org.gnunet.seaspider.parser.nodes.ForStatement;
import org.gnunet.seaspider.parser.nodes.FunctionDeclaration;
import org.gnunet.seaspider.parser.nodes.IfStatement;
import org.gnunet.seaspider.parser.nodes.InclusiveORExpression;
import org.gnunet.seaspider.parser.nodes.InitDeclarator;
import org.gnunet.seaspider.parser.nodes.InitDeclaratorList;
import org.gnunet.seaspider.parser.nodes.Initializer;
import org.gnunet.seaspider.parser.nodes.InitializerList;
import org.gnunet.seaspider.parser.nodes.JumpStatement;
import org.gnunet.seaspider.parser.nodes.LogicalANDExpression;
import org.gnunet.seaspider.parser.nodes.LogicalORExpression;
import org.gnunet.seaspider.parser.nodes.MultiplicativeExpression;
import org.gnunet.seaspider.parser.nodes.Node;
import org.gnunet.seaspider.parser.nodes.NodeChoice;
import org.gnunet.seaspider.parser.nodes.NodeSequence;
import org.gnunet.seaspider.parser.nodes.NodeToken;
import org.gnunet.seaspider.parser.nodes.ParameterDeclaration;
import org.gnunet.seaspider.parser.nodes.PostfixExpression;
import org.gnunet.seaspider.parser.nodes.PrimaryExpression;
import org.gnunet.seaspider.parser.nodes.RelationalExpression;
import org.gnunet.seaspider.parser.nodes.ShiftExpression;
import org.gnunet.seaspider.parser.nodes.StructOrUnionSpecifier;
import org.gnunet.seaspider.parser.nodes.SwitchStatement;
import org.gnunet.seaspider.parser.nodes.TranslationUnit;
import org.gnunet.seaspider.parser.nodes.TypeDeclaration;
import org.gnunet.seaspider.parser.nodes.UnaryExpression;
import org.gnunet.seaspider.parser.nodes.UnaryOperator;
import org.gnunet.seaspider.parser.nodes.VariableDeclaration;
import org.gnunet.seaspider.parser.nodes.WhileStatement;
import org.gnunet.seaspider.parser.visitors.DepthFirstVisitor;
import org.grothoff.LineNumberInfo;

/**
 * @author grothoff
 * 
 */
public class ExpressionExtractorVisitor extends DepthFirstVisitor {

	class ExpressionBuilder {
		String expression = "";

		void push(String token) {
			expression = expression + token;
		}

		void commit(int line) {
			ExpressionDatabaseHandler.insertIntoExpressionTable(filename,
					expression, line, scope_end_line);
		}

	}

	final String filename;

	ExpressionBuilder current_expression;

	int scope_end_line;

	boolean operator;

	boolean skip_mode = true;

	/**
	 * 
	 */
	public ExpressionExtractorVisitor(String filename) {
		this.filename = filename;
	}

	public void visit(TranslationUnit n) {
		LineNumberInfo lin = LineNumberInfo.get(n);
		scope_end_line = lin.lineEnd;
		n.f0.accept(this);
		assert scope_end_line == lin.lineEnd;
	}

	public void visit(NodeToken n) {
		if (skip_mode)
			return;
		current_expression.push(n.tokenImage);
	}

	public void visit(StructOrUnionSpecifier n) {
		// do nothing -- skip!
	}

	public void visit(TypeDeclaration n) {
		// do nothing -- skip!
	}

	public void visit(InitDeclaratorList n) {
		assert skip_mode == true;
		super.visit(n);
		assert skip_mode == true;
	}

	public void visit(Initializer n) {
		assert skip_mode == true;
		if (n.f0.which == 0) {
			boolean old_mode = skip_mode;
			skip_mode = false;
			ExpressionBuilder old = current_expression;
			current_expression = new ExpressionBuilder();
			n.f0.accept(this);
			LineNumberInfo lin = LineNumberInfo.get(n);
			if (old != null) {
				old.push(current_expression.expression);
				old.commit(lin.lineEnd);
			} else {
				current_expression.commit(lin.lineEnd);
			}			
			current_expression = old;
			skip_mode = old_mode;
		} else {
			super.visit(n);
		}
		assert skip_mode == true;
	}

	public void visit(InitializerList n) {
		assert skip_mode == true;
		super.visit(n);
		assert skip_mode == true;
	}

	public void visit(VariableDeclaration n) {
		assert skip_mode == true;
		super.visit(n);
	}

	public void visit(FunctionDeclaration n) {
		if (n.f5.which == 0)
			return; // no body
		int old_scope = scope_end_line;
		LineNumberInfo lin = LineNumberInfo.get(n);
		scope_end_line = lin.lineEnd;
		n.f3.accept(this);
		n.f5.accept(this);
		assert scope_end_line == lin.lineEnd;
		scope_end_line = old_scope;
	}

	public void visit(ParameterDeclaration n) {
		skip_mode = false;
		assert current_expression == null;
		if (n.f1.present()) {
			NodeSequence ns = (NodeSequence) n.f1.node;
			Node var = ns.elementAt(0);
			current_expression = new ExpressionBuilder();
			var.accept(this);
			LineNumberInfo lin = LineNumberInfo.get(var);
			current_expression.commit(lin.lineEnd);
		}
		current_expression = null;
		skip_mode = true;
	}

	public void visit(InitDeclarator n) {
		skip_mode = false;
		assert current_expression == null;
		current_expression = new ExpressionBuilder();
		n.f0.accept(this);
		current_expression = null;
		skip_mode = true;
		n.f2.accept(this);
	}

	public void visit(ExpressionStatement n) {
		if (!n.f0.present())
			return;
		assert current_expression == null;
		skip_mode = false;
		current_expression = new ExpressionBuilder();
		n.f0.accept(this);
		LineNumberInfo lin = LineNumberInfo.get(n);
		current_expression.commit(lin.lineEnd);
		current_expression = null;
		skip_mode = true;
	}

	public void visit(CompoundStatement n) {
		assert current_expression == null;
		assert skip_mode == true;
		int old_end = scope_end_line;
		scope_end_line = n.f2.endLine;
		n.f1.accept(this);
		scope_end_line = old_end;
	}

	public void visit(SwitchStatement n) {
		assert current_expression == null;
		skip_mode = false;
		current_expression = new ExpressionBuilder();
		n.f2.accept(this);
		current_expression.commit(n.f0.endLine);
		skip_mode = true;
		current_expression = null;
		n.f4.accept(this);
	}

	public void visit(IfStatement n) {
		assert current_expression == null;
		skip_mode = false;
		current_expression = new ExpressionBuilder();
		n.f2.accept(this);
		current_expression.commit(n.f0.endLine);
		skip_mode = true;
		current_expression = null;
		n.f4.accept(this);
		n.f5.accept(this);
	}

	public void visit(WhileStatement n) {
		assert current_expression == null;
		skip_mode = false;
		current_expression = new ExpressionBuilder();
		n.f2.accept(this);
		current_expression.commit(n.f0.endLine);
		skip_mode = true;
		current_expression = null;
		n.f4.accept(this);
	}

	public void visit(DoWhileStatement n) {
		assert current_expression == null;
		skip_mode = false;
		current_expression = new ExpressionBuilder();
		n.f4.accept(this);
		current_expression.commit(n.f6.endLine);
		skip_mode = true;
		current_expression = null;
		n.f1.accept(this);
	}

	public void visit(ForStatement n) {
		assert current_expression == null;
		skip_mode = false;
		int old_scope = scope_end_line;
		LineNumberInfo lin = LineNumberInfo.get(n);
		scope_end_line = lin.lineEnd;
		if (n.f2.present()) {
			current_expression = new ExpressionBuilder();
			n.f2.accept(this);
			current_expression.commit(n.f3.endLine);
		}
		if (n.f4.present()) {
			current_expression = new ExpressionBuilder();
			n.f4.accept(this);
			current_expression.commit(n.f5.endLine);
		}
		if (n.f6.present()) {
			current_expression = new ExpressionBuilder();
			n.f6.accept(this);
			current_expression.commit(n.f7.endLine);
		}
		skip_mode = true;
		current_expression = null;
		n.f8.accept(this);
		scope_end_line = old_scope;
	}

	public void visit(JumpStatement n) {
		if (n.f0.which != 3)
			return;
		NodeSequence ns = (NodeSequence) n.f0.choice;
		assert current_expression == null;
		skip_mode = false;
		current_expression = new ExpressionBuilder();
		ns.elementAt(1).accept(this);
		LineNumberInfo lin = LineNumberInfo.get(n);
		current_expression.commit(lin.lineEnd);
		current_expression = null;
		skip_mode = true;
	}

	public void visit(Expression n) {
		ExpressionBuilder old = current_expression;
		current_expression = new ExpressionBuilder();
		n.f0.accept(this);
		for (int i = 0; i < n.f1.size(); i++) {
			NodeSequence ns = (NodeSequence) n.f1.elementAt(i);
			current_expression = new ExpressionBuilder();
			ns.elementAt(1).accept(this);
		}
		old.push(current_expression.expression);
		current_expression = old;
	}	
	
	public void visit(AssignmentOperator n) {
		operator = true;
		super.visit(n);
		operator = false;
	}
	
	public void visit(AssignmentExpression n)
	{
		if (0 == n.f0.which)
		{
			NodeSequence ns = (NodeSequence) n.f0.choice;
			UnaryExpression u = (UnaryExpression) ns.elementAt(0);
			AssignmentOperator ao = (AssignmentOperator) ns.elementAt(1);
			AssignmentExpression ae = (AssignmentExpression) ns.elementAt(2);
			LineNumberInfo lin = LineNumberInfo.get(n);

			ExpressionBuilder old = current_expression;
			current_expression = new ExpressionBuilder();
			u.accept(this);
			current_expression.commit(lin.lineEnd);
			ao.accept (this);
			old.push(current_expression.expression);
			current_expression = new ExpressionBuilder();
			ae.accept(this);
			current_expression.commit(lin.lineEnd);
			old.push(current_expression.expression);
			current_expression = old;
		}
		else
		{
			n.f0.choice.accept (this);
		}
	}

	public void visit(ConditionalExpression n) {
		ExpressionBuilder old = current_expression;
		current_expression = new ExpressionBuilder();
		n.f0.accept(this);
		old.push(current_expression.expression);
		if (n.f1.present()) {
			LineNumberInfo lin = LineNumberInfo.get(n);
			NodeSequence ns = (NodeSequence) n.f1.node;
			current_expression = new ExpressionBuilder();
			ns.elementAt(1).accept(this);
			current_expression.commit(lin.lineEnd);
			old.push("?");
			old.push(current_expression.expression);
			current_expression = new ExpressionBuilder();
			ns.elementAt(3).accept(this);
			current_expression.commit(lin.lineEnd);
			old.push(":");
			old.push(current_expression.expression);
			old.commit(lin.lineEnd);
		}
		current_expression = old;
	}

	public void visit(ConstantExpression n) {
		/* skip */
	}

	public void visit(LogicalORExpression n) {
		assert skip_mode == false;
		ExpressionBuilder old = current_expression;
		current_expression = new ExpressionBuilder();
		n.f0.accept(this);
		if (n.f1.present()) {
			LineNumberInfo lin = LineNumberInfo.get(n);
			current_expression.commit(lin.lineEnd);
			operator = true;
			NodeSequence ns = (NodeSequence) n.f1.node;
			ns.nodes.get(0).accept(this);
			operator = false;
			old.push(current_expression.expression);			
			current_expression = new ExpressionBuilder();			
			ns.nodes.get(1).accept(this);
			current_expression.commit(lin.lineEnd);
		}
		old.push(current_expression.expression);
		current_expression = old;
	}

	public void visit(LogicalANDExpression n) {
		assert skip_mode == false;
		ExpressionBuilder old = current_expression;
		current_expression = new ExpressionBuilder();
		n.f0.accept(this);
		if (n.f1.present()) {
			LineNumberInfo lin = LineNumberInfo.get(n);
			current_expression.commit(lin.lineEnd);
			operator = true;
			NodeSequence ns = (NodeSequence) n.f1.node;
			ns.nodes.get(0).accept(this);
			operator = false;
			old.push(current_expression.expression);			
			current_expression = new ExpressionBuilder();			
			ns.nodes.get(1).accept(this);
			current_expression.commit(lin.lineEnd);
		}
		old.push(current_expression.expression);
		current_expression = old;
	}

	public void visit(InclusiveORExpression n) {
		assert skip_mode == false;
		ExpressionBuilder old = current_expression;
		current_expression = new ExpressionBuilder();
		n.f0.accept(this);
		if (n.f1.present()) {
			operator = true;
			NodeSequence ns = (NodeSequence) n.f1.node;
			ns.nodes.get(0).accept(this);
			operator = false;
			ns.nodes.get(1).accept(this);
		}
		old.push(current_expression.expression);
		current_expression = old;
	}

	public void visit(ExclusiveORExpression n) {
		assert skip_mode == false;
		ExpressionBuilder old = current_expression;
		current_expression = new ExpressionBuilder();
		n.f0.accept(this);
		if (n.f1.present()) {
			operator = true;
			NodeSequence ns = (NodeSequence) n.f1.node;
			ns.nodes.get(0).accept(this);
			operator = false;
			ns.nodes.get(1).accept(this);
		}
		old.push(current_expression.expression);
		current_expression = old;
	}

	public void visit(ANDExpression n) {
		assert skip_mode == false;
		ExpressionBuilder old = current_expression;
		current_expression = new ExpressionBuilder();
		n.f0.accept(this);
		if (n.f1.present()) {
			operator = true;
			NodeSequence ns = (NodeSequence) n.f1.node;
			ns.nodes.get(0).accept(this);
			operator = false;
			ns.nodes.get(1).accept(this);
		}
		old.push(current_expression.expression);
		current_expression = old;
	}

	// Safey: this function was fixed to commit the right hand side, the
	// other similar functions still need to be updated accordingly...
	public void visit(EqualityExpression n) {
		assert skip_mode == false;
		ExpressionBuilder old = current_expression;
		current_expression = new ExpressionBuilder();
		n.f0.accept(this);
		if (n.f1.present()) {
			LineNumberInfo lin = LineNumberInfo.get(n);
			current_expression.commit(lin.lineEnd);
			operator = true;
			NodeSequence ns = (NodeSequence) n.f1.node;
			ns.nodes.get(0).accept(this);
			operator = false;
			old.push(current_expression.expression);
			current_expression = new ExpressionBuilder();
			ns.nodes.get(1).accept(this);
			current_expression.commit(lin.lineEnd);
		}
		old.push(current_expression.expression);
		current_expression = old;
	}

	public void visit(RelationalExpression n) {
		assert skip_mode == false;
		ExpressionBuilder old = current_expression;
		current_expression = new ExpressionBuilder();
		n.f0.accept(this);
		if (n.f1.present()) {
			LineNumberInfo lin = LineNumberInfo.get(n);
			current_expression.commit(lin.lineEnd);
			operator = true;
			NodeSequence ns = (NodeSequence) n.f1.node;
			ns.nodes.get(0).accept(this);
			operator = false;
			old.push(current_expression.expression);
			current_expression = new ExpressionBuilder();
			ns.nodes.get(1).accept(this);
			current_expression.commit(lin.lineEnd);
		}
		old.push(current_expression.expression);
		current_expression = old;
	}

	public void visit(ShiftExpression n) {
		assert skip_mode == false;
		ExpressionBuilder old = current_expression;
		current_expression = new ExpressionBuilder();
		n.f0.accept(this);
		if (n.f1.present()) {
			operator = true;
			NodeSequence ns = (NodeSequence) n.f1.node;
			ns.nodes.get(0).accept(this);
			operator = false;
			ns.nodes.get(1).accept(this);
		}
		old.push(current_expression.expression);
		current_expression = old;
	}

	public void visit(AdditiveExpression n) {
		assert skip_mode == false;
		ExpressionBuilder old = current_expression;
		current_expression = new ExpressionBuilder();
		n.f0.accept(this);
		if (n.f1.present()) {
			operator = true;
			NodeSequence ns = (NodeSequence) n.f1.node;
			ns.nodes.get(0).accept(this);
			operator = false;
			ns.nodes.get(1).accept(this);
		}
		old.push(current_expression.expression);
		current_expression = old;
	}

	public void visit(MultiplicativeExpression n) {
		assert skip_mode == false;
		ExpressionBuilder old = current_expression;
		current_expression = new ExpressionBuilder();
		n.f0.accept(this);
		if (n.f1.present()) {
			operator = true;
			NodeSequence ns = (NodeSequence) n.f1.node;
			ns.nodes.get(0).accept(this);
			operator = false;
			ns.nodes.get(1).accept(this);
		}
		old.push(current_expression.expression);
		current_expression = old;
	}

	public void visit(CastExpression n) {
		if (n.f0.which == 1) {
			n.f0.accept(this);
			return;
		}
		NodeSequence ns = (NodeSequence) n.f0.choice;
		ns.nodes.get(3).accept(this);
	}

	public void visit(UnaryExpression n) {
		if ((n.f0.which == 1) || (n.f0.which == 2)) {
			NodeSequence ns = (NodeSequence) n.f0.choice;
			ns.nodes.get(1).accept(this);
		} else
			n.f0.accept(this);

	}

	public void visit(UnaryOperator n) {
		operator = true;
		n.f0.accept(this);
		operator = false;
	}

	public void visit(PostfixExpression n) {
		n.f0.accept(this);
		for (int i = 0; i < n.f1.size(); i++) {
			NodeChoice nc = (NodeChoice) n.f1.elementAt(i);
			switch (nc.which) {
			case 0: // []
			{
				ExpressionBuilder old = current_expression;
				current_expression = new ExpressionBuilder();
				NodeSequence ns = (NodeSequence) nc.choice;
				ns.elementAt(1).accept(this);
				LineNumberInfo lin = LineNumberInfo.get(n);
				current_expression.commit(lin.lineEnd);
				old.push("[");
				old.push(current_expression.expression);
				old.push("]");
				current_expression = old;
			}
			case 1: // ()
			{
				ExpressionBuilder old = current_expression;
				current_expression = new ExpressionBuilder();
				NodeSequence ns = (NodeSequence) nc.choice;
				ns.elementAt(1).accept(this);
				LineNumberInfo lin = LineNumberInfo.get (ns.elementAt(1));
				current_expression.commit(lin.lineEnd);
				old.push("(");
				old.push(current_expression.expression);
				old.push(")");
				current_expression = old;
			}
				break;
			case 2: // .
			case 3: // ->
			{
				ExpressionBuilder old = current_expression;
				LineNumberInfo lin = LineNumberInfo.get(n);
				old.commit(lin.lineEnd);
				current_expression = new ExpressionBuilder();
				NodeSequence ns = (NodeSequence) nc.choice;
				ns.elementAt(1).accept(this);
				if (nc.which == 2)
					old.push(".");
				else
					old.push("->");
				old.push(current_expression.expression);
				current_expression = old;
			}
				break;
			case 4: // ++
			case 5: // --
				/* skip */
				break;
			default:
				throw new Error("Oops!");
			}
		}
	}

	public void visit(PrimaryExpression n) {
		if (n.f0.which == 2) {
			ExpressionBuilder old = current_expression;
			current_expression = new ExpressionBuilder();
			NodeSequence ns = (NodeSequence) n.f0.choice;
			ns.elementAt(1).accept(this);
			old.push("(");
			old.push(current_expression.expression);
			old.push(")");
			LineNumberInfo lin = LineNumberInfo.get(n);
			old.commit(lin.lineEnd);
			current_expression = old;
		} else
			n.f0.accept(this);
	}

	public void visit(ArgumentExpressionList n) {
		ExpressionBuilder old = current_expression;
		current_expression = new ExpressionBuilder();
		n.f0.accept(this);
		old.push(current_expression.expression);
		for (int i = 0; i < n.f1.size(); i++) {
			NodeSequence ns = (NodeSequence) n.f1.elementAt(i);
			current_expression = new ExpressionBuilder();
			ns.elementAt(1).accept(this);
			old.push(",");
			old.push(current_expression.expression);
		}
		current_expression = old;
	}

}
