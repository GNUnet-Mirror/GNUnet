package org.gnunet.seaspider;

import java.io.File;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Stack;
import org.tmatesoft.sqljet.core.SqlJetException;
import org.tmatesoft.sqljet.core.SqlJetTransactionMode;
import org.tmatesoft.sqljet.core.table.ISqlJetTable;
import org.tmatesoft.sqljet.core.table.SqlJetDb;

/**
 * ExpressionDatabaseHandler is fed by expressions from the C code parser, and
 * inserts them into SQLite Expression database using SQLJet API. Before
 * inserting an expression into the database, ExpressionDatabaseHandler makes
 * sure it's not redundant. 
 * For example: 
 * int x = 0; 
 * int y = 1; 
 * int z = x + y // line 3 
 * The parser input for line 3 is: z, x, y, x + y, and z = x + y The
 * expressions to be committed to the database will be only: z, and z = x + y
 */
public class ExpressionDatabaseHandler {

	private static final boolean DEBUG = false;

	private static final boolean PRINT_STACK = false;

	private static SqlJetDb db;

	private static ISqlJetTable table;

	private static String currentFileName = null;

	private static int currentScopeEnd = 0;

	private static Stack<HashMap<String, Integer>> expressionStack = new Stack<HashMap<String, Integer>>();

	public static void createExpressionDatabase(String databasePath) {
		String createTableQuery = "CREATE TABLE Expression ( expr_ID INTEGER PRIMARY KEY AUTOINCREMENT, "
				+ "file_name TEXT NOT NULL , expr_syntax TEXT NOT NULL ,"
				+ " start_lineno INT, end_lineno INT)";

		File dbFile = new File(databasePath);
		dbFile.delete();/* Delete it if already existent */

		/* Create Expressions database */
		try {
			db = SqlJetDb.open(dbFile, true);
			db.getOptions().setAutovacuum(true);
			db.beginTransaction(SqlJetTransactionMode.WRITE);
			try {
				db.getOptions().setUserVersion(1);/* Sets the user's cookie */
			} finally {
				db.commit();
			}
			/* Create table Expression */
			db.createTable(createTableQuery);
			db.beginTransaction(SqlJetTransactionMode.WRITE);
			table = db.getTable("Expression");
		} catch (SqlJetException e) {
			e.printStackTrace();
		}
	}

	public static void closeDatabase() {
		try {
			db.commit();
			db.close();
		} catch (SqlJetException e) {
			e.printStackTrace();
		}
	}

	private static void doInsertExpression(String fileName,
			String expressionSyntax, int startLineNo, int endLineNo) {
		try {
			if (DEBUG)
				System.out.println(fileName + ":[" + startLineNo + "-"
						+ endLineNo + "]: " + expressionSyntax);
			table.insert(null, currentFileName, expressionSyntax, startLineNo,
					endLineNo);
		} catch (SqlJetException e) {
			e.printStackTrace();
		}
	}

	private static boolean isRedundant(String expressionSyntax) {
		Iterator<HashMap<String, Integer>> itr = expressionStack.iterator();
		HashMap<String, Integer> scope;

		while (itr.hasNext()) {
			scope = itr.next();
			if (null != scope.get(expressionSyntax))
				return true;
		}

		return false;
	}

	private static int getScopeEnd(HashMap<String, Integer> scope) {
		Iterator<Integer> itr = scope.values().iterator();
		return itr.next();
	}

	private static HashMap<String, Integer> pushNewScope(int endLineNo) {
		HashMap<String, Integer> scope = new HashMap<String, Integer>();
		currentScopeEnd = endLineNo;
		expressionStack.push(scope);

		return scope;
	}

	private static void printExpressionStack(String expressionSyntax,
			int startLineNo, int endLineNo) {
		HashMap<String, Integer> hashMap;
		Iterator<String> itr;
		System.out.println("Commit call for expression: " + expressionSyntax
				+ " start:" + startLineNo + " end:" + endLineNo);
		for (int i = 0; i < expressionStack.size(); i++) {
			hashMap = expressionStack.get(i);
			itr = hashMap.keySet().iterator();
			System.out.println("Printing expressions of scope " + i + ":");
			while (itr.hasNext()) {
				System.out.println(itr.next());
			}
		}
		System.out.println("");
	}

	private static void insertExpression(String fileName,
			String expressionSyntax, int startLineNo, int endLineNo) {

		HashMap<String, Integer> currentScopeExpressions = null;

		if (PRINT_STACK)
			printExpressionStack(expressionSyntax, startLineNo, endLineNo);

		if (null == currentFileName || !currentFileName.equals(fileName)) {
			/* First time, or new file */
			currentFileName = fileName;
			if (!expressionStack.empty())
				expressionStack.clear();
			currentScopeExpressions = pushNewScope(endLineNo);
		} else {
			if (endLineNo > currentScopeEnd) {
				/*
				 * We are either in a new function or back to an outer scope
				 */
				expressionStack.pop();
				if (expressionStack.empty()) {
					/* We are in a new function */
					currentScopeExpressions = pushNewScope(endLineNo);
				} else {
					/* We just left an inner scope to an outer one */
					currentScopeExpressions = expressionStack.lastElement();
					currentScopeEnd = getScopeEnd(currentScopeExpressions);
					if (isRedundant(expressionSyntax))
						return;
				}
			} else {
				/* Either we delved into a sub-scope or we are in the same scope */
				if (isRedundant(expressionSyntax))
					return;
				if (endLineNo == currentScopeEnd) // same scope
					currentScopeExpressions = expressionStack.lastElement();
				else
					// new sub-scope
					currentScopeExpressions = pushNewScope(endLineNo);
			}
		}

		/* Add the new expression */
		currentScopeExpressions.put(expressionSyntax, endLineNo);
		doInsertExpression(fileName, expressionSyntax, startLineNo, endLineNo);
	}

	/**
	 * Inserts expression into the Expression Database
	 * 
	 * @param fileName source file the expression comes from
	 * @param expressionSyntax string of the expression
	 * @param startLineNo line number of the expression
	 * @param endLineNo end line of the expression scope
	 */
	public static void insertIntoExpressionTable(String fileName,
			String expressionSyntax, int startLineNo, int endLineNo) {
		if (expressionSyntax.matches("[0-9]*"))
			return;
		if (expressionSyntax.startsWith("\""))
			return;
		if (db == null) {
			System.out
					.println("Error:Database handle is not initialized. Program will exit now!");
			System.exit(1);
		}
		
		String[] fileNameArr = fileName.split("src/");
		if (fileNameArr.length > 1)
			fileName = fileNameArr[1];
		insertExpression(fileName, expressionSyntax, startLineNo, endLineNo);
	}
}
