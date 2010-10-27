package org.gnunet.seaspider;

import java.io.File;

import org.tmatesoft.sqljet.core.SqlJetException;
import org.tmatesoft.sqljet.core.SqlJetTransactionMode;
import org.tmatesoft.sqljet.core.table.ISqlJetTable;
import org.tmatesoft.sqljet.core.table.SqlJetDb;

public class ExpressionDatabaseHandler {

	private static final boolean DEBUG = false;
		
	private static SqlJetDb db;

	private static ISqlJetTable table;

	
	public static void createExpressionDatabase(String databasePath) {
		String createTableQuery = "CREATE TABLE Expression ( expr_ID INT NOT NULL PRIMARY KEY , " +
		"file_name TEXT NOT NULL , expr_syntax TEXT NOT NULL ," +
		" start_lineno INT, end_lineno INT)";
		
		File dbFile = new File(databasePath + "/GNUnetExpressions.db");
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
		}
		catch (SqlJetException e) {
			e.printStackTrace();
		}
	}
	
	
	public static void closeDatabase()
	{
		try {
			db.commit();
			db.close();
		} catch (SqlJetException e) {
			e.printStackTrace();
		}
	}
	
	
	public static void insertIntoExpressionTable(String fileName, String expressionSyntax, 
												int startLineNo, int endLineNo)
	{
		if (expressionSyntax.matches("[0-9]*"))
			return;
		if (expressionSyntax.startsWith("\""))
			return;
		if (DEBUG)
			System.out.println (fileName  + ":[" + startLineNo + "-" + endLineNo + "]: " + expressionSyntax);
		if (db == null) {
			System.out.println("Error:Database handle is not initialized. Program will exit now!");
			System.exit(1);
		}
		
		try {
			table.insert(fileName, expressionSyntax, startLineNo, endLineNo);
		}
		catch (SqlJetException e) {
			e.printStackTrace();
		}
	}
}
