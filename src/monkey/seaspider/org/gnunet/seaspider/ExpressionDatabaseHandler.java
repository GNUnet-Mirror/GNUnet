package org.gnunet.seaspider.parser;

import java.io.File;

import org.tmatesoft.sqljet.core.SqlJetException;
import org.tmatesoft.sqljet.core.SqlJetTransactionMode;
import org.tmatesoft.sqljet.core.table.ISqlJetTable;
import org.tmatesoft.sqljet.core.table.SqlJetDb;

public class ExpressionDatabaseHandler {
	
	private static SqlJetDb db = null;
	
	public static void createExpressionDatabase(String databasePath) {
		String createTableQuery = "CREATE TABLE Expression ( expr_ID INT NOT NULL PRIMARY KEY , " +
		"file_name TEXT NOT NULL , expr_syntax TEXT NOT NULL ," +
		" start_lineno INT NOT NULL , end_lineno INT NOT NULL , " +
		"scope_start_lineno INT NOT NULL , scope_end_lineno INT NOT NULL)";
		
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
		}
		catch (SqlJetException e) {
			e.printStackTrace();
		}
	}
	
	
	public static void closeDatabase()
	{
		try {
			db.close();
		} catch (SqlJetException e) {
			e.printStackTrace();
		}
	}
	
	
	public static void insertIntoExpressionTable(String fileName, String expressionSyntax, 
												int startLineNo, int endLineNo, int scopeStartLineNo,
												int scopeEndLineNo)
	{
		if (db == null) {
			System.out.println("Error:Database handle is not initialized. Program will exit now!");
			System.exit(1);
		}
		
		ISqlJetTable table;
		try {
			table = db.getTable("Expression");
			db.beginTransaction(SqlJetTransactionMode.WRITE);
			try {
				table.insert(fileName, expressionSyntax, startLineNo, endLineNo, scopeStartLineNo, scopeEndLineNo);
			} finally {
				db.commit();
			}
		}
		catch (SqlJetException e) {
			e.printStackTrace();
		}
	}
}
