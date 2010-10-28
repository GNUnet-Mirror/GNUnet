package org.gnunet.seaspider;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FilenameFilter;

import org.gnunet.seaspider.parser.CParser;
import org.gnunet.seaspider.parser.ParseException;
import org.gnunet.seaspider.parser.TokenMgrError;
import org.gnunet.seaspider.parser.nodes.Node;

public class Seaspider {
	
	private static final boolean DEBUG = true;
	private static CParser parser = null;
	private static boolean isFirstFile = true;
	private static int successCount = 0;
	private static int failureCount = 0;
	private static FilenameFilter filter = new FilenameFilter() {
		public boolean accept(File dir, String fileName) {
			File file = new File(dir.getPath() + "/" + fileName);
			if ((file.isDirectory() && !fileName.startsWith(".")) || (fileName.endsWith(".c") && !fileName.startsWith("test_")))
				/* directories like .svn are of no interest */
				return true;
			return false;
		}
	};
	
	
	private static void doParseFile(String filePath)
	{
		try {
   		 if (isFirstFile) {
   			 parser = new CParser(new FileInputStream(filePath));
   			 isFirstFile = false;
   		 }
   		 else
   			 parser.ReInit(new FileInputStream(filePath));
		 }
		 catch (FileNotFoundException e) {
			 /* This should never happen */
			 System.err.println("File not found!");
			 e.printStackTrace();
			 System.exit(1);
		 }
		 try {
			 System.out.println("Parsing file: " + filePath);
	         Node root = parser.TranslationUnit();
	         root.accept(new ExpressionExtractorVisitor(filePath));
	         System.out.println("File " + filePath + " parsed successfully.");
	         successCount++;
	     }
	     catch (ParseException e) {
	         System.out.println("Encountered errors during parsing file " + filePath);
	         failureCount++;
	         if (DEBUG)
	        	 e.printStackTrace();
	     } catch (TokenMgrError e) {
			System.err.println("Encountered errors during parsing file " + filePath + ":" + e.getMessage());
			failureCount++;
			if (DEBUG)
				e.printStackTrace();    	    	 
		}
	}
	
	
	private static void parseRecursively(String path)
	{
		File file = new File(path);
		
		if (!file.isDirectory()) {
			if (path.endsWith(".db"))
				return;
			/* A source file */
			doParseFile(path);
			return;
		}
		
		/* A source directory */
		System.out.println("Reading from: " + path + " source directory...");
		String[] dirContents = file.list(filter);/* Only directories and .c files */
		for (int i = 0; i < dirContents.length; i++) {
			String fullPath = path + "/" + dirContents[i];
			parseRecursively(fullPath);
		}
	}
	
   public static void main(String args[])
   {
     String dbFilePath = null;
     
     if (args.length < 2)
     {
    	 System.err.println("Invoke seaspider with database filename and source path!");
    	 System.exit(1);
     }    
     System.out.println("Seaspider 0.0\n");
     
     
     for (int i = 0; i < args.length; i++) {
    	 if (args[i].endsWith(".db"))
    		 dbFilePath = args[i];
    	 else {
    		 /* Should be a valid path for a file or a directory */
    		 File file = new File(args[i]);
    		 if (!file.exists()) {
    			 System.err.println("\"" + args[i] + "\" is an invalid file or directory location");
    			 System.exit(1);
    		 } else if (!file.isDirectory() && !args[i].endsWith(".c")) {
    			 System.err.println("\"" + args[i] + "\" only source files can be parsed");
    		 }
    	 }
     }
     if (null == dbFilePath) {
    	 System.err.println("Missing database file path");
    	 System.exit(1);
     }
     
     /* Create the Expressions Database */
     ExpressionDatabaseHandler.createExpressionDatabase(dbFilePath);
     
     for (int i = 0; i < args.length; i++)
    	 parseRecursively(args[i]);
     
     /* We're done with the Expression Database, close it */
     ExpressionDatabaseHandler.closeDatabase();
     
     System.out.println(successCount + " parsed successfully.");
     System.out.println("Failed to parse " + failureCount + " files.");
  }
}
