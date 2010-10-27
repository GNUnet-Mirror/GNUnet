package org.gnunet.seaspider;

import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

import org.gnunet.seaspider.parser.CParser;
import org.gnunet.seaspider.parser.ParseException;
import org.gnunet.seaspider.parser.TokenMgrError;
import org.gnunet.seaspider.parser.nodes.Node;

public class Seaspider {
	
	static final boolean DEBUG = false;
   
   public static void main(String args[])
   {
     CParser parser = null;
     boolean isFirstFile = true;
     int fileNotFoundCount = 0;
     int successCount = 0;
     int failureCount = 0;
     
     if (args.length != 2)
     {
    	 System.err.println("Invoke seaspider with database filename and source path!");
    	 System.exit(1);
     }    
     System.out.println("Seaspider 0.0\n");
     System.out.println("Reading from " + args[1] + " source directory...");
     String gnunetSourcePath = args[1];
     
     /* Filtering out files */
     FileFilter filter = new FileFilter() {
         public boolean accept(File file) {
             return file.isDirectory();
         }
     };
     
     /* File filter to get only source files and no test cases */
     FileFilter sourceFilter = new FileFilter() {
    	public boolean accept(File file) {
    		String fileName = file.getName();
    		return fileName.endsWith(".c") && ! fileName.startsWith("test_");
    	}
     };
     
     /* Create the Expressions Database */
     ExpressionDatabaseHandler.createExpressionDatabase(args[0]);
     
     File[] dirArr = (new File(gnunetSourcePath)).listFiles(filter);
     for (int i = 0; i < dirArr.length; i++) {
    	 File dir = dirArr[i];
    	 File[] fileArr = dir.listFiles(sourceFilter);
    	 for (int j = 0; j < fileArr.length; j++) {
    		 try {
        		 if (isFirstFile) {
        			 parser = new CParser(new FileInputStream(fileArr[j].getPath()));
        			 isFirstFile = false;
        		 }
        		 else
        			 parser.ReInit(new FileInputStream(fileArr[j].getPath()));
    		 }
    		 catch (FileNotFoundException e) {
    			 fileNotFoundCount++;
    			 e.printStackTrace();
    		 }
    		 try {
    	         Node root = parser.TranslationUnit();
    	         root.accept(new ExpressionExtractorVisitor(fileArr[j].getName()));
    	         System.out.println("File " + dir + "/" + fileArr[j].getName() + " parsed successfully.");
    	         successCount++;
    	     }
    	     catch (ParseException e) {
    	         System.err.println("Encountered errors during parsing file " + fileArr[j].getName() + ":" + e.getMessage());
    	         failureCount++;
    	         if (DEBUG)
    	        	 e.printStackTrace();
    	     } catch (TokenMgrError e)
    	     {
    	    	 System.err.println("Encountered errors during parsing file " + fileArr[j].getName() + ":" + e.getMessage());
    	         failureCount++;
    	         if (DEBUG)
    	        	 e.printStackTrace();    	    	 
    	     }
    	 }
     }
     
     /* We're done with the Expression Database, close it */
     ExpressionDatabaseHandler.closeDatabase();
     
     System.out.println(successCount + " parsed successfully.");
     System.out.println("Failed to parse " + failureCount + " files.");
     System.out.println(fileNotFoundCount + " files not found.");
  }

}
