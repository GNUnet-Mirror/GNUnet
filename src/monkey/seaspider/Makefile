all:
	jtb C.jj
	javacc C.out.jj
	javac -5 -nowarn -classpath ../../../contrib/antlr-runtime-3.1.3.jariantlr-runtime-3.1.3.jarantlr-runtime-3.1.3.jar:../../../contrib/sqljet.1.0.3.b914.jar `find * -name "*.java"`
	jar -cvf seaspider.jar `find * -name "*.class"` 
