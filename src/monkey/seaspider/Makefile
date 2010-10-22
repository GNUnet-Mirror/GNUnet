all:
	jtb C.jj
	javacc C.jj.out
	javac `find * -name "*.java"`
	jar -cvf seaspider.jar `find * -name "*.class"` 
