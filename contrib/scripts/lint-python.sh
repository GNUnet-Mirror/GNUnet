#!/bin/sh
# check python style (and 2 to 3 migration)
#
# behold, the worst lowest effort shell script
# ...given that we have more generic checking
# for executables in other scripts already

existence()
{
    command -v "$1" >/dev/null 2>&1
}

# invoke from root of source!
if [ $(basename $(pwd)) = "scripts" ]
then
   return 1
else
    if [ -e "python-lint.log" ]
    then
        rm "python-lint.log"
    fi

    if existence python;
    then
        python --version >> python-lint.log
    fi

    if existence python2;
    then
        python2 --version >> python-lint.log
    fi

    if existence python3;
    then
        python3 --version >> python-lint.log
    fi

    if existence python3.7;
    then
        python3.7 --version >> python-lint.log
    fi

    if existence flake8;
    then
        echo >> python-lint.log
        echo "flake8:" >> python-lint.log
        echo >> python-lint.log
        flake8 >> python-lint.log
    fi

    if existence flake8-3.7;
    then
        echo >> python-lint.log
        echo "flake8:" >> python-lint.log
        echo >> python-lint.log
        flake8-3.7 >> python-lint.log
    fi

    if existence 2to3;
    then
        echo >> python-lint.log
        echo "2to3" >> python-lint.log
        echo >> python-lint.log
        2to3 -v -d . >> python-lint.log
        2to3 -v -p . >> python-lint.log
    fi

    if existence 2to3-3.7;
    then
        echo >> python-lint.log
        echo "2to3" >> python-lint.log
        echo >> python-lint.log
        2to3-3.7 -v -d . >> python-lint.log
        2to3-3.7 -v -p . >> python-lint.log
    fi
fi
