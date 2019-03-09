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

LOGFILE="lint/python-lint.log"

# invoke from root of source!
if [ $(basename $(pwd)) = "scripts" ]
then
   return 1
else
    if [ -e "${LOGFILE}" ]
    then
        rm ${LOGFILE}
    fi

    if existence python;
    then
        python --version >> ${LOGFILE}
    fi

    if existence python2;
    then
        python2 --version >> ${LOGFILE}
    fi

    if existence python3;
    then
        python3 --version >> ${LOGFILE}
    fi

    if existence python3.7;
    then
        python3.7 --version >> ${LOGFILE}
    fi

    if existence flake8;
    then
        echo >> ${LOGFILE}
        echo "flake8:" >> ${LOGFILE}
        echo >> ${LOGFILE}
        flake8 >> ${LOGFILE}
    fi

    if existence flake8-3.7;
    then
        echo >> ${LOGFILE}
        echo "flake8:" >> ${LOGFILE}
        echo >> ${LOGFILE}
        flake8-3.7 >> ${LOGFILE}
    fi

    if existence 2to3;
    then
        echo >> ${LOGFILE}
        echo "2to3" >> ${LOGFILE}
        echo >> ${LOGFILE}
        2to3 -v -d . >> ${LOGFILE}
        2to3 -v -p . >> ${LOGFILE}
    fi

    if existence 2to3-3.7;
    then
        echo >> ${LOGFILE}
        echo "2to3" >> ${LOGFILE}
        echo >> ${LOGFILE}
        2to3-3.7 -v -d . >> ${LOGFILE}
        2to3-3.7 -v -p . >> ${LOGFILE}
    fi
fi
