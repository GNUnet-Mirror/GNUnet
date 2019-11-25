# This file has to be copied into the directory one level above.
# This also means (obviously): this file is excluded from including
# itself.

BUILDCOMMON_SHLIB_FILES = \
    build-common/sh/bin.sh/python.sh \
    build-common/sh/lib.sh/existence.sh \
    build-common/sh/lib.sh/existence_python.sh \
    build-common/sh/lib.sh/msg.sh \
    build-common/sh/lib.sh/progname.sh \
    build-common/sh/lib.sh/version_gnunet.sh \
    build-common/LICENSE

BUILDCOMMON_CONF_FILES = \
    build-common/conf/.dir-locals.el \
    build-common/conf/.prettierrc \
    build-common/conf/.style.yapf \
    build-common/conf/.vscode/settings.json \
    build-common/conf/.vscode/tasks.json \
    build-common/conf/.yarnrc \
    build-common/conf/uncrustify-mode.el \
    build-common/conf/uncrustify.cfg \
    build-common/conf/uncrustify.el \
    build-common/conf/uncrustify.sh \
    build-common/conf/uncrustify_precommit

BUILDCOMMON_BUILD_FILES = \
    build-common/bootstrap.template \
    build-common/configure \
    build-common/configure.py.template \
    build-common/talerbuildconfig.py \
    build-common/testconfigure.py

BUILDCOMMON_DOC_FILES = \
    build-common/README

BUILDCOMMON_SCRIPT_FILES = \
    build-common/coverage.sh

BUILD_COMMON_FILES = \
    $(BUILDCOMMON_SHLIB_FILES) \
    $(BUILDCOMMON_CONF_FILES) \
    $(BUILDCOMMON_BUILD_FILES) \
    $(BUILDCOMMON_DOC_FILES) \
    $(BUILDCOMMON_SCRIPT_FILES)
