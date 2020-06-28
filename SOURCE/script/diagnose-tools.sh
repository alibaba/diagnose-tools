#!/bin/bash

if [ "X${EXPERIENTIAL}" == "X" ]; then
	EXPERIENTIAL="0"
fi

KO_PATH="/usr/diagnose-tools/lib/`uname -r`/"

function start_uninstall() {

    /sbin/lsmod | grep diagnose > /dev/null

    if [ $? -ne 0 ];then
        echo "already uninstalled"
        return
    fi

    /sbin/rmmod diagnose
    if [ $? -eq 0 ];then
        echo "uninstalled successfully"
        return
    else
        echo "failed to uninstall"
        exit 1
    fi
}

function start_install() {

    /sbin/lsmod | grep diagnose > /dev/null
    if [ $? -eq 0 ];then
        echo "already installed"
        exit 1
    fi

    if [ ! -d $KO_PATH ];then
        echo "rpm installed failed, please check"
        exit 1
    fi

    install_ko="${KO_PATH}/diagnose.ko"
    if [ ! -f $install_ko ];then
        echo "rpm installed failed, please check"
        exit 1
    fi

    /sbin/insmod ${install_ko}

    if [ $? -eq 0 ];then
        echo "installed successfully"
        return
    else
        echo "failed to install"
        exit 1
    fi
}

function usage()
{
	echo "$0 usage:"
	echo "    $0 --help: print this text"
	echo "    $0 install: install module into system"
	echo "    $0 uninstall: remove module from system"
	echo ""
	echo "/***************************************************************************/"
	echo "/*                                                                         */"
	echo "/*       More help documents are in /usr/diagnose-tools/usage.docx         */"
	echo "/*                                                                         */"
	echo "/***************************************************************************/"
	echo ""

	exit
}

function call_sub_cmd()
{
	func=$1
	func=${func//-/_}
	shift 1
	eval "$func $*"
}

function main()
{
	if [ $# -eq 0 ]; then
		usage
	fi

	if  [ "$1" = "?" ]; then
		usage
	fi

	if  [ "$1" = "--help" ]; then
		usage
	fi

	if [ "$1" = "install" ]; then
		if [ $# -ne 1 ]; then
			usage
		fi

		start_install
		exit $?
	fi

	if [ "$1" = "uninstall" ]; then
		if [ $# -ne 1 ]; then
			usage
		fi

		start_uninstall
		exit $?
	fi

	SUB_CMD=$1
	type ${SUB_CMD//-/_} > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		usage
	else
		shift 1;
		call_sub_cmd $SUB_CMD $*
		exit $?
	fi

	usage
}

main $*
