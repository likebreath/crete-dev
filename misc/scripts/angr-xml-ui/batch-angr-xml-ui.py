#!/usr/bin/env python

import angr, claripy
import sys, os, time, datetime, ntpath, struct, shutil, resource
from xml.dom import minidom

TIMEOUT = 300
MEMCAP = 1024*150 # 8GB
# simuvex, time
result_dir = os.path.join(os.getcwd(), "batch-angr-out-" + datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))

def check_argv(argv):
    xml_path = list()

    if (len(argv) == 2):
        input_file = os.path.abspath(argv[1])
        if not os.path.isfile(input_file):
            print "[ERROR] Invalid input file for external batch mode:  \'" + input_file + "\'!"
            sys.exit()

        lines = tuple(open(argv[1]).read().split('\n'))
        for f in sorted(lines):
            xml_file = os.path.abspath(f)
            if xml_file.endswith('.xml'):
                serialize_file_path = xml_file + '.serialized'
                if not os.path.isfile(serialize_file_path):
                    print "[Warning] \'" + xml_file + "\' does not have corresponding \'.serialized\'"
                    continue
                xml_path.append(xml_file)
                print xml_file

    else:
        print "[ERROR] Invalid argument!"
        sys.exit()

    os.makedirs(result_dir)
    os.chdir(result_dir)

    return xml_path

def angr_xml_ui(argv):
    list_xml = check_argv(argv)
    error_log_file=open("external_batch_error.log", "w")
    for xml in list_xml:
        try:
            command='python /home/chenbo/crete/crete-dev/misc/scripts/angr-xml-ui/angr-xml-ui.py -eb %s %s'%(xml, result_dir)
            os.system(command)
        except:
            print("Error happened for: ", xml, " with error: ", sys.exc_info()[0] )
            error_log_file.write("Error happened for: " + str(xml) + " with error: " + str(sys.exc_info()[0]) + "\n")

if __name__ == '__main__':
    angr_xml_ui(sys.argv)
