#!/usr/bin/env python

import angr, claripy
import sys, os, time, datetime, ntpath, struct, shutil, resource
from xml.dom import minidom

TIMEOUT = 3600
MEMCAP = 1024*1024*8 # 8GB
# simuvex, time
result_dir = os.path.join(os.getcwd(), "angr-out-" + datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))

error_log_file = 0
info_log_file = 0

running_time = 0
max_mem_usage = 0

def check_argv(argv):
    global error_log_file, info_log_file, result_dir

    xml_path = list()
    mk_dir = True

    if len(argv) == 2:
        input_xml = argv[1]
        if not os.path.isfile(input_xml):
            print "[ERROR] input file \'" + input_xml + "\' does not exist!"
            sys.exit()

        xml_path.append(os.path.abspath(input_xml))

    elif (len(argv) == 3) and (argv[1] == '-b'):
        input_folder = os.path.abspath(argv[2])
        if not os.path.isdir(input_folder):
            print "[ERROR] Invalid input folder for batch mode:  \'" + input_folder + "\'!"
            sys.exit()

        for f in sorted(os.listdir(input_folder)):
            if f.endswith('.xml'):
                serialize_file_path = os.path.join(input_folder, (f + '.serialized'))
                if not os.path.isfile(serialize_file_path):
                    print "[Warning] \'" + f + "\' does not have corresponding \'.serialized\'"
                    continue
                xml_path.append(os.path.join(input_folder, f))
                print f
    elif (len(argv) == 4) and (argv[1] == '-eb'):
        ## 'python angr-xml-ui.py -eb test.xml out-directory/'
        print "external batch mode!\n"

        input_xml = os.path.abspath(argv[2])
        if (not os.path.isfile(input_xml)) or (not input_xml.endswith('.xml')):
            print "[ERROR] Invalid input xml file for exteranl batch mode:  \'" + input_xml + "\'!"
            sys.exit()
        serialize_file_path = os.path.join(input_xml + '.serialized')
        if not os.path.isfile(serialize_file_path):
            print "[Error] \'" + f + "\' does not have corresponding \'.serialized\'"
            sys.exit()
        xml_path.append(input_xml);

        result_dir = os.path.abspath(argv[3])
        if(os.path.isdir(result_dir)):
            mk_dir = False
    else:
        print "[ERROR] Invalid argument!"
        sys.exit()

    if(mk_dir):
        os.makedirs(result_dir)

    os.chdir(result_dir)
    error_log_file=open("error.log", "a")
    info_log_file=open("info.log", "a")

    return xml_path

def parse_xml_exe(parsed_xml):
    target_exe = parsed_xml.getElementsByTagName('exec')[0].childNodes[0].nodeValue

    if not os.path.isfile(target_exe):
        print "[ERROR] target executable \'" + target_exe + "\' does not exist!"
        sys.exit()
    print "Target executable \'" + target_exe + "\' ..."

    return target_exe

def parse_xml_argv(parsed_xml, dic_args):
    xml_args = parsed_xml.getElementsByTagName('arg')

    for s in xml_args:
        index = int(s.attributes['index'].value)
        value = str(s.attributes['value'].value)
        size = 0
        if s.attributes['size'].value:
            size = int(s.attributes['size'].value)
        if size < len(value):
            size = len(value)
        concolic = s.attributes['concolic'].value

	if concolic == "true":
	    dic_args["argv_{0}".format(index)] = claripy.BVS("argv_{0}".format(index), size*8)
	else:
	    dic_args["argv_{0}".format(index)] = value

    for k,v in dic_args.iteritems():
        if isinstance(v, str):
            print k + ": string instance, concrete argument, value = " + v
        elif isinstance(v, claripy.ast.Bits):
            assert  v.size() % 8 == 0, \
                "size of a claripy AST instance has to be divisible by 8, while the size is %r" % v.size()
            size = v.size() / 8
            print k + ": claripy AST instance, symbolic argument, size = " + str(size)
        else:
            print "[Error] " + k + ": wrong type"
            print type(v)
            sys.exit()

    return dic_args

def parse_xml_file(parsed_xml):
    xml_files = parsed_xml.getElementsByTagName('file')
    list_files = list()

    for f in xml_files:
        path = str(f.attributes['path'].value)
        size = int(f.attributes['size'].value)
        concolic = f.attributes['concolic'].value

	if concolic == "true":
            # filename = ntpath.basename(path)
            list_files.append([path, size])
        else:
            print "[Error] Non-concolic file is given: " + path
            sys.exit()

    ## XXX: sequence of files are not the same as it is in xml file
    for k in list_files:
        print "concolic file: " + k[0] + ", " + str(k[1])

    return list_files

def parse_xml_stdin(parsed_xml):
    xml_stdin = parsed_xml.getElementsByTagName('stdin')
    if not xml_stdin:
        return 0
    if not len(xml_stdin) == 1:
        print "[Error] more than one stdin is given, please check input xml file"
        sys.exit()

    size = int(xml_stdin[0].attributes['size'].value)
    concolic = xml_stdin[0].attributes['concolic'].value

    if not concolic == "true":
        print "[Error] Non-concolic stdin is given"
        sys.exit()

    print "stdin_size from xml: " + str(size)
    return size

def write_angr_script(file_name, target_exe, dic_args, list_files, stdin_size):
    angr_script_file = open(file_name, "w")

    angr_script_file.write("import angr, claripy\n")
    angr_script_file.write("\n")

    angr_script_file.write("def exec_angr():\n")
    angr_script_file.write("    target_exe = '%s'\n" % target_exe)
    angr_script_file.write("\n")

    angr_script_file.write("    arguments = list()\n")
    for i in range(0, len(dic_args)):
        key = "argv_{0}".format(i)
        if not key in dic_args:
            print "[ERROR] incomplete argv list from xml: \'" + key + "\' not found"
            sys.exit()
        v = dic_args[key]
        if isinstance(v, str):
            angr_script_file.write("    arguments.append('{}')\n".format(v))
        elif isinstance(v, claripy.ast.Bits):
            angr_script_file.write("    arguments.append(claripy.BVS('{}', {}))\n".format(key, v.size()))
    angr_script_file.write("\n")

    angr_script_file.write("    files = {}\n")
    angr_script_file.write("    files['/dev/stdin'] = angr.storage.file.SimFile('/dev/stdin', 'r', size = 8)\n")
    angr_script_file.write("\n")

    for f in list_files:
        file_path = f[0]
        file_size = f[1]
        angr_script_file.write("    files['{}'] = angr.storage.file.SimFile('{}', 'r', size = {})\n".format(file_path, file_path, file_size))
        angr_script_file.write("    arguments.append('{}')\n".format(file_path))
    angr_script_file.write("\n")

    angr_script_file.write("    p = angr.Project(target_exe, load_options={'auto_load_libs':True})\n")
    angr_script_file.write("    state = p.factory.entry_state(args=arguments, fs=files)\n")
    angr_script_file.write("    sm = p.factory.simgr(state, save_unconstrained=True)\n")
    angr_script_file.write("    sm.run()\n")
    angr_script_file.write("\n")

    angr_script_file.write("if __name__ == '__main__':\n")
    angr_script_file.write("    exec_angr()\n")
    angr_script_file.write("\n")

    angr_script_file.close()

def check_timeout_memcap(start_time):
    global running_time, max_mem_usage

    running_time = time.time() - start_time
    max_mem_usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    # print "running_time = %s s, max_mem_usage = %s KB\n" %(running_time, max_mem_usage)

    return (running_time > TIMEOUT) or (max_mem_usage > MEMCAP)

def exec_angr(input_xml, target_exe, dic_args, list_files, stdin_size):
    print "========="
    print "exec_angr"
    print "========="

    os.chdir(result_dir)
    error_script_name  = "angr_error_{}.py".format(ntpath.basename(os.path.splitext(input_xml)[0]))
    write_angr_script(error_script_name, target_exe, dic_args, list_files, stdin_size)

    p = angr.Project(target_exe, load_options={'auto_load_libs':True})

    ## prepare arguments
    arguments=list()
    for i in range(0, len(dic_args)):
        key = "argv_{0}".format(i)
        if not key in dic_args:
            print "[ERROR] incomplete argv list from xml: \'" + key + "\' not found"
            sys.exit()
        arguments.append(dic_args[key])

    ## prepare files
    files = {}
    for f in list_files:
        file_path = f[0]
        file_size = f[1]
        files[file_path] = angr.storage.file.SimFile(file_path, "r", size = file_size)
        arguments.append(file_path)

    ## prepare stdin
    if not stdin_size == 0:
        files['/dev/stdin'] = angr.storage.file.SimFile("/dev/stdin", "r", size = stdin_size)

    ## debug prints
    for v in arguments:
        if isinstance(v, str):
            print "concrete argument: " + v
        elif isinstance(v, claripy.ast.Bits):
            print "symbolic argument"
        else:
            print "[Error] " + v + ": wrong type"
            print type(v)
            sys.exit()
    for k,v in files.iteritems():
        print "symbolic file: " + k

    state = p.factory.entry_state(args=arguments, fs=files)
    sm = p.factory.simgr(state, save_unconstrained=True)

    start_time = time.time()
    sm.step(until=lambda lpg: (check_timeout_memcap(start_time)))
    # sm.step(until=lambda lpg: len(lpg.active) > 1)

    os.remove(error_script_name)
    return sm

def get_simfile_content(s, file_path):
    # return s.posix.dump_file_by_path(file_path)
    print "file_path = {}".format(file_path)

    fd = s.posix.filename_to_fd(file_path)
    if(fd == None):
        # print "No fd found, use dump_file_by_path(): " + file_path
        return s.posix.dump_file_by_path(file_path)
    else:
        # print "fd found \'" + str(fd) + "\': " + file_path
        return s.posix.dumps(fd)


def get_test_case(s, dic_args, list_files, stdin_size, count):
    # print "--------------"
    # print "get_test_case:"
    # print "--------------"

    output = open("{}.bin".format(str(count)), "wb")
    elem_count = 0

    output.write(struct.pack("i", 0))

    for k,v in dic_args.iteritems():
        if not isinstance(v, claripy.ast.Bits):
            continue

        elem_count = elem_count + 1
        concrete_value = s.solver.eval(v, cast_to=str)

	#4B for the size of the arg name
        output.write(struct.pack("i", len(k)))

	#name
	output.write(str(k))

	#4B for size of value
        output.write(struct.pack("i", len(concrete_value)))

	#value
        output.write(str(concrete_value))


    for f in list_files:
        elem_count = elem_count + 1

        file_path = f[0]
        file_size = f[1]
        concrete_value = get_simfile_content(s, file_path)
        # print file_path + ": " + concrete_value + ", " + str(len(concrete_value))

        filename = str(ntpath.basename(file_path))

	#4B for the size of the file name
        output.write(struct.pack("i", len(filename)))
	#name
	output.write(filename)

	#4B for size of value
	output.write(struct.pack("i", file_size))

	#check if the string is longer than the file size, if so only take the first file_size bytes
	if (len(concrete_value) > file_size):
            strip = len(concrete_value) - file_size
            #output.write(concrete_value)
            concrete_value = concrete_value[:-strip]
            # print str(len(concrete_value))

	#write value
        output.write(concrete_value)

	#if string is shorter than the file size, fill the byte difference with 00
	if (len(concrete_value) < file_size):
            amount = file_size - len(concrete_value)
	    output.write(b'\x00' * amount)


    if not stdin_size == 0:
        elem_count = elem_count + 1
        stdin_content = get_simfile_content(s, "/dev/stdin")
        # print "stdin_content: " + stdin_content + ", " + str(len(stdin_content))

	#4B for the size of the name
        output.write(struct.pack("i", len("crete-stdin")))

	#name
	output.write("crete-stdin")

	#4B for size of value
	output.write(struct.pack("i", stdin_size))

	#check if the string is longer than the file size, if so only take the first stdin_size bytes
	if (len(stdin_content) > stdin_size):
            strip = len(stdin_content) - stdin_size
            stdin_content = stdin_content[:-strip]

        #write value
        output.write(stdin_content)

	#if string is shorter than the stdin size, fill the byte difference with 00
	if (len(stdin_content) < stdin_size):
            amount = stdin_size - len(stdin_content)
	    output.write(b'\x00' * amount)

    output.seek(0)
    output.write(struct.pack("i", elem_count))

def get_seed_test_case( dic_args, list_files, stdin_size, count):
    output = open("{}.bin".format(str(count)), "wb")
    elem_count = 0

    output.write(struct.pack("i", 0))

    for k,v in dic_args.iteritems():
        if not isinstance(v, claripy.ast.Bits):
            continue

        elem_count = elem_count + 1

	#4B for the size of the arg name
        output.write(struct.pack("i", len(k)))
	#name
	output.write(str(k))

	#4B for size of value
        assert  v.size() % 8 == 0, \
            "size of a claripy AST instance has to be divisible by 8, while the size is %r" % v.size()
        size = v.size() // 8
        output.write(struct.pack("i", size))
	#value
	output.write(b'\x00' * size)

    for f in list_files:
        elem_count = elem_count + 1

        file_path = f[0]
        file_size = f[1]

        filename = str(ntpath.basename(file_path))
	#4B for the size of the file name
        output.write(struct.pack("i", len(filename)))
	#name
	output.write(filename)

	#4B for size of value
	output.write(struct.pack("i", file_size))
        # value
        output.write(b'\x00' * file_size)

    if not stdin_size == 0:
        elem_count = elem_count + 1

	#4B for the size of the name
        output.write(struct.pack("i", len("crete-stdin")))
	#name
	output.write("crete-stdin")

	#4B for size of value
	output.write(struct.pack("i", stdin_size))
        #write value
        output.write(b'\x00' * stdin_size)

    output.seek(0)
    output.write(struct.pack("i", elem_count))

def setup_crete_out_folder(input_xml):
    output_folder = os.path.join(result_dir, ntpath.basename(input_xml))
    os.makedirs(output_folder)

    ## copy serialized xml to the correct place
    guest_config_folder = os.path.join(output_folder, "guest-data")
    os.makedirs(guest_config_folder)
    serialized_xml = str(input_xml) + ".serialized"
    # print "copy " + serialized_xml + " to " + os.path.join(guest_config_folder, "crete-guest-config.serialized")
    shutil.copyfile(serialized_xml, os.path.join(guest_config_folder, "crete-guest-config.serialized"))

    tc_folder = os.path.join(output_folder, "test-case-parsed")
    os.makedirs(tc_folder)
    os.chdir(tc_folder)


def collect_angr_result(sm, dic_args, list_files, stdin_size):
    print "==================="
    print "collect_angr_result"
    print "==================="

    print "deadended: " + str(len(sm.deadended))
    print "active: " + str(len(sm.active))
    print "unconstrained: " + str(len(sm.unconstrained))
    print "len(sum(simgr.stashes.values(), [])): " + str(len(sum(sm.stashes.values(), [])))

    get_seed_test_case(dic_args, list_files, stdin_size, 0)

    all_states = sum(sm.stashes.values(), [])
    tc_count = 0
    for s in all_states:
        tc_count = tc_count + 1
        get_test_case(s, dic_args, list_files, stdin_size, tc_count)



def run_angr_with_xml(input_xml):
    print "\n---------------------------\n"
    print "Start to test: '%s'\n"%(input_xml)

    parsed_xml = minidom.parse(input_xml)

    dic_args  = {}

    ## 1. parse target executable
    target_exe = parse_xml_exe(parsed_xml)
    dic_args["argv_0"] = str(target_exe)

    ## 2. parse xml arguments
    dic_args = parse_xml_argv(parsed_xml, dic_args)

    ## 3. parse xml files
    list_files = parse_xml_file(parsed_xml)

    ## 4. parse xml stdin
    stdin_size = parse_xml_stdin(parsed_xml)

    ## 5. start angr with parsed args, files and stdin
    sm = exec_angr(input_xml, target_exe, dic_args, list_files, stdin_size)

    ## 6. collect angr's result
    setup_crete_out_folder(input_xml)
    collect_angr_result(sm, dic_args, list_files, stdin_size)

    return

def angr_xml_ui(argv):
    list_xml = check_argv(argv)
    for xml in list_xml:
        try:
            run_angr_with_xml(xml)
            msg = "%s finished: %s s, %s MB\n"%(xml, running_time, max_mem_usage/1024.0)
            print(msg)
            info_log_file.write(msg)
        except:
            print("Error happened for: ", xml, " with error: ", sys.exc_info()[0] )
            error_log_file.write("Error happened for: " + str(xml) + " with error: " + str(sys.exc_info()[0]) + "\n")

if __name__ == '__main__':
    angr_xml_ui(sys.argv)
