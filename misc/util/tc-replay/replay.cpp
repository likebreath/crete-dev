#include "replay.h"
#include <crete/common.h>
#include <crete/tc-replay.h>

#include <external/alphanum.hpp>

#include <boost/filesystem/fstream.hpp>
#include <boost/program_options.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>

#include <string>
#include <ctime>
#include <sys/mount.h>

using namespace std;

static const string replay_log_file = "crete.replay.log";
static const string replay_launch_directory = "/tmp/crete-tc-replay-launch/";

namespace crete
{

CreteReplay::CreteReplay(int argc, char* argv[]) :
    m_ops_descr(make_options()),
    m_cwd(fs::current_path()),
    m_seed_mode(false),
    m_init_sandbox(true),
    m_enable_log(false)
{
    process_options(argc, argv);
    setup_launch();
    replay();
}

po::options_description CreteReplay::make_options()
{
    po::options_description desc("Options");

    desc.add_options()
        ("help,h", "displays help message")
        ("exec,e", po::value<fs::path>(), "executable to test")
        ("config,c", po::value<fs::path>(), "configuration file (found in guest-data/)")
        ("tc-dir,t", po::value<fs::path>(), "test case directory")
        ("seed-only,s", "Only replay seed test case (\"1\") from each test case "
                "directory")

        ("input-sandbox,j", po::value<fs::path>(), "input sandbox/jail directory")
        ("no-ini-sandbox,n", po::bool_switch(), "do not initialize sandbox to accumulate coverage info")

        ("input-launch-directory", po::value<fs::path>(), "input launch directory")

        ("environment,v", po::value<fs::path>(), "environment variables")
        ("log,l", po::bool_switch(), "enable log the output of replayed programs")
        ("exploitable-check,x", po::value<fs::path>(), "path to the output of exploitable-check")
        ("explo-check-script,r", po::value<fs::path>(), "path to the script to check exploitable with gdb replay")

        ("auto-replay,a", po::value<fs::path>(), "enable automatic replay on system start with given input folder (crete-dispatch output folder)")
        ("clear-auto-replay", po::bool_switch(), "clear the auto-replay for the given input folder")
        ;

    return desc;
}

void CreteReplay::process_options(int argc, char* argv[])
{
    try
    {
        po::store(po::parse_command_line(argc, argv, m_ops_descr), m_var_map);
        po::notify(m_var_map);
    }
    catch(...)
    {
        cerr << boost::current_exception_diagnostic_information() << endl;
        BOOST_THROW_EXCEPTION(std::runtime_error("Error for parsing options!\n"));
    }

    if(m_var_map.size() == 0)
    {
        cout << "Missing arguments" << endl;
        cout << "Use '--help' for more details" << endl;
        exit(0);
    }
    if(m_var_map.count("help"))
    {
        cout << m_ops_descr << endl;
        exit(0);
    }

    if(m_var_map.count("auto-replay"))
    {
        fs::path input = m_var_map["auto-replay"].as<fs::path>();
        bool clear = m_var_map["clear-auto-replay"].as<bool>();
        init_auto_mode(input, clear);
        return;
    }

    if(m_var_map.count("tc-dir") && m_var_map.count("config"))
    {
        m_tc_dir = m_var_map["tc-dir"].as<fs::path>();
        m_config = m_var_map["config"].as<fs::path>();
    } else {
        BOOST_THROW_EXCEPTION(std::runtime_error("Required options: [tc-dir] [config]. See '--help' for more info"));
    }

    if(m_var_map.count("exec"))
    {
        m_exec = m_var_map["exec"].as<fs::path>();

        if(!fs::exists(m_exec))
        {
            BOOST_THROW_EXCEPTION(std::runtime_error("Executable not found: "
                    + m_exec.generic_string()));
        }
    }

    if(m_var_map.count("input-sandbox"))
    {
        fs::path p = m_var_map["input-sandbox"].as<fs::path>();

        if(!fs::exists(p) && !fs::is_directory(p))
        {
            BOOST_THROW_EXCEPTION(Exception() << err::file_missing(p.string()));
        }

        m_input_sandbox = p;

        if(m_var_map.count("no-ini-sandbox"))
        {
            bool input = m_var_map["no-ini-sandbox"].as<bool>();

            m_init_sandbox = !input;
        }

        fprintf(stderr, "[crete-replay] input_sandbox_dir = %s, m_init_sandbox = %d\n",
                m_input_sandbox.string().c_str(), m_init_sandbox);

    }

    if(m_var_map.count("input-launch-directory"))
    {
        fs::path p = m_var_map["input-launch-directory"].as<fs::path>();

        if(!fs::exists(p) && !fs::is_directory(p))
        {
            BOOST_THROW_EXCEPTION(Exception() << err::file_missing(p.string()));
        }

        m_input_launch = fs::canonical(p);
    }

    if(!m_input_sandbox.empty() && !m_input_launch.empty())
    {
        BOOST_THROW_EXCEPTION(Exception() << err::msg("Only one of \'input-sandbox\' and \'input-launch-directory\' is allowed\n"));;
    }

    if(m_var_map.count("environment"))
    {
        fs::path p = m_var_map["environment"].as<fs::path>();

        if(!fs::exists(p) && !fs::is_regular(p))
        {
            BOOST_THROW_EXCEPTION(Exception() << err::file_missing(p.string()));
        }

        m_environment = p;
    }

    if(m_var_map.count("seed-only"))
    {
        m_seed_mode = true;
    } else {
        m_seed_mode = false;
    }

    if(m_var_map.count("log"))
    {
        bool input = m_var_map["log"].as<bool>();

        m_enable_log = input;
    }

    if(m_var_map.count("exploitable-check"))
    {
        m_exploitable_out = m_var_map["exploitable-check"].as<fs::path>();
        if(!fs::exists(m_exploitable_out))
        {
            fs::create_directories(m_exploitable_out);
        } else {
            CRETE_EXCEPTION_ASSERT(fs::is_directory(m_exploitable_out),
                    err::msg(m_exploitable_out.string() + "exists and is not a folder\n"));
        }

        if(!m_var_map.count("explo-check-script"))
        {
            BOOST_THROW_EXCEPTION(Exception() <<
                    err::file_missing("\'explo-check-script\' is required with \'exploitable-check\'"));
        }

        fs::path p= m_var_map["explo-check-script"].as<fs::path>();
        if(!fs::exists(p) && !fs::is_regular(p))
        {
            BOOST_THROW_EXCEPTION(Exception() << err::file_missing(p.string()));
        }
        m_exploitable_script = p;
    }

    if(!fs::exists(m_tc_dir))
    {
        BOOST_THROW_EXCEPTION(std::runtime_error("Input test case directory not found: "
                + m_tc_dir.generic_string()));
    }

    if(!fs::exists(m_config))
    {
        BOOST_THROW_EXCEPTION(std::runtime_error("Crete-config file not found: " + m_config.string()));
    }
}

// Reference:
// http://unix.stackexchange.com/questions/128336/why-doesnt-mount-respect-the-read-only-option-for-bind-mounts
static inline void rdonly_bind_mount(const fs::path src, const fs::path dst)
{
    assert(fs::is_directory(src));
    assert(fs::is_directory(dst));

    int mount_result = mount(src.string().c_str(), dst.string().c_str(), NULL,
            MS_BIND, NULL);
    if(mount_result != 0)
    {
        fprintf(stderr, "[crete-run] mount failed: "
                "src = %s, dst = %s, mntflags = MS_BIND\n",
                src.string().c_str(), dst.string().c_str());

        assert(0);
    }

    // equal cmd: "sudo mount /home sandbox-dir/home/ -o bind,remount,ro"
    mount_result = mount(src.string().c_str(), dst.string().c_str(), NULL,
            MS_BIND | MS_REMOUNT | MS_RDONLY, NULL);
    if(mount_result != 0)
    {
        fprintf(stderr, "[crete-run] mount failed: "
                "src = %s, dst = %s, mntflags = MS_BIND | MS_REMOUNT | MS_RDONLY\n",
                src.string().c_str(), dst.string().c_str());

        assert(0);
    }
}

static void reset_folder_permission_recursively(const fs::path& root)
{
    for(fs::recursive_directory_iterator it(root), endit;
            it != endit; ++it) {
        if(!fs::is_symlink(*it)){
            fs::permissions(*it, fs::owner_all);
        }
    }
}

// make sure the folder has the right permission within sandbox:
// 1. "/": the root of sandbox
// 2. "/tmp"
// 3. "/tmp/launch-directory"
void CreteReplay::reset_sandbox_folder_permission()
{
    {
        fs::path p = CRETE_SANDBOX_PATH;
        if(fs::exists(p))
        {
            fs::permissions(p, fs::perms_mask);
        }
    }

    {
        fs::path p = fs::path(CRETE_SANDBOX_PATH) / "tmp";
        if(fs::exists(p))
        {
            fs::permissions(p, fs::perms_mask);
        }
    }

    {
        fs::path p = fs::path(CRETE_SANDBOX_PATH) / m_launch_directory;
        if(fs::exists(p))
        {
            fs::permissions(p, fs::perms_mask);
            reset_folder_permission_recursively(p);
        }
    }
}

// Mount folders to sandbox dir:
//  "/home, /lib, /lib64, /usr, /dev, /proc" (for executable, dependency libraries, etc)
// require: "sudo setcap CAP_SYS_ADMIN+ep ./crete-run"
void CreteReplay::init_sandbox()
{
    reset_sandbox_folder_permission();

    // delete the sandbox folder if it existed
    if(fs::is_directory(CRETE_SANDBOX_PATH))
    {
        for (fs::directory_iterator end_dir_it, it((fs::path(CRETE_SANDBOX_PATH))); it!=end_dir_it; ++it)
        {
            int ret = umount(it->path().string().c_str());

            if(ret != 0)
            {
                fprintf(stderr, "umount() failed on: %s, check whether sys_cap_admin is set\n",
                        it->path().string().c_str());
            }
        }

        fs::remove_all(CRETE_SANDBOX_PATH);
        assert(!fs::exists(CRETE_SANDBOX_PATH) && "[crete-run] crete-sandbox folder reset failed!\n");
    }

    {
        const fs::path src = "/home";
        if(fs::is_directory(src))
        {
            const fs::path dst = fs::path(CRETE_SANDBOX_PATH) / "home";
            fs::create_directories(dst);
            rdonly_bind_mount(src, dst);
        }
    }
    {
        const fs::path src = "/lib";
        if(fs::is_directory(src))
        {
            const fs::path dst = fs::path(CRETE_SANDBOX_PATH) / "lib";
            fs::create_directories(dst);
            rdonly_bind_mount(src, dst);
        }
    }
    {
        const fs::path src = "/lib64";
        if(fs::is_directory(src))
        {
            const fs::path dst = fs::path(CRETE_SANDBOX_PATH) / "lib64";
            fs::create_directories(dst);
            rdonly_bind_mount(src, dst);
        }
    }
    {
        const fs::path src = "/usr";
        if(fs::is_directory(src))
        {
            const fs::path dst = fs::path(CRETE_SANDBOX_PATH) / "usr";
            fs::create_directories(dst);
            rdonly_bind_mount(src, dst);
        }
    }
    {
        const fs::path src = "/dev";
        if(fs::is_directory(src))
        {
            const fs::path dst = fs::path(CRETE_SANDBOX_PATH) / "dev";
            fs::create_directories(dst);
            rdonly_bind_mount(src, dst);
        }
    }
    {
        const fs::path src = "/proc";
        if(fs::is_directory(src))
        {
            const fs::path dst = fs::path(CRETE_SANDBOX_PATH) / "proc";
            fs::create_directories(dst);
            rdonly_bind_mount(src, dst);
        }
    }

    fs::create_directories(fs::path(CRETE_SANDBOX_PATH) / "tmp");
    fs::create_directories(fs::path(CRETE_SANDBOX_PATH) / CRETE_REPLAY_GCOV_PREFIX);
}

void CreteReplay::reset_sandbox()
{
    reset_sandbox_folder_permission();

    // 2. reset "sandbox-exec folder" within sandbox
    fs::path crete_sandbox_exec_path = fs::path(CRETE_SANDBOX_PATH) / m_launch_directory;
    fs::remove_all(crete_sandbox_exec_path);
    assert(fs::exists(fs::path(crete_sandbox_exec_path).parent_path()));

    bp::context ctx;
    ctx.stdout_behavior = bp::capture_stream();
    ctx.environment = bp::self::get_environment();

    std::string exec = bp::find_executable_in_path("cp");
    std::vector<std::string> args;
    args.push_back(exec);
    args.push_back("-r");
    args.push_back(m_input_sandbox.string());
    args.push_back(crete_sandbox_exec_path.string());

    bp::child c = bp::launch(exec, args, ctx);

    bp::pistream &is = c.get_stdout();

    // TODO: xxx should check the return status to make sure the "cp" completed successfully
    bp::status s = c.wait();
}

void CreteReplay::reset_launch_dir()
{
    assert(m_launch_directory == fs::path(replay_launch_directory) / fs::canonical(m_input_launch).filename());
    if(fs::exists(m_launch_directory))
    {
        fs::remove_all(m_launch_directory);
    }

    fs::path launch_parent_dir = m_launch_directory.parent_path();
    if(!fs::exists(launch_parent_dir))
    {
        fs::create_directories(launch_parent_dir);
    }

    bp::context ctx;
    ctx.stdout_behavior = bp::capture_stream();
    ctx.environment = bp::self::get_environment();

    std::string exec = bp::find_executable_in_path("cp");
    std::vector<std::string> args;
    args.push_back(exec);
    args.push_back("-r");
    args.push_back(m_input_launch.string());
    args.push_back(launch_parent_dir.string());

    bp::child c = bp::launch(exec, args, ctx);

    bp::pistream &is = c.get_stdout();

    // TODO: xxx should check the return status to make sure the "cp" completed successfully
    bp::status s = c.wait();
}

void CreteReplay::setup_launch()
{
    // 0. Process m_config
    fs::ifstream ifs(m_config.string());

    if(!ifs.good())
    {
        BOOST_THROW_EXCEPTION(Exception() << err::file_open_failed(m_config.string()));
    }

    config::HarnessConfiguration guest_config;
    try
    {
        boost::archive::text_iarchive ia(ifs);
        ia >> guest_config;
    }
    catch(std::exception& e)
    {
        cerr << boost::diagnostic_information(e) << endl;
        BOOST_THROW_EXCEPTION(e);
    };

    // 0. setup m_exec if it is not specified as input of crete-replay
    if(m_exec.empty())
    {

        m_exec = guest_config.get_executable();

        if(!fs::exists(m_exec))
        {
            BOOST_THROW_EXCEPTION(std::runtime_error("Executable not found: "
                    + m_exec.generic_string()));
        }
    }

    // 1. Setup m_launch_directory
    if(!m_input_sandbox.empty())
    {
        m_launch_directory = fs::path("/tmp") / fs::canonical(m_input_sandbox).filename();
    } else if (!m_input_launch.empty()) {
        m_launch_directory = fs::path(replay_launch_directory) / fs::canonical(m_input_launch).filename();
    } else {
        // By default, m_exec_launch_dir is set to the parent folder of the executable,
        // unless that folder is not writable (then it will be the working
        // directory of crete-run)
        m_launch_directory = m_exec.parent_path();
        if(access(m_launch_directory.string().c_str(), W_OK) != 0)
        {
            m_launch_directory = fs::current_path();
        }
    }

    // 2. Set up m_launch_args
    config::Arguments guest_args = guest_config.get_arguments();

    m_launch_args.resize(guest_args.size()+1, string());
    m_launch_args[0] = m_exec.string();

    for(config::Arguments::const_iterator it = guest_args.begin();
            it != guest_args.end(); ++it) {
        assert(it->index < m_launch_args.size());
        assert(m_launch_args[it->index].empty());
        m_launch_args[it->index] = it->value;
    }

    // 3. Setup m_launch_ctx
    m_launch_ctx.output_behavior.insert(bp::behavior_map::value_type(STDOUT_FILENO, bp::capture_stream()));
    m_launch_ctx.output_behavior.insert(bp::behavior_map::value_type(STDERR_FILENO, bp::redirect_stream_to_stdout()));
    m_launch_ctx.input_behavior.insert(bp::behavior_map::value_type(STDIN_FILENO, bp::capture_stream()));

    m_launch_ctx.work_directory = m_launch_directory.string();

    if(!m_environment.empty())
    {
        assert(m_launch_ctx.environment.empty());
        std::ifstream ifs (m_environment.string().c_str());
        if(!ifs.good())
            BOOST_THROW_EXCEPTION(Exception() << err::file_open_failed(m_environment.string()));

        std::string env_name;
        std::string env_value;
        while(ifs >> env_name >> env_value)
        {
            m_launch_ctx.environment.insert(bp::environment::value_type(env_name, env_value));
        }
    } else {
        m_launch_ctx.environment = bp::self::get_environment();
    }
    m_launch_ctx.environment.insert(bp::environment::value_type("LD_PRELOAD", "libcrete_replay_preload.so"));
    m_launch_ctx.environment.erase("PWD");
    m_launch_ctx.environment.insert(bp::environment::value_type("PWD", m_launch_ctx.work_directory));

    if(!m_input_sandbox.empty())
    {
        m_launch_ctx.chroot = CRETE_SANDBOX_PATH;

        m_launch_ctx.environment.erase("GCOV_PREFIX");
        m_launch_ctx.environment.insert(bp::environment::value_type("GCOV_PREFIX", CRETE_REPLAY_GCOV_PREFIX));

        if(m_init_sandbox)
        {
            init_sandbox();
        }
    }

    // 4. setup the path for guest_config_serialized
    if(m_input_sandbox.empty())
    {
        m_guest_config_serialized = CRETE_CONFIG_SERIALIZED_PATH;
        m_current_tc = CRETE_REPLAY_CURRENT_TC;
    } else {
        m_guest_config_serialized = fs::path(CRETE_SANDBOX_PATH) / CRETE_CONFIG_SERIALIZED_PATH;
        m_current_tc = fs::path(CRETE_SANDBOX_PATH) / CRETE_REPLAY_CURRENT_TC;
    }

    m_launch_ctx.environment.insert(bp::environment::value_type(CRETE_CONCOLIC_NAME_SUFFIX, "_p1"));

    m_launch_ctx_secondary = m_launch_ctx;
    m_secondary_cmds = guest_config.get_secondary_cmds();
}

// Get current date/time, format is YYYY-MM-DD.HH:mm:ss
static const std::string currentDateTime() {
    time_t     now = time(0);
    struct tm  tstruct;
    char       buf[80];
    tstruct = *localtime(&now);
    // Visit http://en.cppreference.com/w/cpp/chrono/c/strftime
    // for more information about date/time format
    strftime(buf, sizeof(buf), "%Y-%m-%d.%X", &tstruct);

    return buf;
}

static bool end_with (std::string const &fullString, std::string const &ending)
{
    if (fullString.length() >= ending.length()) {
        return (0 == fullString.compare (fullString.length() - ending.length(), ending.length(), ending));
    } else {
        return false;
    }
}

void CreteReplay::collect_gcov_result()
{
//    fprintf(stderr, "collect_gcov_result() entered\n");

    // gcov data is in the right place if no sandbox is used
    if(m_input_sandbox.empty())
    {
        return;
    }

    // FIXME: xxx temp workwround that it make take a while for gcov to generate gcda files
    //        the sleep time of 1 seconds are subjective here
    sleep(1);

    fs::path gcov_data_dir = fs::path(CRETE_SANDBOX_PATH) / CRETE_REPLAY_GCOV_PREFIX;
    for ( boost::filesystem::recursive_directory_iterator end, it(gcov_data_dir);
            it!= end; ++it) {
        if(fs::is_directory(it->path()))
            continue;

        fs::path src = it->path();
        assert(fs::is_regular_file(src));
        if(!end_with(src.filename().string(), ".gcda"))
        {
            fprintf(stderr, "[crete-tc-replay] unexpected file: %s\n", src.string().c_str());
            assert(0);
        }

        assert(src.string().find(gcov_data_dir.string()) == 0);
        fs::path tgt(src.string().c_str() +  gcov_data_dir.string().length());
        assert(fs::is_directory(tgt.parent_path()));

//        fprintf(stderr, "copy from %s to %s\n",
//                src.string().c_str(),
//                tgt.string().c_str());

        fs::copy_file(src, tgt, fs::copy_option::overwrite_if_exists);
    }

//    fprintf(stderr, "collect_gcov_result() finished\n");
}

static unsigned monitored_pid = 0;
static unsigned monitored_timeout = 5;

static void timeout_handler(int signum)
{
    fprintf(stderr, "Send timeout (%d seconds) signal to its child process\n", monitored_timeout);
    assert(monitored_pid != 0);
    kill(monitored_pid, SIGUSR1);

    // exit() can cause deadlock within signal handlers, but it is required for coverage
    // Double kill the process
    sleep(1);
    kill(monitored_pid, SIGKILL);
}

static inline void init_timeout_handler()
{
    struct sigaction sigact;

    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_handler = timeout_handler;
    sigaction(SIGALRM, &sigact, NULL);
}

// ret: true, if signal catched; false, if not
static inline bool process_exit_status(fs::ofstream& log, int exit_status)
{
    if(exit_status == 0)
    {
        log << "NORMAL EXIT STATUS.\n";
        return false;
    }

    bool ret = false;
    if((exit_status > CRETE_EXIT_CODE_SIG_BASE) &&
            (exit_status < (CRETE_EXIT_CODE_SIG_BASE + SIGUNUSED)) )
    {
        int signum = exit_status - CRETE_EXIT_CODE_SIG_BASE ;
        if(signum == SIGUSR1)
        {
            log << "Replay Timeout\n";
        } else {
            log << "[Signal Caught] signum = " << signum << ", signame: " << strsignal(signum) << endl;
            ret = true;
        }
    }

    log << "ABNORMAL EXIT STATUS: " << exit_status << endl;

    return ret;
}

static vector<string> get_files_ordered(const fs::path& input)
{
    CRETE_EXCEPTION_ASSERT(fs::exists(input),
            err::file_missing(input.string()));
    assert(fs::is_directory(input));

    // Sort the files alphabetically
    vector<string> file_list;
    for ( fs::directory_iterator itr( input );
          itr != fs::directory_iterator();
          ++itr ){
        file_list.push_back(itr->path().string());
    }

    sort(file_list.begin(), file_list.end(), doj::alphanum_less<string>());

    return file_list;
}

static bool execute_command_line(const std::string& cmd, const bp::posix_context& ctx,
        fs::ofstream& log)
{
    bool ret = true;

    std::vector<std::string> args;
    boost::split(args, cmd, boost::is_any_of(" "), boost::token_compress_on);

    std::string exec = args[0];
    if(!fs::exists(exec))
    {
        exec = bp::find_executable_in_path(exec);
    }

    if(!fs::exists(exec))
    {
        fprintf(stderr, "[CRETE ERROR] [crete-run] command not found: %s\n", exec.c_str());
        assert(0);
    }

    // Special handling of executing sleep function
    if(exec.find("sleep") != string::npos)
    {
        sleep(1);
        return ret;
    }

    bp::posix_child c = bp::posix_launch(exec, args, ctx);

    // Start alarm
    monitored_pid = c.get_id();
    assert(monitored_timeout != 0);
    alarm(monitored_timeout);

//    log << "Output from executing: " << cmd.c_str() << endl;
//    bp::pistream& is = c.get_stdout();
//    std::string line;
//    while(getline(is, line))
//    {
//        log << line << endl;
//    }

    int status;
    int w = waitpid(monitored_pid, &status, WUNTRACED);

    // Stop alarm
    if(alarm(0) ==0)
    {
        log << "[CRETE Warning] alarm() returns '0', indicates a time-out, from executing: "
                << cmd.c_str() << endl;
    }

    if(w == -1)
    {
        // 1. waitpid() failed
        ret = false;

        if(errno == EINTR)
        {
            log << "[CRETE Warning] waitpid() failed with 'EINTR' (may caused by time-out) from executing: "
                    << cmd.c_str() << endl;
        } else {
            log << "[CRETE Warning] wiatpid() failed from executing: " << cmd.c_str() << endl;
        }
    } else if(!WIFEXITED(status)) {
        // 2. waitpid() succeeded, but waiting process is not exited
        log << "[CRETE Warning] waitpid() process is not exited: " << cmd.c_str() << endl;
        ret = false;

        if(WIFSTOPPED(status))
        {
            log << "waitpid() process is stopped with signal: " << WSTOPSIG(status) << endl;
        }
    } else {
        // 3. waitpid() succeeded, and waiting process is exited
        int ret_value = WEXITSTATUS(status);
        if(ret_value != 0)
        {
            ret = false;
        } else
        {
            ret = true;
        }
    }

    return ret;
}

static void write_to_procfs(const string& msg, const fs::path &procfs)
{
    ofstream ifs(procfs.string().c_str());
    if(!ifs.good())
    {
        BOOST_THROW_EXCEPTION(Exception() << err::file_open_failed(procfs.string()));
    }

    ifs << msg;

    ifs.close();
}

static void setup_kernel_mode(const fs::path& current_tc)
{
    fs::path crete_replay_procfs(fs::path("/proc") / CRETE_REPLAY_PROCFS);

    if(!fs::exists(crete_replay_procfs))
        return;

    // 1. issue reset
    write_to_procfs("Reset", crete_replay_procfs);

    // 2. write "test cases"
    ifstream ifs(current_tc.string().c_str());
    if(!ifs.good())
    {
        BOOST_THROW_EXCEPTION(Exception() <<
                err::file_open_failed(current_tc.string()));
    }
    TestCase tc = read_test_case(ifs);
    ifs.close();

    for(vector<TestCaseElement>::const_iterator tc_iter = tc.get_elements().begin();
            tc_iter !=  tc.get_elements().end(); ++tc_iter)
    {
        stringstream ss_tc;

        uint32_t name_size = tc_iter->name_size;
        string name(tc_iter->name.begin(), tc_iter->name.end());
        assert(name_size == name.size());

        uint32_t data_size = tc_iter->data_size;
        string data(tc_iter->data.begin(), tc_iter->data.end());
        assert(data_size == data.size());

        ss_tc.write((const char *)&name_size, sizeof(name_size));
        ss_tc << name;
        ss_tc.write((const char *)&data_size, sizeof(data_size));
        ss_tc << data;

        write_to_procfs("TestCase", crete_replay_procfs);
        write_to_procfs(ss_tc.str(), crete_replay_procfs);
    }
}

static void setup_auto_mode_resume_file(fs::path auto_mode_work_dir, fs::path current_tc);

void CreteReplay::replay()
{
    init_timeout_handler();

    // Read all test cases to replay
    vector<string> test_list = get_files_ordered(m_tc_dir);

    fs::ofstream ofs_replay_log;

    if(m_enable_log)
    {
        ofs_replay_log.open(m_cwd / replay_log_file, std::ios_base::app);
    } else {
        ofs_replay_log.open("/dev/null");
    }

    ofs_replay_log << "Replay Summary: [" << currentDateTime() << "]\n"
            << "Executable path: " << m_exec.string() << endl
            << "Test case directory path: " << m_tc_dir.string() << endl
            << "Guest config path: " << m_config.string() << endl
            << "Working directory: " << m_cwd.string() << endl
            << "Launch direcotory: " << m_launch_directory.string() << endl
            << "Number of test cases: " << test_list.size() << endl
            << endl;

    uint64_t replayed_tc_count = 1;
    for (vector<string>::const_iterator it(test_list.begin()), it_end(test_list.end());
            it != it_end; ++it)
    {
        if(m_seed_mode && (replayed_tc_count != 1))
        {
            break;
        }

        setup_auto_mode_resume_file(m_auto_mode_path, *it);

        // check for kernel mode
        setup_kernel_mode(*it);

        ofs_replay_log << "====================================================================\n";
        ofs_replay_log << "Start to replay tc[" << dec << replayed_tc_count++ <<"] :" << it->c_str() << endl;

        // prepare for replay
        {
            if(!m_input_sandbox.empty())
            {
                reset_sandbox();
            }

            if(!m_input_launch.empty())
            {
                reset_launch_dir();
            }

            // write replay_current_tc, for replay-preload to use
            fs::remove(m_current_tc);
            fs::copy(*it, m_current_tc);

            // copy guest-config, for replay-preload to use
            try
            {
                fs::remove(m_guest_config_serialized);
                fs::copy(m_config, m_guest_config_serialized);
            }
            catch(std::exception& e)
            {
                cerr << boost::diagnostic_information(e) << endl;
                BOOST_THROW_EXCEPTION(e);
            }
        }

        // Launch the executable
        {
#if 0
            std::string exec_cmd = "LD_PRELOAD=\"libcrete_replay_preload.so\" ";
            for(vector<string>::const_iterator it = m_launch_args.begin();
                    it != m_launch_args.end(); ++it) {
                exec_cmd = exec_cmd + (*it) + " ";
            }

            std::cerr << "Launch program with system(): " << exec_cmd << std::endl;

            std::system(exec_cmd.c_str());
#else
            sync();

            bp::posix_child proc = bp::posix_launch(m_exec, m_launch_args, m_launch_ctx);

            monitored_pid = proc.get_id();
            assert(monitored_timeout != 0);
            alarm(monitored_timeout);

            ofs_replay_log << "Output from Launched executable:\n";
            bp::pistream& is = proc.get_stdout();
            std::string line;
            stringstream ss_prog_out;
            while(getline(is, line))
            {
                ofs_replay_log << line << endl;
                ss_prog_out << line << endl;
            }
#endif

            bp::status status = proc.wait();
            if(alarm(0) == 0)
            {
                ofs_replay_log << "[CRETE Warning]Launched executable: timed-out\n";
            }

            bool signal_caught;
            if(status.exited())
            {
                signal_caught = process_exit_status(ofs_replay_log, status.exit_status());
            } else {
                // When the child process is not terminated from exit()/_exit(),
                // assuming there is a signal caught.
                signal_caught = true;
            }

            if(signal_caught)
            {
                check_exploitable(*it, ss_prog_out.str());
            }
        }

        // execute secondary cmds
        {
            unsigned int sec_cmd_count = 1;
            for(vector<string>::const_iterator it = m_secondary_cmds.begin();
                    it != m_secondary_cmds.end(); ++it) {
                m_launch_ctx_secondary.environment.erase(CRETE_CONCOLIC_NAME_SUFFIX);
                m_launch_ctx_secondary.environment.insert(bp::environment::value_type(
                        CRETE_CONCOLIC_NAME_SUFFIX, "_p" + boost::lexical_cast<std::string>(++sec_cmd_count)));

                bool cmd_executed = execute_command_line(*it, m_launch_ctx_secondary, ofs_replay_log);
                if(!cmd_executed)
                {
                    ofs_replay_log << "[CRETE Warning][crete-replay] \'" << it->c_str() << "\' executed unsuccessfully.\n";
                }
            }

            sync();
        }
        ofs_replay_log << "====================================================================\n";
    }

//    collect_gcov_result();
//    cleanup_auto_mode();
}

// FIXME: xxx add timeout to deal with GDB hanging
static vector<string> run_gdb_script(const CheckExploitable& ck_exp,
        const string& script)
{
    cerr << "run_gdb_script() entered\n";

    bp::context ctx;
    ctx.stdout_behavior = bp::capture_stream();
    ctx.stderr_behavior = bp::redirect_stream_to_stdout();
    ctx.stdin_behavior = bp::capture_stream();
    ctx.work_directory = ck_exp.m_p_launch;

    fs::copy_file(CRETE_TC_REPLAY_GDB_SCRIPT,
            fs::path(ctx.work_directory) / CRETE_TC_REPLAY_GDB_SCRIPT,
            fs::copy_option::overwrite_if_exists);

    std::string exec = bp::find_executable_in_path("gdb");
    std::vector<std::string> args;
    args.push_back("gdb");
    args.push_back("-x");
    args.push_back(script);

    bp::child c = bp::launch(exec, args, ctx);

    monitored_pid = c.get_id();
    assert(monitored_timeout != 0);
    alarm(monitored_timeout*3);

    bp::pistream &is = c.get_stdout();
    std::string line;

    vector<string> gdb_out;
    while (std::getline(is, line))
    {
        gdb_out.push_back(line);
    }

    alarm(0);

    cerr << "run_gdb_script() finished\n";
    return gdb_out;
}

static fs::path prepare_explo_dir(const CheckExploitable& ck_exp,
        const CheckExploitableResult& result, const fs::path out_dir)
{
    CRETE_EXCEPTION_ASSERT(fs::is_directory(out_dir),
            err::file_missing(out_dir.string()));

    fs::path parsed_explo = out_dir;
    if(!fs::exists(parsed_explo))
    {
        fs::create_directories(parsed_explo);
    } else {
        CRETE_EXCEPTION_ASSERT(fs::is_directory(parsed_explo),
                err::msg(parsed_explo.string() + "exists and is not a folder\n"));
    }

    fs::path prog_out = parsed_explo / fs::path(ck_exp.m_p_exec).filename();
    if(!fs::exists(prog_out))
    {
        fs::create_directories(prog_out);
    } else {
        CRETE_EXCEPTION_ASSERT(fs::is_directory(parsed_explo),
                err::msg(prog_out.string() + "exists and is not a folder\n"));
    }

    fs::path explo_out = prog_out / (result.m_exp_ty_msg + "-" + result.m_hash);
    if(fs::exists(explo_out))
    {
        CRETE_EXCEPTION_ASSERT(fs::is_directory(parsed_explo),
                err::msg(explo_out.string() + "exists and is not a folder\n"));

        explo_out = explo_out / "others";
        if(!fs::exists(explo_out))
        {
            fs::create_directories(explo_out);
        } else {
            CRETE_EXCEPTION_ASSERT(fs::is_directory(parsed_explo),
                    err::msg(explo_out.string() + "exists and is not a folder\n"));
        }

        for (int i = 1; ; i++) {
            fs::path dirPath = explo_out / boost::lexical_cast<std::string>(i);
            if(!fs::exists(dirPath)) {
                explo_out = dirPath.string();
                break;
            }
        }
    }

    assert(!fs::exists(explo_out));
    fs::create_directories(explo_out);

    return explo_out;
}

static void write_exploitable_log(const CheckExploitable& ck_exp,
        const vector<string>& gdb_out, const fs::path out_dir,
        const fs::path& tc_path, const string& replay_log)
{
    CheckExploitableResult result(gdb_out);

    fs::path explo_out = prepare_explo_dir(ck_exp, result, out_dir);
    assert(fs::is_directory(explo_out));

    fs::path exe_launch_dir = ck_exp.m_p_launch;
    // 1. gdb_script
    fs::copy_file(exe_launch_dir / CRETE_TC_REPLAY_GDB_SCRIPT,
            explo_out / CRETE_TC_REPLAY_GDB_SCRIPT);

    // 2. all files
    for(uint64_t i = 0; i < ck_exp.m_files.size(); ++i)
    {
        fs::copy_file(exe_launch_dir / ck_exp.m_files[i],
                    explo_out / ck_exp.m_files[i]);
    }

    fs::copy_file(exe_launch_dir / ck_exp.m_stdin_file,
                explo_out / ck_exp.m_stdin_file);

    // 3. summary_log
    ofstream ofs((explo_out / CRETE_EXPLO_SUMMARY_LOG).string().c_str());

    ofs << "================\n"
        << "Exploitable log:\n"
        << "================\n\n";

    ofs << "Exploitability Classification: " << result.m_exp_ty_msg << endl
        << "Description: " << result.m_description << endl
        << "Explanation: " << result.m_explanation << endl << endl
        << "Note: generated by \"GDB 'exploitable' plugin\" (https://github.com/jfoote/exploitable)"
        << endl << endl;

    ofs << "=================\n"
        << "Complete GDB log:\n"
        << "=================\n\n";

    for(uint64_t i = 0; i < gdb_out.size(); ++i)
    {
        ofs << gdb_out[i] << endl;
    }

    ofs << "==========\n"
        << "CRETE log:\n"
        << "==========\n\n";

    ofs << "crete-tc: " << tc_path.string() << endl << endl;

    ofs << "-----------------------\n"
        << "crete-tc-replay output:\n"
        << "-----------------------\n\n"
        << replay_log << endl;


    ofs.close();
}

void CreteReplay::check_exploitable(const fs::path& tc_path,
        const string& replay_log) const
{
    if(m_exploitable_script.empty())
        return;

    assert(m_input_sandbox.empty() &&
            "[CRETE ERROR] NOT support check for exploitable with sandbox replay.\n");

    cerr << "check_exploitable: " << tc_path.string() << endl;
    assert(fs::exists(CRETE_TC_REPLAY_CK_EXP_INFO));
    ifstream ifs(CRETE_TC_REPLAY_CK_EXP_INFO, ios_base::binary);
    boost::archive::binary_iarchive ia(ifs);

    CheckExploitable ck_exp;
    ia >> ck_exp;

    assert(ck_exp.m_p_launch == m_launch_directory.string());
    ck_exp.m_p_exploitable_script = m_exploitable_script.string();
    ck_exp.gen_gdb_script(CRETE_TC_REPLAY_GDB_SCRIPT);

    vector<string> gdb_out = run_gdb_script(ck_exp, CRETE_TC_REPLAY_GDB_SCRIPT);

    write_exploitable_log(ck_exp, gdb_out, m_exploitable_out,
            tc_path, replay_log);
}

// Reference: https://stackoverflow.com/a/39146566
void copyDirectoryRecursively(const fs::path& sourceDir, const fs::path& destinationDir)
{
    if (!fs::exists(sourceDir) || !fs::is_directory(sourceDir))
    {
        throw std::runtime_error("Source directory " + sourceDir.string() + " does not exist or is not a directory");
    }
    if (fs::exists(destinationDir))
    {
        throw std::runtime_error("Destination directory " + destinationDir.string() + " already exists");
    }
    if (!fs::create_directory(destinationDir))
    {
        throw std::runtime_error("Cannot create destination directory " + destinationDir.string());
    }

    for ( fs::recursive_directory_iterator end, dirEnt(sourceDir);
            dirEnt!= end; ++dirEnt) {
        const fs::path& path = dirEnt->path();
        string relativePathStr = path.string();
        assert(relativePathStr.find(sourceDir.string()) == 0);
        relativePathStr.erase(0, sourceDir.string().size());
        fs::copy(path, destinationDir / relativePathStr);
    }
}

static const char *kdump_crash_dir = "/var/crash/crete/"; //FIXME: xxx make it portable
static const char *collect_info_dir =  "crete_replay_info";
static const char *auto_mode_log = "/home/test/crete-replay-auto-mode.log";
static const char *resume_file_name = "CRETE_REPLAY_AUTO_RESUME";
static const char *resume_tc_dir = "crete_replay_resume_tc_dir";

void CreteReplay::init_auto_mode(fs::path &input, bool clear)
{
    fs::ofstream log(auto_mode_log, std::ios_base::app);
    if(!log.good())
    {
        fprintf(stderr, "[CRETE ERROR] can't open log file: %s\n", auto_mode_log);
        log.close();

        exit(-1);
    }

    if(!fs::is_directory(input))
    {
        cerr << currentDateTime() << " [CRETE WARNING] Input folder does not exist for auto-replay mode: "
            << input.string().c_str() << endl;
        log << currentDateTime() << " [CRETE WARNING] Input folder does not exist for auto-replay mode: "
            << input.string().c_str() << endl;
        exit(0);
    }

    // XXX: Now only supports sub_dirs generated by crete-dispatch with distrubuted mode
    m_auto_mode_path = fs::canonical(input);

    if(clear)
    {
        cleanup_auto_mode();

        fs::path info_dir = m_auto_mode_path / collect_info_dir;
        if(fs::exists(info_dir))
        {
            fs::remove_all(info_dir);
        }

        if(fs::exists(kdump_crash_dir))
        {
            fs::remove_all(kdump_crash_dir);
        }

        if(fs::exists(auto_mode_log))
        {
            fs::remove_all(auto_mode_log);
        }

        exit(0);
    }

    fs::path resume_file(m_auto_mode_path / resume_file_name);
    if(fs::exists(resume_file))
    {
        // If resumed, collect crash information
        fs::ifstream inf(resume_file);
        if(!inf.good())
        {
            cerr << currentDateTime() << " [CRETE ERROR] RESUME FILE broken: " << resume_file.string().c_str() << endl;
            log << currentDateTime() << " [CRETE ERROR] RESUME FILE broken: " << resume_file.string().c_str() << endl;
            exit(0);
        }

        fs::path resume_work_tc;
        string tmp;
        getline(inf, tmp);
        resume_work_tc = tmp;
        inf.close();

        if(!fs::is_regular(resume_work_tc))
        {
            cerr << currentDateTime() << " [CRETE ERROR] invalid resume work_tc: "
                    << resume_work_tc.string().c_str() << endl;
            log << currentDateTime() << " [CRETE ERROR] invalid resume work_tc: "
                    << resume_work_tc.string().c_str() << endl;
            exit(0);
        }

        fs::path resume_info_dir =  m_auto_mode_path / collect_info_dir / currentDateTime();
        fs::create_directories(resume_info_dir);
        // Collect test-case
        fs::copy_file(resume_work_tc, resume_info_dir / resume_work_tc.filename());
        fs::remove(resume_work_tc);

        // Collect kernel crash log
        fs::path kdump_dir(kdump_crash_dir);
        if(!fs::is_directory(kdump_dir))
        {
            cerr << currentDateTime() << " [CRETE ERROR] invalid kdump_crash_dir: "
                    << kdump_crash_dir << endl;
            log << currentDateTime() << " [CRETE ERROR] invalid kdump_crash_dir: "
                    << kdump_crash_dir << endl;
            exit(0);
        }

        for ( fs::directory_iterator itr( kdump_dir );
              itr != fs::directory_iterator();
              ++itr ){
            fs::path src_dir = itr->path();
            if(!fs::is_directory(src_dir))
                continue;

            copyDirectoryRecursively(src_dir, resume_info_dir / src_dir.filename());
            fs::remove_all(src_dir);
        }
    } else {
        // If not resumed, initial start, setup auto-replay
        fs::path tc_dir = m_auto_mode_path / "test-case-parsed";
        if(!fs::is_directory(tc_dir))
        {
            cerr << currentDateTime() << " [CRETE ERROR] wrong folder structure, can't find: "
                    << tc_dir.string().c_str() << endl;
            log << currentDateTime() << " [CRETE ERROR] wrong folder structure, can't find: "
                    << tc_dir.string().c_str() << endl;
            exit(0);
        }

        // copy "test-case-parsed" folder to "auto_tc_dir"
        fs::path auto_tc_dir = m_auto_mode_path / resume_tc_dir;
        if(fs::exists(auto_tc_dir))
        {
            fs::remove_all(auto_tc_dir);
        }
        copyDirectoryRecursively(tc_dir, auto_tc_dir);
    }

    m_tc_dir = m_auto_mode_path / resume_tc_dir;
    m_config = m_auto_mode_path / "guest-data" / "crete-guest-config.serialized";
    m_enable_log = true;

    if(!fs::is_directory(m_tc_dir))
    {
        cerr << currentDateTime() << " [CRETE ERROR] wrong folder structure, can't find: "
                << m_tc_dir.string().c_str() << endl;
        log << currentDateTime() << " [CRETE ERROR] wrong folder structure, can't find: "
                << m_tc_dir.string().c_str() << endl;
        exit(0);
    }

    if(!fs::exists(m_config))
    {
        cerr << currentDateTime() << " [CRETE ERROR] wrong folder structure, can't find: "
                << m_config.string().c_str() << endl;
        log << currentDateTime() << " [CRETE ERROR] wrong folder structure, can't find: "
                << m_config.string().c_str() << endl;
        exit(0);
    }

    log.close();
}

void CreteReplay::cleanup_auto_mode() const
{
    if(m_auto_mode_path.empty())
    {
        return;
    }

    fs::path resume_file = m_auto_mode_path / resume_file_name;
    if(fs::exists(resume_file))
    {
        fs::remove_all(resume_file);
    }

    fs::path __resume_tc = m_auto_mode_path / resume_tc_dir;
    if(fs::exists(__resume_tc))
    {
        fs::remove_all(__resume_tc);
    }

    if(fs::exists(auto_mode_log))
    {
        if(fs::is_directory(m_auto_mode_path / collect_info_dir))
        {
            fs::copy_file(auto_mode_log,
                    m_auto_mode_path / collect_info_dir / fs::path(auto_mode_log).filename(),
                    fs::copy_option::overwrite_if_exists);
        }

        fs::remove_all(auto_mode_log);
    }

    if(fs::exists(kdump_crash_dir))
    {
        fs::remove_all(kdump_crash_dir);
    }

    fs::path log_file = m_cwd / replay_log_file;
    if(fs::exists(log_file))
    {
        if(fs::is_directory(m_auto_mode_path / collect_info_dir))
        {
            fs::copy_file(log_file,
                    m_auto_mode_path / collect_info_dir / replay_log_file,
                    fs::copy_option::overwrite_if_exists);
        }

        fs::remove_all(log_file);
    }
}

static void setup_auto_mode_resume_file(fs::path auto_mode_work_dir, fs::path current_tc)
{
    static fs::path previous_tc;

    if(auto_mode_work_dir.empty())
        return;

    if(!previous_tc.empty())
    {
        assert(fs::is_regular(previous_tc));
        fs::remove(previous_tc);
    }

    fs::ofstream log(auto_mode_log, std::ios_base::app);
    if(!log.good())
    {
        fprintf(stderr, "[CRETE ERROR] can't open log file: %s\n", auto_mode_log);
        log.close();

        exit(-1);
    }

    fs::path resume_file(auto_mode_work_dir / resume_file_name);

    fs::ofstream onf(resume_file);
    if(!onf.good())
    {
        cerr << currentDateTime() << " [CRETE ERROR] can't write RESUME FILE: " << resume_file.string().c_str() << endl;
        log << currentDateTime() << " [CRETE ERROR] can't write RESUME FILE: " << resume_file.string().c_str() << endl;

        exit(0);
    }
    fs::path work_tc = fs::canonical(current_tc);
    onf << work_tc.string() << endl;
    onf.close();

    previous_tc = current_tc;
    log.close();

    sync();
}

} // namespace crete

int main(int argc, char* argv[])
{
    try
    {
        crete::CreteReplay CreteReplay(argc, argv);
    }
    catch(...)
    {
        cerr << "[CRETE Replay] Exception Info: \n"
                << boost::current_exception_diagnostic_information() << endl;
        return -1;
    }

    return 0;
}
