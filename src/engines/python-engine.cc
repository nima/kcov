#include <file-parser.hh>
#include <engine.hh>
#include <configuration.hh>
#include <output-handler.hh>
#include <lineid.hh>
#include <utils.hh>
#include <zlib.h>

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <list>
#include <unordered_map>

#include "../swap-endian.hh"

using namespace kcov;

extern "C" size_t python_helper_data_size;
extern "C" uint8_t python_helper_data[];


const uint64_t COVERAGE_MAGIC = 0x6d6574616c6c6775ULL; // "metallgut"

/* Should be 8-byte aligned */
struct coverage_data
{
	uint64_t magic;
	uint32_t size;
	uint32_t line;
	const char filename[];
};

class PythonEngine : public IEngine, public IFileParser
{
public:
	PythonEngine() :
		m_child(0),
		m_running(false),
		m_pipe(NULL),
		m_listener(NULL),
		m_currentAddress(1) // 0 is an invalid address
	{
		IEngineFactory::getInstance().registerEngine(*this);
		IParserManager::getInstance().registerParser(*this);
	}

	// From IEngine
	int registerBreakpoint(unsigned long addr)
	{
		// No breakpoints
		return 0;
	}

	void setupAllBreakpoints()
	{
	}

	bool clearBreakpoint(int id)
	{
		return true;
	}

	bool start(IEventListener &listener, const std::string &executable)
	{
		std::string kcov_python_pipe_path =
				IOutputHandler::getInstance().getOutDirectory() + "kcov-python.pipe";
		std::string kcov_python_path =
				IOutputHandler::getInstance().getBaseDirectory() + "python-helper.py";

		if (write_file(python_helper_data, python_helper_data_size, kcov_python_path.c_str()) < 0) {
				error("Can't write python helper at %s", kcov_python_path.c_str());

				return false;
		}

		m_listener = &listener;

		std::string kcov_python_env = "KCOV_PYTHON_PIPE_PATH=" + kcov_python_pipe_path;
		unlink(kcov_python_pipe_path.c_str());
		mkfifo(kcov_python_pipe_path.c_str(), 0600);

		char *envString = (char *)xmalloc(kcov_python_env.size() + 1);
		strcpy(envString, kcov_python_env.c_str());

		putenv(envString);

		/* Launch the python helper */
		m_child = fork();
		if (m_child == 0) {
			auto &conf = IConfiguration::getInstance();
			const char **argv = conf.getArgv();
			unsigned int argc = conf.getArgc();

			std::string s = fmt("%s %s ",
					conf.getPythonCommand().c_str(),
					kcov_python_path.c_str());
			for (unsigned int i = 0; i < argc; i++)
				s += std::string(argv[i]) + " ";

			int res;

			res = system(s.c_str());
			panic_if (res < 0,
					"Can't execute python helper");

			exit(WEXITSTATUS(res));
		} else if (m_child < 0) {
			perror("fork");

			return false;
		}
		m_running = true;
		m_pipe = fopen(kcov_python_pipe_path.c_str(), "r");
		panic_if (!m_pipe,
				"Can't open python pipe %s", kcov_python_pipe_path.c_str());

		return true;
	}

	bool checkEvents()
	{
		uint8_t buf[8192];
		size_t sz;
		struct coverage_data *p;

		p = readCoverageDatum(buf, sizeof(buf), sz);

		if (!p) {
			reportEvent(ev_error, -1);

			return false;
		}

		if (!m_reportedFiles[p->filename]) {
			m_reportedFiles[p->filename] = true;

			for (const auto &it : m_fileListeners)
				it->onFile(p->filename, IFileParser::FLG_NONE);

			parseFile(p->filename);
		}

		if (m_listener) {
			uint64_t address = 0;
			Event ev;

			auto it = m_lineIdToAddress.find(LineId(p->filename, p->line));
			if (it != m_lineIdToAddress.end())
				address = it->second;

			ev.type = ev_breakpoint;
			ev.addr = address;
			ev.data = 1;

			m_listener->onEvent(ev);
		}

		return true;
	}

	bool continueExecution()
	{
		if (checkEvents())
			return true;


		// Otherwise wait for child
		int status;
		int rv;

		rv = waitpid(m_child, &status, WNOHANG);
		if (rv != m_child)
			return true;

		if (WIFEXITED(status)) {
			reportEvent(ev_exit_first_process, WEXITSTATUS(status));
		} else {
			warning("Other status: 0x%x\n", status);
			reportEvent(ev_error, -1);
		}

		return false;
	}

	bool childrenLeft()
	{
		return m_running;
	}

	std::string eventToName(Event ev)
	{
		return "";
	}

	void kill()
	{
	}

	unsigned int matchFile(const std::string &filename, uint8_t *data, size_t dataSize)
	{
		return matchParser(filename, data, dataSize);
	}


	// From IFileParser
	bool addFile(const std::string &filename, struct phdr_data_entry *phdr_data)
	{
		return true;
	}

	void registerLineListener(ILineListener &listener)
	{
		m_lineListeners.push_back(&listener);
	}

	void registerFileListener(IFileListener &listener)
	{
		m_fileListeners.push_back(&listener);
	}

	bool parse()
	{
		return true;
	}

	uint64_t getChecksum()
	{
		return 0;
	}

	unsigned int matchParser(const std::string &filename, uint8_t *data, size_t dataSize)
	{
		std::string s((const char *)data, 80);

		if (filename.substr(filename.size() - 3, filename.size()) == ".py")
			return 200;

		if (s.find("python") != std::string::npos)
			return 100;

		return match_none;
	}

private:
	void reportEvent(enum event_type type, int data = -1, uint64_t address = 0)
	{
		if (!m_listener)
			return;

		m_listener->onEvent(Event(type, data, address));
	}

	void unmarshalCoverageData(struct coverage_data *p)
	{
		p->magic = be_to_host<uint64_t>(p->magic);
		p->size = be_to_host<uint32_t>(p->size);
		p->line = be_to_host<uint32_t>(p->line);
	}

	// Sweep through lines in a file to determine what is valid code
	void parseFile(const std::string &filename)
	{
		if (!m_listener)
			return;

		size_t sz;
		char *p = (char *)read_file(&sz, "%s", filename.c_str());

		// Can't handle this file
		if (!p)
			return;
		std::string fileData(p, sz);

		// Compute crc32 for this file
		uint32_t crc = crc32(0, (unsigned char *)p, sz);

		free((void*)p);

		const auto &stringList = split_string(fileData, "\n");
		unsigned int lineNo = 0;
		enum { start, multiline_active } state = start;
		bool multiLineStartLine = false;

		for (const auto &it : stringList) {
			const auto &s = trim_string(it);

			lineNo++;
			// Empty line, ignore
			if (s == "")
				continue;

			// Non-empty, but comment
			if (s[0] == '#')
				continue;

			auto idx = multilineIdx(s);

			switch (state)
			{
			case start:
				if (idx != std::string::npos) {
					kcov_debug(PTRACE_MSG, "python multiline ON  %3d: %s\n", lineNo, s.c_str());

					std::string s2 = s.substr(idx + 3, std::string::npos);

					if (multilineIdx(s2) == std::string::npos)
						state = multiline_active;

					// E.g., a = '''yadayada [...]'''
					if (idx > 0)
						multiLineStartLine = true;

					// Don't report this line
					continue;
				}
				break;
			case multiline_active:
				if (idx != std::string::npos) {
					kcov_debug(PTRACE_MSG, "python multiline OFF %3d: %s\n", lineNo, s.c_str());
					state = start;

					// The last line of a multi-line string will get reported by the
					// python helper, so add this as a line if there was an assignment
					// above
					if (multiLineStartLine) {
						fileLineFound(crc, filename, lineNo);
						multiLineStartLine = false;
					}
				}
				continue; // Don't report this line
			default:
				panic("Unknown state %u", state);
				break;
			}

			fileLineFound(crc, filename, lineNo);
		}
	}

	void fileLineFound(uint32_t crc, const std::string &filename, unsigned int lineNo)
	{
		LineId id(filename, lineNo);
		uint64_t address = m_currentAddress ^ crc;

		m_lineIdToAddress[id] = address;

		for (const auto &lit : m_lineListeners)
			lit->onLine(filename.c_str(), lineNo, address);

		m_currentAddress++;
	}

	size_t multilineIdx(const std::string &s)
	{
		auto idx = s.find("'''");

		if (idx == std::string::npos)
			idx = s.find("\"\"\"");

		return idx;
	}



	struct coverage_data *readCoverageDatum(uint8_t *buf, size_t totalSize, size_t &outSz)
	{
		struct coverage_data *p = (struct coverage_data *)buf;
		ssize_t rv;

		rv = fread(buf, 1, sizeof(struct coverage_data), m_pipe);
		if (rv == 0)
			return NULL; // Not an error
		if (rv < (int)sizeof(struct coverage_data)) {
			error("Read too little %zd", rv);

			return NULL;
		}
		unmarshalCoverageData(p);

		if (p->magic != COVERAGE_MAGIC ||
				p->size > totalSize - sizeof(struct coverage_data)) {
			error("Data magic wrong or size too large: magic 0x%llx, size %u (%zu left)\n",
					(unsigned long long)p->magic,
					(unsigned int)p->size,
					totalSize);

			return NULL;
		}

		size_t remainder = p->size - sizeof(struct coverage_data);
		rv = fread(buf + sizeof(struct coverage_data), 1, remainder, m_pipe);
		if (rv < (ssize_t)remainder) {
			error("Read too little %zd vs %zu", rv, remainder);

			return NULL;
		}

		return p;
	}

	typedef std::list<ILineListener *> LineListenerList_t;
	typedef std::list<IFileListener *> FileListenerList_t;
	typedef std::unordered_map<std::string, bool> ReportedFileMap_t;
	typedef std::unordered_map<LineId, uint64_t, LineIdHash> LineIdToAddressMap_t;

	pid_t m_child;
	bool m_running;
	FILE *m_pipe;

	LineListenerList_t m_lineListeners;
	FileListenerList_t m_fileListeners;
	ReportedFileMap_t m_reportedFiles;
	LineIdToAddressMap_t m_lineIdToAddress;

	IEventListener *m_listener;
	uint64_t m_currentAddress;
};

static PythonEngine g_instance;
