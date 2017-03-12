#include <file-parser.hh>
#include <engine.hh>
#include <configuration.hh>
#include <output-handler.hh>
#include <utils.hh>
#include <generated-data-base.hh>

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <signal.h>

#include <list>
#include <unordered_map>
#include <vector>


#include <dyninst/BPatch.h>
#include <dyninst/BPatch_statement.h>
#include <dyninst/BPatch_point.h>
#include <dyninst/BPatch_function.h>

using namespace kcov;

extern GeneratedData __dyninst_library_data;
extern GeneratedData __dyninst_binary_library_data;

class DyninstEngine : public IEngine, public IFileParser
{
public:
	DyninstEngine() :
		m_listener(NULL),
		m_bpatch(NULL),
		m_process(NULL),
		m_addressSpace(NULL),
		m_binaryEdit(NULL),
		m_image(NULL),
		m_reporterInitFunction(NULL),
		m_addressReporterFunction(NULL),
		m_pipe(NULL),
		m_breakpointIdx(0)
	{
		IParserManager::getInstance().registerParser(*this);
	}

	virtual ~DyninstEngine()
	{
	}

	// From IEngine
	virtual int registerBreakpoint(unsigned long addr)
	{
		std::vector<BPatch_point *> pts;

		if (!m_image->findPoints(addr, pts))
			return -1;

		std::vector< BPatch_snippet * > args;
		BPatch_snippet id = BPatch_constExpr(m_breakpointIdx);

		args.push_back(&id);

		BPatch_funcCallExpr call(*m_addressReporterFunction, args);
		addSnippet(call, pts);

		m_breakpointIdx++;

		return m_breakpointIdx - 1;
	}

	void addSnippet(BPatch_snippet &snippet, std::vector<BPatch_point *> &where)
	{
		BPatchSnippetHandle *handle = m_addressSpace->insertSnippet(snippet, where,
				BPatch_lastSnippet);

		if (!handle)
			return;

		for (std::vector<BPatch_point *>::iterator it = where.begin();
				it != where.end();
				++it)
			m_snippetsByPoint[*it] = handle;
	}


	// From IFileParser
	virtual bool addFile(const std::string &filename, struct phdr_data_entry *phdr_data)
	{
		m_filename = filename;

		for (FileListenerList_t::const_iterator it = m_fileListeners.begin();
				it != m_fileListeners.end();
				++it)
			(*it)->onFile(File(m_filename, IFileParser::FLG_NONE));


		// Actual parsing is done in start
		return true;
	}

	virtual bool setMainFileRelocation(unsigned long relocation)
	{
		return true;
	}

	virtual void registerLineListener(ILineListener &listener)
	{
		m_lineListeners.push_back(&listener);
	}

	virtual void registerFileListener(IFileListener &listener)
	{
		m_fileListeners.push_back(&listener);
	}

	virtual bool parse()
	{
		// Handled when the program is launched
		return true;
	}

	virtual uint64_t getChecksum()
	{
		return 0;
	}

	virtual enum IFileParser::PossibleHits maxPossibleHits()
	{
		return IFileParser::HITS_LIMITED;
	}

	virtual void setupParser(IFilter *filter)
	{
		if (!m_bpatch)
			m_bpatch = new BPatch();
	}

	std::string getParserType()
	{
		return "dyninst";
	}

	unsigned int matchParser(const std::string &filename, uint8_t *data, size_t dataSize)
	{
		return 1;
	}

	bool start(IEventListener &listener, const std::string &executable)
	{
		IConfiguration &conf = IConfiguration::getInstance();
		std::string libraryPath =
				IOutputHandler::getInstance().getBaseDirectory() + "libkcov-dyninst.so";
		std::string binaryLibraryPath =
				IOutputHandler::getInstance().getBaseDirectory() + "libkcov-binary-dyninst.so";

		write_file(__dyninst_library_data.data(), __dyninst_library_data.size(),
				"%s", libraryPath.c_str());
		write_file(__dyninst_binary_library_data.data(), __dyninst_binary_library_data.size(),
				"%s", binaryLibraryPath.c_str());

		m_listener = &listener;

		setupEnvironment();

		if (0) {
			unsigned int pid = conf.keyAsInt("attach-pid");

			if (pid != 0)
				m_process = m_bpatch->processAttach(executable.c_str(), pid);
			else
				m_process = m_bpatch->processCreate(executable.c_str(), conf.getArgv());

			if (!m_process) {
				error("Cannot launch process\n");

				return false;
			}

			BPatch_object *p = m_process->loadLibrary(libraryPath.c_str());
			if (!p) {
				kcov_debug(INFO_MSG, "Can't load kcov dyninst library\n");

				return false;
			}

			// Is also an address space
			m_addressSpace = m_process;
		} else {
			m_binaryEdit = m_bpatch->openBinary(executable.c_str());

			if (!m_binaryEdit) {
				error("Can't open binary for rewriting\n");

				return false;
			}

			BPatch_object *p = m_binaryEdit->loadLibrary(binaryLibraryPath.c_str());
			if (!p) {
				kcov_debug(INFO_MSG, "Can't load kcov dyninst library\n");

				return false;
			}

			m_addressSpace = m_binaryEdit;
		}

		m_image = m_addressSpace->getImage();

		if (!m_image) {
			// FIXME!

			return false;
		}


		m_addressReporterFunction = lookupFunction("kcov_dyninst_binary_report_address");
		m_reporterInitFunction = lookupFunction("kcov_dyninst_binary_init");

		if (!m_addressReporterFunction || !m_reporterInitFunction)
			return false;

		BPatch_Vector<BPatch_module *> *modules = m_image->getModules();

		if (modules)
			handleModules(*modules);

		BPatch_function *main = lookupFunction("main");
		if (!main)
			return false;

		std::vector< BPatch_snippet * > args;
		BPatch_snippet id = BPatch_constExpr(1234); // FIXME
		BPatch_snippet size = BPatch_constExpr(m_breakpointIdx);

		args.push_back(&id);
		BPatch_funcCallExpr call(*main, args);

		BPatch_Vector<BPatch_point *> mainEntries;
		main->getEntryPoints(mainEntries);

		BPatchSnippetHandle *handle = m_addressSpace->insertSnippet(call, mainEntries,
				BPatch_firstSnippet);
		if (!handle) {
			error("Can't insert init func\n");
			return false;
		}

		m_binaryEdit->writeFile("/tmp/anka");


		return true;
	}


	bool continueExecution()
	{
		return false;

		Event ev;
		bool out = true;

		m_process->continueExecution();

		bool res = m_bpatch->pollForStatusChange();

		if (!res) {
			checkEvents();
			return true;
		}


			if (m_process->isTerminated()) {

				while (1)
				{
					if (!checkEvents())
						break;
				}

				ev.type = ev_exit;
				ev.data = m_process->getExitCode();

				return false;
			}

		return out;
	}


	void kill(int signal)
	{
		// FIXME! use kill
	}

private:
	BPatch_function *lookupFunction(const char *name)
	{
		std::vector<BPatch_function *> funcs;

		m_image->findFunction(name, funcs);
		if (funcs.empty()) {
			error("unable to find function %s\n", name);

			return NULL;
		}

		return funcs[0];
	}

	bool checkEvents()
	{
		// Open the pipe when the program is already running to avoid hanging on it
		if (!m_pipe) {
			m_pipe = fopen(m_pipePath.c_str(), "r");
			panic_if (!m_pipe,
					"Can't open pipe %s", m_pipePath.c_str());
		}

		for (unsigned i = 0; i < 64; i++) {
			uint8_t *buf[sizeof(void *)];
			uint64_t *p;

			p = readCoverageDatum((void *)buf, sizeof(buf));

			if (!p)
				return false;

			reportEvent(ev_breakpoint, 0, *p);
		}

		return true;
	}

	uint64_t *readCoverageDatum(void *buf, size_t totalSize)
	{
		ssize_t rv;

		if (feof(m_pipe))
			return NULL; // Not an error

		// No data?
		if (!file_readable(m_pipe, 100))
			return NULL;

		memset(buf, 0, totalSize);
		rv = fread(buf, sizeof(uint64_t), 1, m_pipe);
		if (rv == 0)
			return NULL; // Not an error

		return (uint64_t *)buf;
	}

	void setupEnvironment()
	{
		m_pipePath = IOutputHandler::getInstance().getOutDirectory() + "kcov-dyninst.pipe";

		m_pipePath = "/tmp/kcov-dyninst.pipe";
		std::string env = "KCOV_DYNINST_PIPE_PATH=" + m_pipePath;
		unlink(m_pipePath.c_str());
		if (mkfifo(m_pipePath.c_str(), 0600) < 0) {
			error("Can't create FIFO %s\n", m_pipePath.c_str());

			return;
		}

		char *envString = (char *)xmalloc(env.size() + 1);
		strcpy(envString, env.c_str());
		putenv(envString);
	}

	void handleModules(BPatch_Vector<BPatch_module *> &modules)
	{
		for (BPatch_Vector<BPatch_module *>::iterator it = modules.begin();
				it != modules.end();
				++it)
		{
			BPatch_Vector<BPatch_statement> stmts;

			char buf[256];
			printf("M: %s\n", (*it)->getFullName(buf, 256));

			bool res = (*it)->getStatements(stmts);
			if (!res)
				continue;

			handleStatements(stmts);
		}
	}

	void handleStatements(BPatch_Vector<BPatch_statement> &stmts)
	{
		for (BPatch_Vector<BPatch_statement>::iterator it = stmts.begin();
				it != stmts.end();
				++it) {
			handleOneStatement(*it);
		}
	}

	void handleOneStatement(BPatch_statement &stmt)
	{
		const std::string filename = stmt.fileName();
		int lineNo = stmt.lineNumber();
		uint64_t addr = (uint64_t)stmt.startAddr();

		for (LineListenerList_t::iterator it = m_lineListeners.begin();
				it != m_lineListeners.end();
				++it)
			(*it)->onLine(filename, lineNo, addr);
	}

	void reportEvent(enum event_type type, int data = -1, uint64_t address = 0)
	{
		if (!m_listener)
			return;

		m_listener->onEvent(Event(type, data, address));
	}


	typedef std::vector<ILineListener *> LineListenerList_t;
	typedef std::vector<IFileListener *> FileListenerList_t;

	std::string m_filename;

	LineListenerList_t m_lineListeners;
	FileListenerList_t m_fileListeners;

	IEventListener *m_listener;
	BPatch *m_bpatch;
	BPatch_process *m_process;
	BPatch_addressSpace *m_addressSpace;
	BPatch_binaryEdit *m_binaryEdit;
	BPatch_image *m_image;

	std::unordered_map<BPatch_point *, BPatchSnippetHandle *> m_snippetsByPoint;
	BPatch_function *m_reporterInitFunction;
	BPatch_function *m_addressReporterFunction;
	FILE *m_pipe;

	std::string m_pipePath;
	unsigned int m_breakpointIdx;
};



// This ugly stuff was inherited from bashEngine
static DyninstEngine *g_dyninstEngine;
class DyninstCtor
{
public:
	DyninstCtor()
	{
		g_dyninstEngine = new DyninstEngine();
	}
};
static DyninstCtor g_dyninstCtor;


class DyninstEngineCreator : public IEngineFactory::IEngineCreator
{
public:
	virtual ~DyninstEngineCreator()
	{
	}

	virtual IEngine *create(IFileParser &parser)
	{
		return g_dyninstEngine;
	}

	unsigned int matchFile(const std::string &filename, uint8_t *data, size_t dataSize)
	{
		// Better than the ptrace engine
		return 2;
	}
};

static DyninstEngineCreator g_dyninstEngineCreator;
