#include <file-parser.hh>
#include <engine.hh>
#include <configuration.hh>
#include <output-handler.hh>
#include <utils.hh>

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

using namespace kcov;
void g_dyninstStopThreadCallback(BPatch_point *at_point, void *handlers);

class DyninstEngine : public IEngine, public IFileParser
{
public:
	DyninstEngine() :
		m_listener(NULL),
		m_bpatch(NULL),
		m_target(NULL),
		m_image(NULL)
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

		BPatch_stopThreadExpr stopThread(g_dyninstStopThreadCallback, BPatch_originalAddressExpr());
		BPatch_breakPointExpr bpt;
		addSnippet(bpt, pts);

		return 0;
	}

	void addSnippet(BPatch_snippet &snippet, std::vector<BPatch_point *> &where)
	{
		BPatchSnippetHandle *handle = m_target->insertSnippet(snippet, where);

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
		return "lldb";
	}

	unsigned int matchParser(const std::string &filename, uint8_t *data, size_t dataSize)
	{
		return 1;
	}

	bool start(IEventListener &listener, const std::string &executable)
	{
		IConfiguration &conf = IConfiguration::getInstance();

		m_listener = &listener;

		unsigned int pid = conf.keyAsInt("attach-pid");

		if (pid != 0)
			m_target = m_bpatch->processAttach(executable.c_str(), pid);
		else
			m_target = m_bpatch->processCreate(executable.c_str(), conf.getArgv());

		if (!m_target) {
			error("Cannot launch process\n");

			return false;
		}

		m_image = m_target->getImage();

		if (!m_image) {
			// FIXME!

			return false;
		}

		BPatch_Vector<BPatch_module *> *modules = m_image->getModules();

		if (modules)
			handleModules(*modules);

		return true;
	}

	bool checkEvents()
	{
		return false;
	}

	bool continueExecution()
	{
		Event ev;
		bool out = true;

		m_target->continueExecution();
		bool res = m_bpatch->waitForStatusChange();

		if (!res)
			return false;

		if (m_target->isTerminated()) {
			ev.type = ev_exit;
			ev.data = m_target->getExitCode();

			printf("TERM? %d\n", ev.data);
			return false;
		}

		std::vector<BPatch_thread *> threads;

		m_target->getThreads(threads);

		for (std::vector<BPatch_thread *>::iterator it = threads.begin();
				it != threads.end();
				++it) {
			BPatch_Vector<BPatch_frame> stack;

			if (!(*it)->getCallStack(stack))
				continue;

			if (stack.size() < 6)
				continue;

			void *pt = stack[5].getPC();

			if (!pt)
				continue;

			printf("ANKA: %p\n", pt);
			ev.addr = (uint64_t)pt;
			ev.type = ev_breakpoint;
			ev.data = 0;
		}

		kcov_debug(BP_MSG, "STOPPED\n");

		m_listener->onEvent(ev);

		return out;
	}


	void kill(int signal)
	{
		// FIXME! use kill
	}

	// Called below. Private really.
	void dyninstStopThreadCallback(BPatch_point *at_point, void *data)
	{
		printf("K anka %p!\n", data);

		BPatchSnippetHandle *snippet = m_snippetsByPoint[at_point];

		if (snippet != NULL) {
			printf("Found\n");
			m_target->deleteSnippet(snippet);
			m_snippetsByPoint.erase(at_point);
		}
	}

private:

	void handleModules(BPatch_Vector<BPatch_module *> &modules)
	{
		for (BPatch_Vector<BPatch_module *>::iterator it = modules.begin();
				it != modules.end();
				++it)
		{
			BPatch_Vector<BPatch_statement> stmts;

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
	BPatch_process *m_target;
	BPatch_image *m_image;

	std::unordered_map<BPatch_point *, BPatchSnippetHandle *> m_snippetsByPoint;
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


void g_dyninstStopThreadCallback(BPatch_point *at_point, void *data)
{
	g_dyninstEngine->dyninstStopThreadCallback(at_point, data);
}


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
