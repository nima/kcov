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

#include <lldb/API/LLDB.h>

using namespace kcov;
using namespace lldb;

extern char **environ;

class LLDBEngine : public IEngine, public IFileParser
{
public:
	LLDBEngine() :
		m_listener(NULL)
	{
		SBDebugger::Initialize();
		m_debugger = SBDebugger::Create();

		m_debugger.SetAsync(false);
		IParserManager::getInstance().registerParser(*this);
	}

	virtual ~LLDBEngine()
	{
	}

	// From IEngine
	virtual int registerBreakpoint(unsigned long addr)
	{
		SBBreakpoint bp = m_target.BreakpointCreateByAddress(addr);

		if (!bp.IsValid())
			return -1;

		return bp.GetID();
	}


	// From IFileParser
	virtual bool addFile(const std::string &filename, struct phdr_data_entry *phdr_data)
	{
		m_filename = filename;

		// This now assumes we have only one file, i.e., no shared libraries
		m_target = m_debugger.CreateTarget(m_filename.c_str());

		if (!m_target.IsValid())
			return false;


		for (FileListenerList_t::const_iterator it = m_fileListeners.begin();
				it != m_fileListeners.end();
				++it)
			(*it)->onFile(File(m_filename, IFileParser::FLG_NONE));

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
		char buf[MAXPATHLEN + 1];
		SBError error;
		SBListener l;

		m_listener = &listener;

		if (getcwd(buf, sizeof(buf)) < 0) {
			error("No current WD?\n");

			return false;
		}

		SBBreakpoint bp = m_target.BreakpointCreateByName("main");
		if (!bp.IsValid()) {
			error("No main symbol?\n");

			return false;
		}

		m_process = m_target.Launch(l,
				IConfiguration::getInstance().getArgv(),
				(const char **)environ,
				"/dev/stdin",
				"/dev/stdout",
				"/dev/stderr",
				buf,
				0,
				false, // Don't stop when started, but on the first BP to get the load addresses
				error);

		if (!m_process.IsValid()) {
			kcov_debug(BP_MSG, "Cannot launch process\n");

			return false;
		}

		if (error.Fail()) {
			kcov_debug(BP_MSG, "Launch failure\n");

			return false;
		}

		// Parse the file/line -> address mappings
		for (uint32_t i = 0; i < m_target.GetNumModules(); i++)
		{
			SBModule cur = m_target.GetModuleAtIndex(i);

			if (!cur.IsValid())
				continue;

			handleModule(cur);
		}

		return true;
	}

	bool checkEvents()
	{
		return false;
	}

	bool continueExecution()
	{
		StateType state = m_process.GetState();

		if (state == eStateStopped)
		{
			SBThread curThread = m_process.GetSelectedThread();
			SBFrame frame = curThread.GetSelectedFrame();

			Event ev(ev_breakpoint, -1, frame.GetPCAddress().GetLoadAddress(m_target));
			m_listener->onEvent(ev);
		}

		SBError err = m_process.Continue();

		return err.Success();
	}

	void kill(int signal)
	{
		m_process.Destroy();
	}


private:
	void handleModule(SBModule &module)
	{
		for (uint32_t i = 0; i < module.GetNumCompileUnits(); i++)
		{
			SBCompileUnit cu = module.GetCompileUnitAtIndex(i);

			if (!cu.IsValid())
				continue;

			handleCompileUnit(cu);
		}
	}

	// The file:line -> address mappings are in the compile units
	void handleCompileUnit(SBCompileUnit &cu)
	{
		for (uint32_t i = 0; i < cu.GetNumLineEntries(); i++)
		{
			SBLineEntry cur = cu.GetLineEntryAtIndex(i);

			if (!cur.IsValid())
				continue;

			// Filename
			SBFileSpec fs = cur.GetFileSpec();
			if (!fs.IsValid())
				continue;

			// The address where the program is at
			SBAddress addr = cur.GetStartAddress();

			std::string filename = fmt("%s/%s", fs.GetDirectory(), fs.GetFilename());

			for (LineListenerList_t::const_iterator lit = m_lineListeners.begin();
				lit != m_lineListeners.end();
				++lit)
				(*lit)->onLine(filename, cur.GetLine(), addr.GetLoadAddress(m_target));
		}

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
	SBDebugger m_debugger;
	SBTarget m_target;
	SBProcess m_process;
};



// This ugly stuff was inherited from bashEngine
static LLDBEngine *g_lldbEngine;
class LLDBCtor
{
public:
	LLDBCtor()
	{
		g_lldbEngine = new LLDBEngine();
	}
};
static LLDBCtor g_bashCtor;


class LLDBEngineCreator : public IEngineFactory::IEngineCreator
{
public:
	virtual ~LLDBEngineCreator()
	{
	}

	virtual IEngine *create(IFileParser &parser)
	{
		return g_lldbEngine;
	}

	unsigned int matchFile(const std::string &filename, uint8_t *data, size_t dataSize)
	{
		// Unless #!/bin/sh etc, this should win
		return 1;
	}
};

static LLDBEngineCreator g_lldbEngineCreator;
