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

using namespace kcov;

class DyninstEngine : public IEngine, public IFileParser
{
public:
	DyninstEngine() :
		m_listener(NULL),
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
		return 0;
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
			m_target = m_bpatch.processAttach(executable.c_str(), pid);
		else
			m_target = m_bpatch.processCreate(executable.c_str(), conf.getArgv());


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

		m_target->continueExecution();
		bool res = m_bpatch.waitForStatusChange();

		if (res) {
		}

		kcov_debug(BP_MSG, "STOPPED in state\n");

		m_listener->onEvent(ev);

		return true;
	}


	void kill(int signal)
	{
		// FIXME! use kill
	}


private:
	void handleModules(BPatch_Vector<BPatch_module *> &modules)
	{
		for (BPatch_Vector<BPatch_module *>::iterator it = modules.begin();
				it != modules.end();
				++it)
		{
			BPatch_Vector<BPatch_statement> stmts;

			printf("STMT?\n");
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
		printf("XXX: %s\n", stmt.fileName());
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
	BPatch m_bpatch;
	BPatch_process *m_target;
	BPatch_image *m_image;
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
static DyninstCtor g_bashCtor;


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
