#include <output-handler.hh>
#include <writer.hh>
#include <configuration.hh>
#include <reporter.hh>
#include <utils.hh>

#include <thread>
#include <list>

#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <pthread.h>

namespace kcov
{
	class OutputHandler : public IOutputHandler
	{
	public:
		OutputHandler(IReporter &reporter) : m_reporter(reporter)
		{
			IConfiguration &conf = IConfiguration::getInstance();

			m_baseDirectory = conf.getOutDirectory();
			m_outDirectory = m_baseDirectory + conf.getBinaryName() + "/";
			m_dbFileName = m_outDirectory + "coverage.db";
			m_summaryDbFileName = m_outDirectory + "summary.db";

			m_threadStopped = false;
			m_stop = false;

			mkdir(m_baseDirectory.c_str(), 0755);
			mkdir(m_outDirectory.c_str(), 0755);
		}

		std::string getBaseDirectory()
		{
			return m_baseDirectory;
		}


		std::string getOutDirectory()
		{
			return m_outDirectory;
		}

		void registerWriter(IWriter &writer)
		{
			m_writers.push_back(&writer);
		}

		void start()
		{
			size_t sz;

			void *data = read_file(&sz, m_dbFileName.c_str());

			if (data) {
				m_reporter.unMarshal(data, sz);

				free(data);
			}

			for (WriterList_t::iterator it = m_writers.begin();
					it != m_writers.end();
					it++)
				(*it)->onStartup();

			panic_if (pthread_create(&m_thread, NULL, threadMainStatic, this) < 0,
					"Can't create thread");
		}

		void stop()
		{
			m_stop = true;

			while (!m_threadStopped)
			{
				struct timespec ts;
				ts.tv_sec = 0;
				ts.tv_nsec = 100 * 1000 * 1000;

				nanosleep(&ts, NULL);
			}

			for (WriterList_t::iterator it = m_writers.begin();
					it != m_writers.end();
					it++)
				(*it)->write();

			size_t sz;
			void *data = m_reporter.marshal(&sz);

			if (data)
				write_file(data, sz, m_dbFileName.c_str());

			free(data);

			for (WriterList_t::iterator it = m_writers.begin();
					it != m_writers.end();
					it++)
				(*it)->onStop();
		}

	private:

		void threadMain()
		{
			while (!m_stop) {
				for (WriterList_t::iterator it = m_writers.begin();
						it != m_writers.end();
						it++)
					(*it)->write();

				sleep(1);
			}

			m_threadStopped = true;
		}

		static void *threadMainStatic(void *pThis)
		{
			OutputHandler *p = (OutputHandler *)pThis;

			p->threadMain();

			return NULL;
		}


		typedef std::list<IWriter *> WriterList_t;

		IReporter &m_reporter;

		std::string m_outDirectory;
		std::string m_baseDirectory;
		std::string m_dbFileName;
		std::string m_summaryDbFileName;

		WriterList_t m_writers;
		pthread_t m_thread;
		bool m_stop;
		bool m_threadStopped;
	};

	static OutputHandler *instance;
	IOutputHandler &IOutputHandler::create(IReporter &reporter)
	{
		if (!instance)
			instance = new OutputHandler(reporter);

		return *instance;
	}

	IOutputHandler &IOutputHandler::getInstance()
	{
		return *instance;
	}
}