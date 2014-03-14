#include <reporter.hh>
#include <file-parser.hh>
#include <collector.hh>
#include <utils.hh>
#include <filter.hh>
#include <lineid.hh>

#include <string>
#include <list>
#include <unordered_map>

#include "swap-endian.hh"

using namespace kcov;

#define KCOV_MAGIC      0x6b636f76 /* "kcov" */
#define KCOV_DB_VERSION 2

struct marshalHeaderStruct
{
	uint32_t magic;
	uint32_t db_version;
	uint64_t checksum;
};

class Reporter : public IReporter, public IFileParser::ILineListener, public ICollector::IListener
{
public:
	Reporter(IFileParser &fileParser, ICollector &collector) :
		m_fileParser(fileParser), m_collector(collector), m_filter(IFilter::getInstance())
	{
		m_fileParser.registerLineListener(*this);
		m_collector.registerListener(*this);
	}

	bool lineIsCode(const std::string &file, unsigned int lineNr)
	{
		bool out;

		out =  m_lines.find(LineId(file, lineNr)) != m_lines.end();

		return out;
	}

	LineExecutionCount getLineExecutionCount(const std::string &file, unsigned int lineNr)
	{
		unsigned int hits = 0;
		unsigned int possibleHits = 0;

		LineMap_t::iterator it = m_lines.find(LineId(file, lineNr));

		if (it != m_lines.end()) {
			Line *line = it->second;

			hits = line->hits();
			possibleHits = line->possibleHits();
		}

		return LineExecutionCount(hits,
				possibleHits);
	}

	ExecutionSummary getExecutionSummary()
	{
		unsigned int executedLines = 0;
		unsigned int nrLines = 0;

		for (const auto &it : m_lines) {
			Line *cur = it.second;

			if (!m_filter.runFilters(cur->m_file))
				continue;

			executedLines += !!cur->hits();
			nrLines++;
		}

		return ExecutionSummary(nrLines, executedLines);
	}

	void *marshal(size_t *szOut)
	{
		size_t sz = getMarshalSize();
		void *start;
		uint8_t *p;

		start = malloc(sz);
		if (!start)
			return nullptr;
		memset(start, 0, sz);
		p = marshalHeader((uint8_t *)start);

		for (const auto &it : m_lines) {
			Line *cur = it.second;

			p = cur->marshal(p);
		}

		*szOut = sz;

		return start;
	}

	bool unMarshal(void *data, size_t sz)
	{
		uint8_t *start = (uint8_t *)data;
		uint8_t *p = start;
		size_t n;

		p = unMarshalHeader(p);

		if (!p)
			return false;

		n = (sz - (p - start)) / getMarshalEntrySize();

		for (size_t i = 0; i < n; i++) {
			unsigned long addr;
			unsigned int hits;

			p = Line::unMarshal(p, &addr, &hits);
			AddrToLineMap_t::iterator it = m_addrToLine.find(addr);

			if (it == m_addrToLine.end())
				continue;

			Line *line = it->second;

			if (!hits)
				continue;

			// Really an internal error, but let's not hang on corrupted data
			if (hits > line->possibleHits())
				hits = line->possibleHits();

			// Register all hits for this address
			line->registerHit(addr, hits);
		}

		return true;
	}

	virtual void stop()
	{
	}


private:
	size_t getMarshalEntrySize()
	{
		return 2 * sizeof(uint64_t);
	}

	size_t getMarshalSize()
	{
		size_t out = 0;

		for (const auto &it : m_lines) {
			Line *cur = it.second;

			out += cur->m_addrs.size();
		}


		return out * getMarshalEntrySize() + sizeof(struct marshalHeaderStruct);
	}

	uint8_t *marshalHeader(uint8_t *p)
	{
		struct marshalHeaderStruct *hdr = (struct marshalHeaderStruct *)p;

		hdr->magic = to_be<uint32_t>(KCOV_MAGIC);
		hdr->db_version = to_be<uint32_t>(KCOV_DB_VERSION);
		hdr->checksum = to_be<uint64_t>(m_fileParser.getChecksum());

		return p + sizeof(struct marshalHeaderStruct);
	}

	uint8_t *unMarshalHeader(uint8_t *p)
	{
		struct marshalHeaderStruct *hdr = (struct marshalHeaderStruct *)p;

		if (be_to_host<uint32_t>(hdr->magic) != KCOV_MAGIC)
			return nullptr;

		if (be_to_host<uint32_t>(hdr->db_version) != KCOV_DB_VERSION)
			return nullptr;

		if (be_to_host<uint64_t>(hdr->checksum) != m_fileParser.getChecksum())
			return nullptr;

		return p + sizeof(struct marshalHeaderStruct);
	}

	/* Called when the file is parsed */
	void onLine(const std::string &file, unsigned int lineNr, unsigned long addr)
	{
		if (!m_filter.runFilters(file))
			return;

		LineId key(file, lineNr);

		LineMap_t::iterator it = m_lines.find(key);
		Line *line;

		if (it == m_lines.end()) {
			line = new Line(key);

			m_lines[key] = line;
		} else {
			line = it->second;
		}

		line->addAddress(addr);
		m_addrToLine[addr] = line;
	}

	/* Called during runtime */
	void onAddress(unsigned long addr, unsigned long hits)
	{
		AddrToLineMap_t::iterator it = m_addrToLine.find(addr);

		if (it != m_addrToLine.end()) {
			Line *line = it->second;

			line->registerHit(addr, hits);
		}
	}

	class Line
	{
	public:
		typedef std::unordered_map<unsigned long, int> AddrToHitsMap_t;

		Line(LineId id) : m_file(id.m_file),
				m_lineNr(id.m_lineNr)

		{
		}

		void addAddress(unsigned long addr)
		{
			m_addrs[addr] = 0;
		}

		unsigned int registerHit(unsigned long addr, unsigned long hits)
		{
			unsigned int out = !m_addrs[addr];

			m_addrs[addr] = 1;

			return out;
		}

		void clearHits()
		{
			for (auto &it : m_addrs)
				it.second = 0;
		}

		unsigned int hits()
		{
			unsigned int out = 0;

			for (const auto &it : m_addrs)
				out += it.second;

			return out;
		}

		unsigned int possibleHits()
		{
			return m_addrs.size();
		}

		uint8_t *marshal(uint8_t *start)
		{
			uint64_t *data = (uint64_t *)start;

			for (const auto &it : m_addrs) {
				// Address and number of hits
				*data++ = to_be<uint64_t>(it.first);
				*data++ = to_be<uint64_t>(it.second);
			}

			return (uint8_t *)data;
		}

		static uint8_t *unMarshal(uint8_t *p,
				unsigned long *outAddr, unsigned int *outHits)
		{
			uint64_t *data = (uint64_t *)p;

			*outAddr = be_to_host(*data++);
			*outHits = be_to_host(*data++);

			return (uint8_t *)data;
		}

		std::string m_file;
		unsigned int m_lineNr;
		AddrToHitsMap_t m_addrs;
	};

	typedef std::unordered_map<LineId, Line *, LineIdHash> LineMap_t;
	typedef std::unordered_map<unsigned long, Line *> AddrToLineMap_t;

	LineMap_t m_lines;
	AddrToLineMap_t m_addrToLine;

	IFileParser &m_fileParser;
	ICollector &m_collector;
	IFilter &m_filter;
};

IReporter &IReporter::create(IFileParser &parser, ICollector &collector)
{
	return *new Reporter(parser, collector);
}
