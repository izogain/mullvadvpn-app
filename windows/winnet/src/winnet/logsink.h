#pragma once

#include "winnet.h"
#include <libcommon/synchronization.h>
#include <mutex>

class LogSink
{
	WinNetLogSink m_target;
	void *m_context;

	mutable std::mutex m_loglock;

public:

	LogSink(WinNetLogSink target, void *context)
		: m_target(target)
		, m_context(context)
	{
	}

	void info(const char *msg) const
	{
		common::sync::ScopeLock<> lock(m_loglock);
		m_target(WINNET_LOG_SEVERITY_INFO, msg, m_context);
	}

	void warning(const char *msg) const
	{
		common::sync::ScopeLock<> lock(m_loglock);
		m_target(WINNET_LOG_SEVERITY_WARNING, msg, m_context);
	}

	void error(const char *msg) const
	{
		common::sync::ScopeLock<> lock(m_loglock);
		m_target(WINNET_LOG_SEVERITY_ERROR, msg, m_context);
	}
};
