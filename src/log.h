
#ifndef __RS_LOG_H_INCLUDED__
#define __RS_LOG_H_INCLUDED__

enum verbosity_value {
 /** 0 - no verbose messages */
	NO_VERBOSE = 0,
 /** 1 - operational information */
 	VERB_OPS,
 /** 2 - detailed information */
 	VERB_DETAIL,
 /** 3 - query level information */
 	VERB_QUERY,
 /** 4 - algorithm level information */
 	VERB_ALGO,
 /** 5 - querier client information */
	VERB_CLIENT
};

extern enum verbosity_value verbosity;

void log_stderr(int level, const char *fmt, ...);

#endif
