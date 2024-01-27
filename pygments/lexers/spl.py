from pygments.lexer import RegexLexer
from pygments.token import Comment, Keyword, Name, String, Number, Operator, Text, Literal

__all__ = ['SplunkSplLexer']

class SplunkSplLexer(RegexLexer):
    name = 'Splunk SPL'
    aliases = ['spl']
    filenames = ['*.spl', '*.splunk']

    tokens = {
        'root': [
            # Splunk Search Commands See https://docs.splunk.com/Documentation/SplunkCloud/9.1.2308/SearchReference/Abstract#
            (r'(abstract|accum|addcoltotals|addinfo|addtotals|analyzefields|anomalies|anomalousvalue|append|appendcols|appendpipe|arules|associate|audit|autoregress|awsnsalert|bin|bucket|bucketdir|chart|cluster|collect|concurrency|contingency|convert|correlate|ctable|datamodel|datamodelsimple|dbinspect|dbxquery|dedup|delete|delta|diff|entitymerge|erex|eval|eventcount|eventstats|extract|fieldformat|fields|fieldsummary|filldown|fillnull|findtypes|folderize|foreach|format|from|fromjson|gauge|gentimes|geom|geomfilter|geostats|head|highlight|history|iconify|inputcsv|inputintelligence|inputlookup|iplocation|join|kmeans|kvform|loadjob|localize|localop|lookup|makecontinuous|makemv|makeresults|map|metadata|metasearch|meventcollect|mpreview|msearch|mstats|multikv|multisearch|mvcombine|mvexpand|mvreverse|nomv|outlier|outputcsv|outputlookup|outputtext|overlap|pivot|predict|rangemap|rare|regex|reltime|rename|replace|require|rest|return|reverse|rex|rtorder|run|savedsearch|script|scrub|search|searchtxn|selfjoin|sendalert|sendemail|set|setfields|sichart|sirare|sistats|sitimechart|sitop|snowincident|snowincidentstream|snowevent|snoweventstream|sort|spath|stats|strcat|streamstats|table|tags|tail|timechart|timewrap|tojson|top|transaction|transpose|trendline|tscollect|tstats|typeahead|typelearner|typer|union|uniq|untable|walklex|where|x11|xmlkv|xmlunescape|xpath|xyseries)\b', Keyword),
            # Splunk Eval functions. See https://docs.splunk.com/Documentation/Splunk/9.1.2/SearchReference/CommonEvalFunctions#Alphabetical_list_of_functions
            (r'\b(abs|acos|acosh|asin|asinh|atan|atan2|atanh|case|cidrmatch|ceiling|coalesce|commands|cos|cosh|exact|exp|floor|hypot|if|in|isbool|isint|isnotnull|isnull|isnum|isstr|len|like|ln|log|lower|ltrim|match|max|md5|min|mvappend|mvcount|mvdedup|mvfilter|mvfind|mvindex|mvjoin|mvrange|mvsort|mvzip|now|null|nullif|pi|pow|printf|random|relative_time|replace|round|rtrim|searchmatch|sha1|sha256|sha512|sigfig|sin|sinh|spath|split|sqrt|strftime|strptime|substr|tan|tanh|time|tonumber|tostring|trim|typeof|upper|urldecode|validate)\b(?=\()', Name.Function),
            # Splunk Statistical and Charting Functions. See https://docs.splunk.com/Documentation/SplunkCloud/9.1.2308/SearchReference/CommonStatsFunctions
            (r'\b(avg|count|distinct_count|earliest|earliest_time|estdc|estdc_error|exactperc|first|last|latest|latest_time|list|max|mean|median|min|mode|perc|per_day|per_hour|per_minute|per_second|range|rate|rate_avg|rate_sum|stdev|stdevp|sum|sumsq|var|varp)\b(?=\()', Name.Function),
            # Splunk Internal commands. See https://docs.splunk.com/Documentation/SplunkCloud/9.1.2308/SearchReference/Aboutinternalcommands
            (r'\b(collapse|dump|findkeywords|makejson|mcatalog|noop|prjob|redistribute|runshelscript)\b', Keyword),
            # Splunk Macro Names
            (r'`[\w]+(?=\(|`)', Name.Function),
            # Digits
            (r'\b\d+\b', Number),
            # Escape Characters
            (r'(\\|\\\||\\\*|\\\=)', String.Escape),
            # Splunk Operators
            (r'(\||,)', Operator),
            # Splunk Language Constants
            (r'\b(as|by|or|and|over|where|output|outputnew)\b', Keyword),
            (r'\b(NOT|true|false)\b', Keyword.Constant),
            # Splunk Macro Parameters
            (r'(?<=\(|,|\s)[^\(\)",=\s]+(?=\)|,)', Name.Variable),
            # Splunk Variables
            (r'[\w\.]+(?=\[|\]|\{|\})?\s*(?==)', Name.Variable),
            # Comparison or assignment
            (r'=', Operator),
            # Strings
            (r'"(\\\\|\\"|[^"])*"', String.Double),
            (r"'(\\\\|\\'|[^'])*'", String.Single),
            # Comments. See https://docs.splunk.com/Documentation/SplunkCloud/9.1.2308/Search/Comments
            (r'```[\s\S]*?```', Comment.Multiline),
        ]
    }
